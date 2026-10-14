"""Regression tests for the 2026-09-23 node-server leak.

663 `node coverage_wrapper.js` orphans (~47 GB) were found on the VM after the
set_e2 campaign: every node config leaked its server, because the server lives
in its own session (out of reach of run_eval's killpg) and libFuzzer's C exit()
skips JSRunner.stop(). See src/runners/procreap.py.
"""
import os
import shutil
import subprocess
import sys
import textwrap
import time
import uuid

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "src", "runners"))
import procreap  # noqa: E402

# Captured at collection: test_introspection_sanitizer.py runs a tool that sets
# os.environ["PATH"]="/tmp/malicious_bin" in-process and never restores it.
_PATH = os.environ.get("PATH", "")
_PS = shutil.which("ps") or "/bin/ps"
_NODE = shutil.which("node")


def _wait_gone(key, value, secs=8.0):
    end = time.time() + secs
    while time.time() < end:
        left = procreap.find_tagged(key, value)
        if not left:
            return []
        time.sleep(0.2)
    return procreap.find_tagged(key, value)


def _argv_matches(*needles):
    """PIDs whose command line contains any needle (portable; macOS hides env)."""
    out = subprocess.run([_PS, "-axww", "-o", "pid=,command="],
                         capture_output=True, text=True).stdout
    me = os.getpid()
    return [int(l.split(None, 1)[0]) for l in out.splitlines()
            if l.strip() and int(l.split(None, 1)[0]) != me
            and any(n in l for n in needles)]


def _wait_argv_gone(*needles, secs=8.0):
    end = time.time() + secs
    while time.time() < end:
        if not _argv_matches(*needles):
            return []
        time.sleep(0.2)
    return _argv_matches(*needles)


@pytest.mark.skipif(not os.path.isdir("/proc/self"), reason="env sweep is Linux-only")
def test_reap_tagged_kills_detached_tree_and_nothing_else():
    tag = uuid.uuid4().hex
    other = uuid.uuid4().hex
    env = dict(os.environ, **{procreap.TAG_ENV: tag})
    # a parent in its own session whose child setsid()s AGAIN -- out of reach of
    # any process-group kill, which is exactly what the tag is for.
    tree = subprocess.Popen(
        [sys.executable, "-c",
         "import subprocess,sys,time,os;"
         "subprocess.Popen([sys.executable,'-c','import time;time.sleep(300)'],"
         "start_new_session=True);time.sleep(300)"],
        env=env, start_new_session=True)
    bystander = subprocess.Popen(
        [sys.executable, "-c", "import time;time.sleep(300)"],
        env=dict(os.environ, **{procreap.TAG_ENV: tag + "x"}))  # prefix must not match
    try:
        deadline = time.time() + 5
        while len(procreap.find_tagged(procreap.TAG_ENV, tag)) < 2 and time.time() < deadline:
            time.sleep(0.1)
        assert len(procreap.find_tagged(procreap.TAG_ENV, tag)) == 2
        assert procreap.find_tagged(procreap.TAG_ENV, other) == []
        assert procreap.reap_tagged(procreap.TAG_ENV, tag) == 2
        tree.wait(timeout=5)
        assert _wait_gone(procreap.TAG_ENV, tag) == []
        assert bystander.poll() is None, "reap killed a process with a different tag"
    finally:
        for p in (tree, bystander):
            try:
                p.kill()
            except Exception:
                pass
        procreap.reap_tagged(procreap.TAG_ENV, tag)


@pytest.mark.skipif(not _NODE, reason="node not installed")
def test_js_server_dies_with_fuzzer_even_when_stop_is_skipped(tmp_path):
    """The real failure: the fuzzer process ends WITHOUT calling stop() (as
    libFuzzer's C exit() does) and the node server -- plus a child it spawned --
    must not outlive it. Must fail with TOFU_NO_ORPHAN_GUARD=1 on macOS, and
    with that plus TOFU_NO_PDEATHSIG=1 on Linux."""
    naptime = str(3000000 + uuid.uuid4().int % 1000000)   # unique argv marker
    target = tmp_path / "target.js"
    target.write_text(textwrap.dedent(f"""
        import {{ spawn }} from 'node:child_process';
        spawn('sleep', ['{naptime}'], {{ stdio: 'ignore' }});
        setInterval(() => {{}}, 1000);
    """))
    (tmp_path / "package.json").write_text('{"type": "module"}')
    driver = textwrap.dedent(f"""
        import os, sys
        sys.path.insert(0, {ROOT!r})
        from src.runners.js_runner import JSRunner
        r = JSRunner("node", [{str(target)!r}], "noop")
        r.start()
        print(r.sock_path, flush=True)
        sys.stdin.readline()
        os._exit(0)          # skips stop() AND atexit, like libFuzzer's exit()
    """)
    drv = subprocess.Popen([sys.executable, "-c", driver], stdin=subprocess.PIPE,
                           stdout=subprocess.PIPE, text=True, cwd=str(tmp_path),
                           env=dict(os.environ, PATH=_PATH))
    marks = (str(target), f"sleep {naptime}")
    try:
        sock = drv.stdout.readline().strip()
        assert sock.startswith("/tmp/mcp_fuzz_"), sock
        deadline = time.time() + 10
        while len(_argv_matches(*marks)) < 2 and time.time() < deadline:
            time.sleep(0.2)
        assert len(_argv_matches(*marks)) >= 2, "expected node + its sleep child running"
        drv.stdin.write("\n"); drv.stdin.flush()
        drv.wait(timeout=10)
        left = _wait_argv_gone(*marks)
        assert left == [], f"server tree outlived the fuzzer: {left}"
    finally:
        try:
            drv.kill()
        except Exception:
            pass
        for p in _argv_matches(*marks):
            try:
                os.kill(p, 9)
            except Exception:
                pass
