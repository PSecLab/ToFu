"""Find and kill every process descended from one fuzzing config.

WHY THIS EXISTS (2026-09-23). The VM was found with 663 orphaned
`node coverage_wrapper.js ...` processes (~47 GB RSS, reparented to PID 1,
44-48h old) left behind by the set_e2 / rerun campaigns. Reproduced on 3/3
node configs of a 20s run: EVERY node config leaked its target server, on
normal exit as well as on timeout. Two independent causes:

  1. JSRunner starts node with start_new_session=True (so its startup watchdog
     can killpg the server tree without killing the fuzzer). That puts node in
     a DIFFERENT process group from the fuzzer, so run_eval's
     os.killpg(fuzzer_pgid) never reached it.
  2. libFuzzer ends the run with a C-level exit() at -max_total_time, which
     skips fuzzer._cleanup_runner() and every Python atexit handler, so
     JSRunner.stop() never ran either. Nothing in the wrapper noticed its
     parent was gone: its stdout is written once (SOCKET_READY) and its stdin
     is never read, and the listening socket keeps the event loop alive
     forever.

A process group cannot describe "everything this config started" (the server
is in its own session, and a target may setsid() again). An inherited
environment variable can: run_eval gives each config a unique TOFU_REAP_TAG,
every descendant inherits it (secrets.scrub_secrets does not strip it), and
reap_tagged() kills whatever still carries it once the config is over.

Standalone on purpose -- no package-relative imports -- so eval/run_eval.py can
load it by path without importing src/ (which pulls in atheris).
"""
import os
import shutil
import signal
import subprocess
import sys
import threading
import time

TAG_ENV = "TOFU_REAP_TAG"


def find_tagged(key: str, value: str) -> list:
    """PIDs (other than this process) whose environment has key=value exactly.

    Linux only (/proc/PID/environ); returns [] elsewhere."""
    if not key or not value:
        return []
    me = os.getpid()
    needle = f"{key}={value}".encode()
    found = []
    if os.path.isdir("/proc/self"):
        for d in os.listdir("/proc"):
            if not d.isdigit() or int(d) == me:
                continue
            try:
                with open(f"/proc/{d}/environ", "rb") as f:
                    env = f.read()
            except OSError:
                continue   # exited, or not ours (EACCES)
            if needle in env.split(b"\0"):
                found.append(int(d))
        return found
    # macOS: `ps -E` no longer shows another process's environment (verified
    # 2026-09-23, even unsandboxed), so there is nothing to match on. The
    # wrapper's orphan guard is the layer that covers macOS; the campaign host
    # (the Linux VM) gets all of them.
    return found


def reap_tagged(key: str, value: str, rounds: int = 5) -> int:
    """SIGKILL every process carrying key=value. Returns how many were killed.

    Repeats because a dying parent can fork between the scan and the kill."""
    killed = set()
    for _ in range(rounds):
        pids = [p for p in find_tagged(key, value) if p not in killed]
        if not pids:
            break
        for p in pids:
            try:
                os.kill(p, signal.SIGKILL)
                killed.add(p)
            except ProcessLookupError:
                pass
            except PermissionError:
                pass
        time.sleep(0.1)
    return len(killed)


def pdeathsig_prefix() -> list:
    """argv prefix that SIGTERMs the child when its parent thread dies (Linux).

    A kernel-delivered backstop to the wrapper's orphan guard (stdin EOF / ppid
    poll): coverage_wrapper.js handles SIGTERM by SIGKILLing its whole process
    group. NOT SIGKILL: measured 2026-09-23, PDEATHSIG=KILL killed node before
    the guard ran and ORPHANED the target's own children (a spawned `sleep`
    survived) -- worse than no PDEATHSIG. A target wedged in a synchronous loop
    runs no JS handler at all; under run_eval the tag sweep covers that case.
    Uses setpriv(1) rather than a preexec_fn, which is not fork-safe once the
    fuzzer has threads running. setpriv exec()s node in place, so the Popen pid
    is still node's pid.

    PDEATHSIG fires when the THREAD that forked exits, not the process -- so it
    is only armed from the main thread (where JSRunner.start() normally runs,
    including restarts from inside the atheris callback). A server started from
    a short-lived worker thread would otherwise be killed the moment that thread
    returned: a silently dead target, this codebase's usual failure mode.
    """
    if (sys.platform.startswith("linux")
            and threading.current_thread() is threading.main_thread()
            and not os.environ.get("TOFU_NO_PDEATHSIG")):
        global _SETPRIV_OK
        if _SETPRIV_OK is None:
            # Probe once: util-linux < 2.33 has setpriv without --pdeathsig,
            # and a prefix that fails to exec would look like a startup hang.
            sp = shutil.which("setpriv")
            try:
                _SETPRIV_OK = bool(sp) and subprocess.run(
                    [sp, "--pdeathsig", "TERM", "true"],
                    capture_output=True, timeout=10).returncode == 0
            except Exception:
                _SETPRIV_OK = False
            _SETPRIV_OK = sp if _SETPRIV_OK else False
        if _SETPRIV_OK:
            return [_SETPRIV_OK, "--pdeathsig", "TERM"]
    return []


_SETPRIV_OK = None
