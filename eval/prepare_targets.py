#!/usr/bin/env python3
"""
STEP 1 of the ToFu evaluation: materialise Set A + Set B targets.

For each selected repo:  clone at the PINNED commit -> install deps -> detect a
launch command -> handshake with the server to enumerate its REAL tools ->
emit one ToFu config per tool.

RESUMABLE. State lives in eval/state/prepared.jsonl and eval/state/skipped.jsonl
(both append-only). Re-running skips anything already recorded. Ctrl-C anytime.

Every skip is recorded WITH A REASON -- that file IS the documented exclusion
list the paper needs (Pierre's TODO: "state how many were excluded and why").

Usage:
    python3 eval/prepare_targets.py                 # all of Set A + Set B
    python3 eval/prepare_targets.py --only-set a    # just Set A
    python3 eval/prepare_targets.py --limit 5       # smoke test
"""
import argparse, json, os, shutil, subprocess, sys, time

ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
EVAL   = os.path.join(ROOT, "eval")
TGTDIR = os.path.join(EVAL, "targets")
CFGDIR = os.path.join(EVAL, "configs")
STATE  = os.path.join(EVAL, "state")
EXTR   = os.path.join(ROOT, "Benchmarks", "extraction")
PREPARED = os.path.join(STATE, "prepared.jsonl")
SKIPPED  = os.path.join(STATE, "skipped.jsonl")

# The interpreter every per-target venv is built with. The invariant is
# EQUALITY with the interpreter that runs `python -m src`: PythonRunner imports
# the target in-process, so a venv on another CPython minor cannot be used and
# the runner refuses it at start() (item 86). Default to the interpreter running
# this script -- in the sandbox that is ToFu's own venv (3.13; Dockerfile.sandbox
# also sets TOFU_TARGET_PYTHON explicitly). Override only if you know why.
TARGET_PYTHON   = os.environ.get("TOFU_TARGET_PYTHON",
                                 f"{sys.version_info.major}.{sys.version_info.minor}")
CLONE_TIMEOUT   = int(os.environ.get("TOFU_CLONE_TIMEOUT", "180"))
INSTALL_TIMEOUT = int(os.environ.get("TOFU_INSTALL_TIMEOUT", "240"))  # was 600; build-from-source stragglers now skip sooner
PROBE_TIMEOUT   = int(os.environ.get("TOFU_PROBE_TIMEOUT", "60"))


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def load_done():
    done = {}
    for path in (PREPARED, SKIPPED):
        if os.path.exists(path):
            for line in open(path):
                try:
                    d = json.loads(line); done[d["repo"]] = d.get("status")
                except Exception: pass
    return done

def record(path, obj):
    os.makedirs(STATE, exist_ok=True)
    with open(path, "a") as f: f.write(json.dumps(obj) + "\n")

def run(cmd, cwd=None, timeout=120, env=None):
    return subprocess.run(cmd, cwd=cwd, capture_output=True, timeout=timeout,
                          env=env or os.environ.copy())

def clone(repo, commit, dest):
    if os.path.exists(dest): shutil.rmtree(dest, ignore_errors=True)
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
    p = run(["git", "clone", "--quiet", f"https://github.com/{repo}.git", dest],
            timeout=CLONE_TIMEOUT, env=env)
    if p.returncode != 0:
        raise RuntimeError("clone failed: " + p.stderr.decode()[:150].strip())
    # pin to the exact commit recorded during extraction -> reproducible
    p = run(["git", "-C", dest, "checkout", "--quiet", commit], timeout=60, env=env)
    if p.returncode != 0:
        raise RuntimeError(f"checkout {commit[:8]} failed (history may have been rewritten)")

# Credentials that must never reach a target (bug 23). Mirrors
# src/runners/js_runner._scrub_secrets; kept local so prepare has no import
# dependency on the fuzzer package.
_SECRET_EXACT = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_CLOUD_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "NPM_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD",
    "MCP_SCANNER_LLM_API_KEY", "MCP_SCANNER_API_KEY",
}
_SECRET_SUFFIX = ("_API_KEY", "_SECRET", "_SECRET_KEY", "_TOKEN", "_PASSWORD", "_PASSWD", "_PRIVATE_KEY")


def _scrub_secrets(env):
    for k in list(env.keys()):
        ku = k.upper()
        if ku in _SECRET_EXACT or ku.endswith(_SECRET_SUFFIX):
            env.pop(k, None)
    return env


# Placeholder credentials for env-gated servers. These servers check that a
# variable is PRESENT at import time and refuse to start otherwise (e.g.
# "GOOGLE_API_KEY: ['Required']"), which hid their whole tool surface from us.
# Values are deliberately fake but format-plausible; network calls will fail
# at call time (recorded as an environment exclusion per tool), but every
# pre-network code path -- schema validation, path building, local file and
# git operations -- becomes fuzzable. NEVER put a real credential here.
TARGET_ENV_HINTS = {
    "alexatnordnet/mcp-google-custom-search-server": {
        "GOOGLE_API_KEY": "AIzaSy-tofu-placeholder-000000000000000000",
        "GOOGLE_SEARCH_ENGINE_ID": "tofu-placeholder-cx",
    },
    "da-okazaki/mcp-neo4j-server": {
        "NEO4J_URI": "bolt://127.0.0.1:7687", "NEO4J_USER": "neo4j",
        "NEO4J_USERNAME": "neo4j", "NEO4J_PASSWORD": "tofu-placeholder",
    },
    "jatinsandilya/mcp-server-auto-commit": {
        # placeholder ONLY -- the real key is scrubbed above and must never
        # reach this target (it is a third-party server).
        "OPENAI_API_KEY": "sk-tofu-placeholder-000000000000000000000000000000",
    },
    "teddyzxcv/ntfy-mcp": {"NTFY_TOPIC": "tofu-placeholder-topic"},
    "niledatabase/nile-mcp-server": {
        "NILE_API_KEY": "tofu-placeholder", "NILE_WORKSPACE_SLUG": "tofu-placeholder",
        "NILE_DB": "tofu", "NILE_WORKSPACE": "tofu-placeholder",
    },
    "gerred/mcp-server-replicate": {
        "REPLICATE_API_TOKEN": "r8_tofuplaceholder0000000000000000000000000",
    },
    "Tiberriver256/azure-devops-mcp": {
        "AZURE_DEVOPS_ORG_URL": "https://dev.azure.com/tofu-placeholder",
        "AZURE_DEVOPS_AUTH_METHOD": "pat",
        "AZURE_DEVOPS_PAT": "tofu-placeholder-pat",
        "AZURE_DEVOPS_DEFAULT_PROJECT": "tofu",
    },
}


# Servers gated on CLI arguments or on a credentials FILE rather than an env
# var. "args" are appended to the launch argv; "files" are planted relative to
# the repo root (only if absent). Same rule as TARGET_ENV_HINTS: placeholders
# only, format-plausible, so import/startup validation passes and the tool
# surface becomes visible; real API calls fail at call time and are recorded
# as per-tool environment exclusions.
_PLACEHOLDER_OAUTH_CLIENT = json.dumps({"installed": {
    "client_id": "tofu-placeholder.apps.googleusercontent.com",
    "project_id": "tofu-placeholder", "client_secret": "tofu-placeholder",
    "auth_uri": "https://accounts.google.com/o/oauth2/auth",
    "token_uri": "https://oauth2.googleapis.com/token",
    "redirect_uris": ["http://localhost"]}})
TARGET_LAUNCH_HINTS = {
    # stderr at prepare: "usage: gmail [-h] --creds-file-path CREDS_FILE_PATH --token-path TOKEN_PATH"
    "jasonsum/gmail-mcp-server": {
        "args": ["--creds-file-path", ".tofu/gcp-oauth.keys.json", "--token-path", ".tofu/token.json"],
        "files": {".tofu/gcp-oauth.keys.json": _PLACEHOLDER_OAUTH_CLIENT, ".tofu/token.json": "{}"},
    },
    # stderr at prepare: "GCP keys not found. Please ... copy `gcp-oauth.keys.json` into your ./dist directory."
    "mkummer225/google-sheets-mcp": {
        "args": [],
        "files": {"dist/gcp-oauth.keys.json": _PLACEHOLDER_OAUTH_CLIENT},
    },
}


def apply_launch_hints(repo, dest, command, args):
    """Plant hinted files and append hinted argv. Returns (command, args)."""
    h = TARGET_LAUNCH_HINTS.get(repo)
    if not h:
        return command, args
    for rel, content in (h.get("files") or {}).items():
        fp = os.path.join(dest, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        if not os.path.exists(fp):
            with open(fp, "w") as f:
                f.write(content)
    return command, list(args) + list(h.get("args") or [])


def _err_head(stderr_bytes, n=2, width=160):
    """First error-bearing lines of a stderr blob. A stack trace's TAIL is
    useless ('at node:internal/main/run_main_module:36:49'); the message is
    at the HEAD. Falls back to the first non-empty lines."""
    try:
        lines = [l.strip() for l in stderr_bytes.decode(errors="ignore").splitlines() if l.strip()]
    except Exception:
        return "(no stderr)"
    if not lines:
        return "(no stderr)"
    errs = [l for l in lines if any(k in l for k in ("Error", "error", "ERR_", "Cannot find", "not found", "Missing", "required"))]
    pick = (errs or lines)[:n]
    return " | ".join(l[:width] for l in pick)


def target_env(dest, interp=None, extra=None):
    """Environment for a TARGET process.

    ToFu runs inside its own virtualenv. If we hand that environment to a child
    MCP server, VIRTUAL_ENV/PYTHONPATH/PATH leak ToFu's site-packages into the
    target and it imports ToFu's pinned mcp==2.2.0 instead of its own. Strip
    them, then put the target's own venv first on PATH.
    """
    env = _scrub_secrets(os.environ.copy())
    for k in ("VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME", "CONDA_PREFIX"):
        env.pop(k, None)
    if interp:
        env["VIRTUAL_ENV"] = os.path.dirname(os.path.dirname(interp))
        env["PATH"] = os.path.dirname(interp) + os.pathsep + env.get("PATH", "")
    if extra:
        env.update({str(k): str(v) for k, v in extra.items()})
    return env

def _venv_pyver(interp):
    """'3.11' from the venv's pyvenv.cfg next to `interp` (None if unknown)."""
    try:
        cfg = os.path.join(os.path.dirname(os.path.dirname(interp)), "pyvenv.cfg")
        for line in open(cfg, encoding="utf-8", errors="ignore"):
            k, _, v = line.partition("=")
            if k.strip() in ("version_info", "version"):
                parts = v.strip().split(".")
                if len(parts) >= 2:
                    return f"{parts[0]}.{parts[1]}"
    except OSError:
        pass
    return None

def _console_entry(dest, command):
    """'pkg.mod:func' behind a console-script launch, from [project.scripts].

    Recorded in the config as `python_entry` so the in-process PythonRunner can
    import the MODULE instead of trying to import the bin/ path (item 86 bug A).
    The runner also parses the shim itself; this is the belt to that suspenders.
    """
    script = os.path.basename(command or "")
    if not script or script.startswith("python"):
        return None
    pp = os.path.join(dest, "pyproject.toml")
    if not os.path.exists(pp):
        return None
    try:
        txt = open(pp, encoding="utf-8", errors="ignore").read()
        for header in ("[project.scripts]", "[tool.poetry.scripts]"):
            if header not in txt:
                continue
            seg = txt.split(header, 1)[1].split("\n[", 1)[0]
            for line in seg.strip().splitlines():
                if "=" not in line:
                    continue
                name = line.split("=", 1)[0].strip().strip('"\'')
                target = line.split("=", 1)[1].strip().strip('"\'')
                if name == script and target:
                    return target
    except Exception:
        pass
    return None

def make_venv(dest):
    """Create a per-target virtualenv and return its interpreter.

    THIS IS THE WHOLE POINT OF item 51. Before this, every Python target was
    installed into ToFu's OWN venv with sys.executable, so targets collided
    with each other and with ToFu's pins (mcp==2.2.0, atheris, langchain).
    75 of 75 Python repos failed to prepare; several failures were literally
    the mcp<2 migration error raised against our mcp 2.x.
    """
    vdir = os.path.join(dest, ".venv")
    py   = os.path.join(vdir, "bin", "python")
    if os.path.exists(py):
        return py
    # PIN THE INTERPRETER. uv defaults to the newest Python it can find (3.14
    # on this machine). The corpus commits are mid-2025 and their transitive
    # deps (pydantic-core 2.27, etc.) ship no wheels for 3.14, so resolution
    # succeeds and the BUILD then fails needing a Rust toolchain. 3.11 is
    # contemporary with the snapshot and has wheels for everything in it.
    p = run(["uv", "venv", vdir, "--python", TARGET_PYTHON], cwd=dest,
            timeout=180, env=target_env(dest))
    if p.returncode != 0:
        raise RuntimeError("uv venv failed: " + p.stderr.decode()[:150].strip())
    if not os.path.exists(py):
        raise RuntimeError("uv venv produced no interpreter at .venv/bin/python")
    return py

def install(dest, lang, last_commit=None):
    """Best-effort dependency install.

    Prefers the repo's OWN lockfile. This matters: the corpus snapshot is from
    mid-2025 and the MCP SDKs have shipped breaking changes since, so a plain
    `pip install`/`npm install` pulls a NEWER SDK than the pinned commit was
    written against and the server fails to import. Lockfiles avoid that.
    """
    if lang == "python":
        if not shutil.which("uv"):
            raise RuntimeError("uv not installed -- required for per-target venvs")
        env = target_env(dest)
        # uv sync builds its OWN .venv in dest from the repo's lockfile. Best
        # case: exact pinned deps, no resolution at all.
        if os.path.exists(os.path.join(dest, "uv.lock")):
            # PIN THE INTERPRETER HERE TOO (item 86). Without --python, uv sync
            # picks the newest CPython it can find (3.13/3.14 on this machine),
            # and the PythonRunner imports the target IN-PROCESS into ToFu's
            # 3.11 -- a cp313 wheel cannot load there, so every such target
            # silently produced "0 findings". If the lockfile's requires-python
            # excludes 3.11 we fall through to make_venv() and the repo becomes
            # an honest, recorded exclusion instead.
            p = run(["uv", "sync", "--frozen", "--python", TARGET_PYTHON], cwd=dest,
                    timeout=INSTALL_TIMEOUT, env=env)
            if p.returncode == 0:
                py = os.path.join(dest, ".venv", "bin", "python")
                if os.path.exists(py):
                    return "uv:frozen", py
            else:
                log(f"    uv sync --frozen --python {TARGET_PYTHON} failed "
                    f"({_err_head(p.stderr)}); falling back to a pinned venv + pip")
                shutil.rmtree(os.path.join(dest, ".venv"), ignore_errors=True)
        interp = make_venv(dest)
        env = target_env(dest, interp)
        # RESOLVE DEPENDENCIES AS OF THE COMMIT DATE. Repos pin their own code
        # but almost never their SDK: mindmap-mcp-server asks for "mcp>=1.2.0",
        # so a plain install pulls mcp 2.x, which renamed FastMCP -> MCPServer
        # and the server dies on import. --exclude-newer makes resolution both
        # contemporary AND reproducible.
        cutoff = ["--exclude-newer", last_commit] if last_commit else []
        notes = []
        did = False
        if os.path.exists(os.path.join(dest, "requirements.txt")):
            p = run(["uv", "pip", "install", "--python", interp, "-q"]
                    + cutoff + ["-r", "requirements.txt"], cwd=dest,
                    timeout=INSTALL_TIMEOUT, env=env)
            if p.returncode != 0:
                raise RuntimeError("uv pip -r requirements.txt failed: "
                                   + p.stderr.decode()[:120].strip())
            notes.append("uv:requirements.txt"); did = True
        if os.path.exists(os.path.join(dest, "pyproject.toml")):
            p = run(["uv", "pip", "install", "--python", interp, "-q"]
                    + cutoff + ["-e", "."],
                    cwd=dest, timeout=INSTALL_TIMEOUT, env=env)
            if p.returncode != 0 and cutoff:
                # The date cutoff is a heuristic, not ground truth: some repos
                # were updated after the snapshot recorded last_commit and
                # genuinely require a newer SDK. Retry unpinned before giving
                # up, and SAY SO in the note so the provenance is honest.
                p2 = run(["uv", "pip", "install", "--python", interp, "-q", "-e", "."],
                         cwd=dest, timeout=INSTALL_TIMEOUT, env=env)
                if p2.returncode == 0:
                    notes.append("uv:pyproject(no-cutoff)")
                    did = True
                    p = p2
            if p.returncode != 0:
                # A failed editable install is not fatal when requirements.txt
                # already succeeded -- many repos ship a pyproject that only
                # carries build metadata.
                if not did:
                    raise RuntimeError("uv pip install -e . failed: "
                                       + p.stderr.decode()[:120].strip())
                notes.append("uv:pyproject(failed,ignored)")
            else:
                notes.append("uv:pyproject"); did = True
        if not did:
            # No manifest at all. The venv is still correct to launch from:
            # empty, but isolated from ToFu.
            return "no-python-manifest", interp
        return "+".join(notes), interp
    # node -- no per-target interpreter; npm already installs into ./node_modules
    if os.path.exists(os.path.join(dest, "package.json")):
        note = None
        if os.path.exists(os.path.join(dest, "package-lock.json")):
            p = run(["npm", "ci", "--silent", "--no-audit", "--no-fund"],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode == 0: note = "npm:ci(lockfile)"
        if note is None:
            p = run(["npm", "install", "--silent", "--no-audit", "--no-fund"],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode != 0:
                raise RuntimeError("npm install failed: " + _err_head(p.stderr))
            note = "npm:install"
        try:
            pkg = json.load(open(os.path.join(dest, "package.json")))
            build_script = (pkg.get("scripts") or {}).get("build")
            if build_script:
                if "bun" in build_script and shutil.which("bun"):
                    bi = run(["bun", "install", "--no-progress"], cwd=dest, timeout=INSTALL_TIMEOUT)
                    note += ";bun-install" + ("" if bi.returncode == 0 else "(FAILED)")
                b = run(["npm", "run", "build", "--silent"], cwd=dest, timeout=INSTALL_TIMEOUT)
                if b.returncode == 0:
                    note += ";build"
                else:
                    # Keep the tail of stderr. Before this, a failed build left
                    # only "no node entrypoint (is a build step required?)" in
                    # skipped.jsonl -- 17 repos, zero diagnosis. The most common
                    # cause is a missing toolchain (bun, esbuild, tsc via a
                    # devDependency npm ci skipped), which is OUR gap, not the
                    # repo's, and must be visible.
                    note += ";build(FAILED: " + _err_head(b.stderr, n=3, width=120) + ")"
                    if "bun" in build_script and not shutil.which("bun"):
                        note += ";needs-bun"
        except Exception: pass
        return note, None
    raise RuntimeError("no package.json")

def detect_launch(dest, lang, interp=None):
    """Return (command, args) to start the MCP server over stdio.

    For Python targets `interp` MUST be the target's own venv interpreter.
    Launching with sys.executable runs the server against ToFu's site-packages
    (item 51) -- that is what broke all 75 Python repos.
    """
    if lang == "node":
        pkgp = os.path.join(dest, "package.json")
        if os.path.exists(pkgp):
            try: pkg = json.load(open(pkgp))
            except Exception: pkg = {}
            # built output FIRST -- package.json "main" often points at TS source
            cands = ["dist/index.js", "build/index.js", "dist/server.js",
                     "dist/main.js", "build/server.js"]
            b = pkg.get("bin")
            if isinstance(b, str): cands.append(b)
            elif isinstance(b, dict): cands.extend(b.values())
            if pkg.get("main"): cands.append(pkg["main"])
            # tsconfig outDir: `tsc` builds land wherever compilerOptions.outDir
            # says, which is often not dist/ or build/.
            try:
                tsc = json.load(open(os.path.join(dest, "tsconfig.json")))
                out_dir = ((tsc.get("compilerOptions") or {}).get("outDir") or "").strip("./")
                if out_dir:
                    cands += [f"{out_dir}/index.js", f"{out_dir}/server.js", f"{out_dir}/main.js",
                              f"{out_dir}/index.cjs", f"{out_dir}/index.mjs"]
            except Exception:
                pass
            cands += ["dist/index.cjs", "dist/index.mjs", "build/index.cjs", "build/index.mjs",
                      "index.js", "index.cjs", "index.mjs", "src/index.js", "server.js"]
            for c in cands:
                fp = os.path.join(dest, c)
                # .cjs / .mjs are first-class Node entrypoints; the old test
                # `c.endswith(".js")` rejected e.g. dist/index.cjs outright.
                if c.endswith((".js", ".cjs", ".mjs")) and os.path.exists(fp):
                    return "node", [fp]
        raise RuntimeError("no node entrypoint (is a build step required?)")
    # python
    for c in ["server.py", "main.py", "app.py", "__main__.py",
              "src/server.py", "src/main.py", "src/__main__.py"]:
        fp = os.path.join(dest, c)
        if os.path.exists(fp): return (interp or sys.executable), [fp]
    # installed console script from pyproject
    pp = os.path.join(dest, "pyproject.toml")
    if os.path.exists(pp):
        try:
            txt = open(pp, encoding="utf-8", errors="ignore").read()
            if "[project.scripts]" in txt:
                seg = txt.split("[project.scripts]", 1)[1].split("[", 1)[0]
                for line in seg.strip().splitlines():
                    if "=" not in line or ":" not in line:
                        continue
                    script = line.split("=", 1)[0].strip().strip('"\'')
                    target = line.split("=", 1)[1].strip().strip('"\'')
                    mod = target.split(":")[0]
                    # PREFER THE INSTALLED CONSOLE SCRIPT. "pkg:main" means the
                    # entry point is a FUNCTION, so `-m pkg` fails with
                    # "'pkg' is a package and cannot be directly executed"
                    # unless the package happens to ship __main__.py. The venv's
                    # bin/ script calls the function directly and always works.
                    if interp:
                        binp = os.path.join(os.path.dirname(interp), script)
                        if os.path.exists(binp):
                            return binp, []
                    # `-m` only if the module is directly runnable
                    if os.path.exists(os.path.join(dest, *mod.split("."))
                                      + os.sep + "__main__.py") or "." in mod:
                        return (interp or sys.executable), ["-m", mod]
        except Exception: pass
    raise RuntimeError("no python entrypoint")

def probe_tools(command, args, cwd, interp=None, extra_env=None):
    """Speak MCP over stdio and ask for tools/list.

    MCP servers are long-lived: they do NOT exit after answering, so we must
    read incrementally and stop as soon as the tools/list reply arrives rather
    than waiting for process exit.
    """
    import threading, queue
    init = {"jsonrpc":"2.0","id":1,"method":"initialize","params":{
            "protocolVersion":"2024-11-05","capabilities":{},
            "clientInfo":{"name":"tofu-prepare","version":"1.0"}}}
    msgs = [json.dumps(init),
            json.dumps({"jsonrpc":"2.0","method":"notifications/initialized"}),
            json.dumps({"jsonrpc":"2.0","id":2,"method":"tools/list"})]

    proc = subprocess.Popen([command] + args, cwd=cwd, env=target_env(cwd, interp, extra_env),
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, bufsize=1)
    q = queue.Queue()
    def reader():
        try:
            for line in proc.stdout: q.put(line)
        except Exception: pass
        q.put(None)
    threading.Thread(target=reader, daemon=True).start()

    tools, err = [], None
    try:
        for m in msgs:
            proc.stdin.write(m + "\n"); proc.stdin.flush()
        deadline = time.time() + PROBE_TIMEOUT
        while time.time() < deadline:
            try: line = q.get(timeout=1.0)
            except Exception: continue
            if line is None: break
            line = line.strip()
            if not line.startswith("{"): continue
            try: msg = json.loads(line)
            except Exception: continue
            if msg.get("id") == 2:
                if isinstance(msg.get("result"), dict):
                    tools = [t for t in msg["result"].get("tools", []) if t.get("name")]
                elif msg.get("error"):
                    err = str(msg["error"])[:120]
                break
    finally:
        try: proc.stdin.close()
        except Exception: pass
        proc.terminate()
        try: proc.wait(timeout=5)
        except Exception: proc.kill()

    if not tools:
        # Keep the HEAD of stderr (the "Error: ..." line), not the tail of a
        # stack trace -- the tail is always "at node:internal/..." and told us
        # nothing for 70 skipped repos. Also keep a short tail for context.
        tail = ""
        try:
            raw = proc.stderr.read() or ""
            head = _err_head(raw.encode() if isinstance(raw, str) else raw, n=2, width=160)
            tail = head + " || tail: " + raw[-120:].replace("\n", " ")
        except Exception: pass
        raise RuntimeError((f"tools/list error: {err}" if err else
                            "no tools/list reply") + (f" | stderr: {tail}" if tail else ""))
    return tools

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-set", choices=["a","b","d","e","host","full"], default=None,
                    help="host = the 41 repos that prepared READY on the host (set_host.json); reproduces the host executable corpus in the sandbox")
    ap.add_argument("--limit", type=int, default=None)
    ap.add_argument("--only-repo", default=None,
                    help="comma-separated substrings; prepare only repos matching one")
    ap.add_argument("--only-lang", choices=["python","node"], default=None,
                    help="restrict to one runtime")
    ap.add_argument("--retry-skipped", action="store_true",
                    help="re-attempt repos previously recorded in skipped.jsonl. "
                         "Needed after item 51: the 75 Python skips were caused "
                         "by the harness, not by the repos, so the exclusion "
                         "list must be recomputed before it is reported.")
    ap.add_argument("--shard", default=None, metavar="K/N",
                    help="deterministic K-of-N split of the todo list (K in 0..N-1) so N "
                         "prepare processes can run in parallel on disjoint repos; e.g. "
                         "0/4 .. 3/4. All shards share prepared.jsonl/skipped.jsonl "
                         "(append-only) and never touch the same repo.")
    ap.add_argument("--redo", action="store_true",
                    help="re-prepare repos even if already READY (requires --only-repo). "
                         "clone() wipes the target dir, so the venv is rebuilt from "
                         "scratch -- use after item 86 to move Python venvs onto "
                         f"TOFU_TARGET_PYTHON={TARGET_PYTHON}.")
    a = ap.parse_args()
    if a.redo and not (a.only_repo or a.only_lang):
        log("--redo needs --only-repo or --only-lang (refusing to re-prepare the whole corpus)"); sys.exit(2)

    for d in (TGTDIR, CFGDIR, STATE): os.makedirs(d, exist_ok=True)

    sel = []
    # Set D (VIPER-MCP's own 0-day servers) is opt-in only: it is NOT part of
    # the default a+b sweep, because its commits are GitHub HEAD rather than the
    # paper's vulnerable revision (see set_d_manifest.json). Ask for it by name.
    if a.only_set:
        names = [a.only_set]
    else:
        names = ["a", "b"]
    for name in names:
        path = os.path.join(EXTR, f"set_{name}.json")
        if not os.path.exists(path):
            log(f"MISSING {path} -- run from the repo root"); sys.exit(1)
        for r in json.load(open(path))[f"set_{name}"]:
            sel.append(dict(r, set=name.upper()))

    done = load_done()
    if a.retry_skipped:
        done = {k: v for k, v in done.items() if v != "skipped"}
    if a.redo:
        # scope: --only-repo substrings and/or --only-lang (lang comes from the
        # sampling-set rows, which is the same source `todo` is built from).
        pats = [x.strip().lower() for x in (a.only_repo or "").split(",") if x.strip()]
        lang_of = {r["repo"]: r["lang"] for r in sel}
        redo = [k for k in done
                if (not pats or any(pt in k.lower() for pt in pats))
                and (not a.only_lang or lang_of.get(k) == a.only_lang)]
        for k in redo: done.pop(k, None)
        log(f"--redo: re-preparing {len(redo)} already-recorded repo(s): {redo}")
    todo = [r for r in sel if r["repo"] not in done]
    if a.only_lang:
        todo = [r for r in todo if r["lang"] == a.only_lang]
    if a.only_repo:
        pats = [x.strip().lower() for x in a.only_repo.split(",") if x.strip()]
        todo = [r for r in todo if any(pt in r["repo"].lower() for pt in pats)]
    if a.shard:
        k, n = (int(x) for x in a.shard.split("/"))
        assert 0 <= k < n, "--shard K/N needs 0 <= K < N"
        todo = [r for i, r in enumerate(todo) if i % n == k]
        log(f"--shard {k}/{n}: this process takes {len(todo)} repo(s)")
    if a.limit: todo = todo[:a.limit]
    log(f"selected={len(sel)} already_done={len(done)} todo={len(todo)}")

    ok = skip = 0
    for i, r in enumerate(todo, 1):
        repo, commit, lang = r["repo"], r.get("commit"), r["lang"]
        dest = os.path.join(TGTDIR, repo.replace("/", "__"))
        log(f"({i}/{len(todo)}) {repo} [{lang}, Set {r['set']}]")
        note = None
        try:
            if not commit: raise RuntimeError("no pinned commit recorded")
            clone(repo, commit, dest)
            hints = TARGET_ENV_HINTS.get(repo, {})
            note, interp = install(dest, lang, r.get("last_commit"))
            command, args = detect_launch(dest, lang, interp)
            # In-process oracle prerequisite (item 86): the venv MUST match
            # ToFu's interpreter. Record it; the runner refuses loudly otherwise.
            pyver = _venv_pyver(interp) if lang == "python" else None
            inprocess_ok = (pyver == TARGET_PYTHON) if lang == "python" else None
            if lang == "python" and not inprocess_ok:
                log(f"    WARNING venv python={pyver} != TOFU_TARGET_PYTHON={TARGET_PYTHON}: "
                    f"stdio probe will work, in-process fuzzing will NOT (recorded inprocess_ok=false)")
            entry = _console_entry(dest, command) if lang == "python" else None
            command, args = apply_launch_hints(repo, dest, command, args)
            tools = probe_tools(command, args, dest, interp, hints)
            ncfg = 0
            for t in tools:
                cfg = {"_repo": repo, "_set": r["set"], "_lang": lang,
                       "_commit": commit, "_stars": r.get("stars"),
                       "command": command, "args": args, "cwd": dest,
                       # item 86: venv interpreter + console-script entry, so the
                       # in-process runner can import the module and refuse a
                       # mismatched venv instead of failing silently.
                       "python": pyver, "python_entry": entry,
                       "target_tool": t["name"],
                       "_tool_description": t.get("description", ""),
                       # override_rules INTENTIONALLY EMPTY -> forces
                       # llm.select_sanitizers() (fuzzer.py:801), which is the
                       # automated path the paper actually claims.
                       "override_rules": {}, "predefined_seeds": [],
                       # placeholder credentials the runner must pass to the
                       # target (src/__main__ -> FuzzerConfig.target_env);
                       # empty for the vast majority of targets.
                       "env": hints}
                fn = f"{repo.replace('/','__')}__{t['name']}.json"
                json.dump(cfg, open(os.path.join(CFGDIR, fn), "w"), indent=1)
                ncfg += 1
            record(PREPARED, {"repo": repo, "set": r["set"], "lang": lang,
                              "commit": commit, "status": "ready", "install": note,
                              "command": command, "args": args, "cwd": dest,
                              "python": pyver, "inprocess_ok": inprocess_ok,
                              "python_entry": entry,
                              "n_tools_probed": len(tools), "n_configs": ncfg,
                              "env_hints": sorted(hints.keys()),
                              "launch_hints": bool(TARGET_LAUNCH_HINTS.get(repo)),
                              "tools": [t["name"] for t in tools]})
            ok += 1; log(f"    READY  {len(tools)} tools -> {ncfg} configs ({note})")
        except Exception as e:
            reason = str(e)[:220]
            # If install ran, append its note: a "no node entrypoint" that
            # follows "build(FAILED: ...)" is a toolchain gap, not a repo gap.
            try:
                if "note" in dir() and note and ("FAILED" in note or "needs-bun" in note):
                    reason = (reason + " || install: " + note)[:400]
            except Exception:
                pass
            record(SKIPPED, {"repo": repo, "set": r["set"], "lang": lang,
                             "commit": commit, "status": "skipped", "reason": reason})
            shutil.rmtree(dest, ignore_errors=True)
            skip += 1; log(f"    SKIP   {reason}")

    log(f"DONE ready={ok} skipped={skip}")
    log(f"  configs   -> {CFGDIR}")
    log(f"  exclusions-> {SKIPPED}  (this is the paper's exclusion list)")

if __name__ == "__main__":
    main()
