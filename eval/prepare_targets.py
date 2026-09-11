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

CLONE_TIMEOUT   = 180
INSTALL_TIMEOUT = 600
PROBE_TIMEOUT   = 60


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

def install(dest, lang):
    """Best-effort dependency install.

    Prefers the repo's OWN lockfile. This matters: the corpus snapshot is from
    mid-2025 and the MCP SDKs have shipped breaking changes since, so a plain
    `pip install`/`npm install` pulls a NEWER SDK than the pinned commit was
    written against and the server fails to import. Lockfiles avoid that.
    """
    if lang == "python":
        if os.path.exists(os.path.join(dest, "uv.lock")) and shutil.which("uv"):
            p = run(["uv", "sync", "--frozen"], cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode == 0: return "uv:frozen"
        if os.path.exists(os.path.join(dest, "requirements.txt")):
            p = run([sys.executable, "-m", "pip", "install", "-q", "-r", "requirements.txt"],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode != 0: raise RuntimeError("pip -r requirements.txt failed")
            return "pip:requirements.txt"
        if os.path.exists(os.path.join(dest, "pyproject.toml")):
            p = run([sys.executable, "-m", "pip", "install", "-q", "-e", "."],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode != 0: raise RuntimeError("pip install -e . failed")
            return "pip:pyproject"
        return "no-python-manifest"
    # node
    if os.path.exists(os.path.join(dest, "package.json")):
        note = None
        if os.path.exists(os.path.join(dest, "package-lock.json")):
            p = run(["npm", "ci", "--silent", "--no-audit", "--no-fund"],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode == 0: note = "npm:ci(lockfile)"
        if note is None:
            p = run(["npm", "install", "--silent", "--no-audit", "--no-fund"],
                    cwd=dest, timeout=INSTALL_TIMEOUT)
            if p.returncode != 0: raise RuntimeError("npm install failed")
            note = "npm:install"
        try:
            pkg = json.load(open(os.path.join(dest, "package.json")))
            if "build" in (pkg.get("scripts") or {}):
                b = run(["npm", "run", "build", "--silent"], cwd=dest, timeout=INSTALL_TIMEOUT)
                note += ";build" + ("" if b.returncode == 0 else "(FAILED)")
        except Exception: pass
        return note
    raise RuntimeError("no package.json")

def detect_launch(dest, lang):
    """Return (command, args) to start the MCP server over stdio."""
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
            cands += ["index.js", "src/index.js", "server.js"]
            for c in cands:
                fp = os.path.join(dest, c)
                if c.endswith(".js") and os.path.exists(fp):
                    return "node", [fp]
        raise RuntimeError("no node entrypoint (is a build step required?)")
    # python
    for c in ["server.py", "main.py", "app.py", "__main__.py",
              "src/server.py", "src/main.py", "src/__main__.py"]:
        fp = os.path.join(dest, c)
        if os.path.exists(fp): return sys.executable, [fp]
    # installed console script from pyproject
    pp = os.path.join(dest, "pyproject.toml")
    if os.path.exists(pp):
        try:
            txt = open(pp, encoding="utf-8", errors="ignore").read()
            if "[project.scripts]" in txt:
                seg = txt.split("[project.scripts]", 1)[1].split("[", 1)[0]
                for line in seg.strip().splitlines():
                    if "=" in line and ":" in line:
                        mod = line.split("=", 1)[1].strip().strip('"\'').split(":")[0]
                        return sys.executable, ["-m", mod]
        except Exception: pass
    raise RuntimeError("no python entrypoint")

def probe_tools(command, args, cwd):
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

    proc = subprocess.Popen([command] + args, cwd=cwd,
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
        tail = ""
        try: tail = (proc.stderr.read() or "")[-200:].replace("\n", " ")
        except Exception: pass
        raise RuntimeError((f"tools/list error: {err}" if err else
                            "no tools/list reply") + (f" | stderr: {tail}" if tail else ""))
    return tools

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--only-set", choices=["a","b","d","e"], default=None)
    ap.add_argument("--limit", type=int, default=None)
    a = ap.parse_args()

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
    todo = [r for r in sel if r["repo"] not in done]
    if a.limit: todo = todo[:a.limit]
    log(f"selected={len(sel)} already_done={len(done)} todo={len(todo)}")

    ok = skip = 0
    for i, r in enumerate(todo, 1):
        repo, commit, lang = r["repo"], r.get("commit"), r["lang"]
        dest = os.path.join(TGTDIR, repo.replace("/", "__"))
        log(f"({i}/{len(todo)}) {repo} [{lang}, Set {r['set']}]")
        try:
            if not commit: raise RuntimeError("no pinned commit recorded")
            clone(repo, commit, dest)
            note = install(dest, lang)
            command, args = detect_launch(dest, lang)
            tools = probe_tools(command, args, dest)
            ncfg = 0
            for t in tools:
                cfg = {"_repo": repo, "_set": r["set"], "_lang": lang,
                       "_commit": commit, "_stars": r.get("stars"),
                       "command": command, "args": args, "cwd": dest,
                       "target_tool": t["name"],
                       "_tool_description": t.get("description", ""),
                       # override_rules INTENTIONALLY EMPTY -> forces
                       # llm.select_sanitizers() (fuzzer.py:801), which is the
                       # automated path the paper actually claims.
                       "override_rules": {}, "predefined_seeds": []}
                fn = f"{repo.replace('/','__')}__{t['name']}.json"
                json.dump(cfg, open(os.path.join(CFGDIR, fn), "w"), indent=1)
                ncfg += 1
            record(PREPARED, {"repo": repo, "set": r["set"], "lang": lang,
                              "commit": commit, "status": "ready", "install": note,
                              "command": command, "args": args, "cwd": dest,
                              "n_tools_probed": len(tools), "n_configs": ncfg,
                              "tools": [t["name"] for t in tools]})
            ok += 1; log(f"    READY  {len(tools)} tools -> {ncfg} configs ({note})")
        except Exception as e:
            reason = str(e)[:220]
            record(SKIPPED, {"repo": repo, "set": r["set"], "lang": lang,
                             "commit": commit, "status": "skipped", "reason": reason})
            shutil.rmtree(dest, ignore_errors=True)
            skip += 1; log(f"    SKIP   {reason}")

    log(f"DONE ready={ok} skipped={skip}")
    log(f"  configs   -> {CFGDIR}")
    log(f"  exclusions-> {SKIPPED}  (this is the paper's exclusion list)")

if __name__ == "__main__":
    main()
