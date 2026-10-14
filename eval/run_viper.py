#!/usr/bin/env python3
"""
BASELINE #3: VIPER-MCP (Sun et al. 2026) over ToFu's own prepared targets.
The closest competing system. Its batch scripts were REMOVED from the anonymous
artifact and config.yaml takes ONE server, so this generates a config per
target from eval/state/prepared.jsonl and loops. RESUMABLE via
eval/state/viper_runs.jsonl.

TWO PHASES. Phase I = CodeQL taint queries (needs the CodeQL CLI >= 2.16;
`brew install codeql` gives 2.27.0). Phase II = LLM agent that evolves prompts
until a value provably reaches a sink at runtime. --skip-codeql runs Phase II
alone, which is what we can do before CodeQL is installed. Paper reports ~15
min/server, Phase II dominating -- budget accordingly.

LLM held fixed at gpt-4.1 (their default is gpt-5.4) to match the ToFu
gpt41-full arm and the Cisco/MCPSafety baselines. Temperature forced to 0
(theirs 0.7) for reproducibility -- STATE THIS; it is a deviation from their
default protocol.

VIPER models exactly three classes -- command injection, SSRF, path traversal
-- and its authors say so. Do not read a VIPER miss on any other class as a
weakness; it is out of scope by design (MANIFEST.md).

  python3 eval/run_viper.py --preflight
  python3 eval/run_viper.py --test-agent --limit 1     # LLM connectivity, cheap
  python3 eval/run_viper.py --skip-codeql --limit 1    # Phase II smoke
  python3 eval/run_viper.py --skip-codeql              # all, Phase II
  python3 eval/run_viper.py                            # full, needs codeql
"""
import argparse, copy, json, os, shutil, subprocess, sys, time

ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "eval", "state")
PREPARED = os.path.join(STATE, "prepared.jsonl")
# VIPER_TAG=<name> isolates a campaign: its own index (eval/state/viper_runs.<tag>.jsonl)
# and outputs (eval/viper_runs/<tag>/<slug>), so a new campaign never overwrites the
# outputs an earlier table was counted from.
TAG   = os.environ.get("VIPER_TAG", "").strip()
RUNS  = os.path.join(STATE, f"viper_runs.{TAG}.jsonl" if TAG else "viper_runs.jsonl")
OUT   = os.path.join(ROOT, "eval", "viper_runs", TAG) if TAG else os.path.join(ROOT, "eval", "viper_runs")
VDIR  = os.path.join(ROOT, "Benchmarks", "Viper-MCP")
VPY   = os.environ.get("VIPER_PY") or os.path.join(VDIR, ".venv", "bin", "python")  # sandbox: /opt/viper-venv/bin/python
BASE_CFG = os.path.join(VDIR, "config.yaml")

sys.path.insert(0, os.path.join(VDIR, ".venv", "lib"))  # not needed; yaml via VPY below

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def read_jsonl(p):
    out = []
    if os.path.exists(p):
        for line in open(p):
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def load_yaml(path):
    # Use VIPER's own interpreter, which has pyyaml; ToFu's venv may not.
    code = "import sys,yaml,json; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))"
    p = subprocess.run([VPY, "-c", code, path], capture_output=True, text=True)
    if p.returncode != 0: raise RuntimeError("yaml load failed: " + p.stderr[:200])
    return json.loads(p.stdout)

def dump_yaml(obj, path):
    # JSON is valid YAML 1.2 -- write it as such. No yaml dep in ToFu's venv.
    with open(path, "w") as f: json.dump(obj, f, indent=2)

def make_cfg(base, target, slug, skip_codeql, codeql_bin, rounds):
    cfg = copy.deepcopy(base)
    resdir = os.path.join(OUT, slug)
    if TAG and os.path.isdir(resdir):
        # a tagged campaign re-runs a repo only when it has no ok row (interrupted or
        # failed); clear the partial outputs so stale verdicts never mix into the count
        shutil.rmtree(resdir)
    os.makedirs(resdir, exist_ok=True)
    ms = cfg.setdefault("mcp_server", {})
    ms["repo_path"] = target.get("cwd")
    ms["transport"] = "stdio"
    ms["startup_command"] = [target["command"]] + list(target.get("args", []))
    # Viper installs its Python runtime hook ONLY when startup_command[0] is a python
    # interpreter (instrumentation.py _iter_candidate_python_binaries). Most python
    # configs launch a venv console script (e.g. .venv/bin/paper-search-mcp), so Viper
    # never recognised them as python, installed no hook, and Phase II was blind
    # (2026-09-26 PC: hook_injected=False on 9/10, all hits 0). Run the SAME console
    # script through its venv interpreter: same server, same entry point, and Viper's
    # own instrumentation now engages.
    cmd0 = target.get("command") or ""
    if target.get("lang") == "python" and not os.path.basename(cmd0).startswith("python"):
        vpy = os.path.join(os.path.dirname(cmd0), "python")
        if os.path.isfile(cmd0) and os.path.exists(vpy):
            ms["startup_command"] = [vpy, cmd0] + list(target.get("args", []))
    ms["timeout"] = 30
    ms["interaction_log_path"] = os.path.join(resdir, "interactions.jsonl")
    model = os.environ.get("VIPER_MODEL", "gpt-4.1")
    key = os.environ.get("OPENAI_API_KEY", "")
    base_url = os.environ.get("OPENAI_BASE_URL") or None
    # hit_judge is read by config.hit_judge_llm (engine.py:327) but is ABSENT
    # from the shipped config.yaml -> {} -> falls back to prompt_llm. Set all
    # three so every LLM role is explicit and identical.
    for role in ("prompt_generator", "agent", "hit_judge"):
        r = cfg.setdefault("llm", {}).setdefault(role, {})
        r["provider"] = "openai"; r["model"] = model; r["api_key"] = key
        r["temperature"] = 0
        # base_url MUST be absent (None), never "". src/llm/__init__.py hands
        # the value straight to AsyncOpenAI(base_url=...), and the SDK treats
        # "" as a literal URL -> "Connection error" on every non-agent call.
        # Measured 2026-09-11: seed_generator, mutator, strategy scoring and
        # hit_judge all died this way while the langchain agent (tolerant of
        # "") kept working, which is why --test-agent passed and fuzz failed.
        if base_url: r["base_url"] = base_url
        else: r.pop("base_url", None)
    cq = cfg.setdefault("codeql", {})
    cq["language"] = "python" if target.get("lang") == "python" else "javascript"
    cq["codeql_binary_path"] = codeql_bin
    cq["report_path"] = os.path.join(resdir, "codeql_output")
    cq["query_pack_root"] = os.path.join(VDIR, "ql")
    cq["enabled"] = not skip_codeql
    if cq["language"] == "python":
        # item 95: the pyql pack does NOT mirror the jsql filename stems, so a
        # dir-only jsql/->pyql/ swap points codeql at nonexistent .ql files ->
        # `codeql database analyze` exits 2 -> no report.json -> "Anchor
        # enrichment skipped: report not found" on EVERY python repo. Map stems
        # explicitly (verified against Benchmarks/Viper-MCP/ql/pyql/src/).
        _PYQL = {
            "jsql/src/CommandInjectionFromRequest.ql": "pyql/src/CommandInjectionFromMcp.ql",
            "jsql/src/FileAccessFromRequest.ql":       "pyql/src/PathInjectionFromMcp.ql",
            "jsql/src/RequestForgeryFromRequest.ql":   "pyql/src/RequestForgeryFromMcp.ql",
        }
        mapped, missing = [], []
        for q in cq.get("queries", []):
            m = _PYQL.get(q, q.replace("jsql/", "pyql/"))
            mapped.append(m)
            if not os.path.isfile(os.path.join(cq["query_pack_root"], m)):
                missing.append(m)
        cq["queries"] = mapped
        if missing:
            print(f"[run_viper] WARNING python query pack missing: {missing}", flush=True)
    cfg.setdefault("fuzz", {})["rounds"] = rounds
    cfg.setdefault("logging", {})["file"] = os.path.join(resdir, "fuzzer.log")
    out = cfg.setdefault("output", {})
    out["directory"] = os.path.join(resdir, "fuzz_results")
    out["oracle_path"] = os.path.join(resdir, "oracle.json")   # engine._resolve_oracle_path
    p = os.path.join(resdir, "config.yaml")
    dump_yaml(cfg, p)
    return p, resdir

def preflight(skip_codeql, codeql_bin):
    ok = True
    if not os.path.exists(VPY):
        log(f"PREFLIGHT FAIL: {VPY} missing -- uv venv + uv pip install -r requirements.txt in {VDIR}"); ok = False
    if not os.environ.get("OPENAI_API_KEY"):
        log("PREFLIGHT FAIL: OPENAI_API_KEY not set"); ok = False
    if not skip_codeql and not shutil.which(codeql_bin) and not os.path.exists(codeql_bin):
        log(f"PREFLIGHT FAIL: codeql binary '{codeql_bin}' not found -- brew install codeql, or use --skip-codeql"); ok = False
    log(f"model={os.environ.get('VIPER_MODEL','gpt-4.1')}  codeql={'SKIPPED' if skip_codeql else codeql_bin}")
    ready = [t for t in read_jsonl(PREPARED) if t.get("status") == "ready"]
    log(f"targets: {len(ready)} ready servers from {PREPARED}")
    if not ready: ok = False
    return ok

def one(target, base, skip_codeql, codeql_bin, rounds, timeout, test_agent):
    repo = target["repo"]; slug = repo.replace("/", "__")
    rec = {"repo": repo, "set": target.get("set"), "lang": target.get("lang"),
           "commit": target.get("commit"), "started": time.time(),
           "model": os.environ.get("VIPER_MODEL", "gpt-4.1"), "skip_codeql": skip_codeql,
           "test_agent": test_agent, "rounds": rounds}
    t0 = time.time()
    try:
        cfgp, resdir = make_cfg(base, target, slug, skip_codeql, codeql_bin, rounds)
        cmd = [VPY, "main.py", cfgp]
        if skip_codeql: cmd.append("--skip-codeql")
        if test_agent: cmd.append("--test-agent")
        rec["cmd"] = " ".join(cmd)
        # VIPER resolves ./ql, ./results relative to ITS OWN dir -> cwd=VDIR.
        env = os.environ.copy()
        env["MCP_FUZZER_ORACLE_LOG"] = os.path.join(resdir, "oracle.json")
        p = subprocess.run(cmd, cwd=VDIR, env=env, capture_output=True, timeout=timeout)
        out = p.stdout.decode(errors="ignore") + "\n" + p.stderr.decode(errors="ignore")
        rec.update(returncode=p.returncode, ok=p.returncode == 0)
        fr = os.path.join(resdir, "fuzz_results")
        if os.path.isdir(fr):
            # results land one level down, <fuzz_results>/<repo_slug>/*.json
            files = [os.path.join(d, f) for d, _, fs in os.walk(fr) for f in fs]
            rec["n_result_files"] = len(files)
            # Viper's CONFIRMED verdicts live in triggered_vulnerability_prompts.json: one
            # entry per prompt its hit judge accepted (hit_judge.sink_reached &&
            # effect_success). The previous string search ('"vulnerable": true',
            # "exploit_success") matched nothing Viper writes, so it was 0 on every run.
            conf, chains = 0, set()
            for fp in files:
                if os.path.basename(fp) != "triggered_vulnerability_prompts.json":
                    continue
                try:
                    for e in json.load(open(fp)):
                        hj = (e or {}).get("hit_judge") or {}
                        if hj.get("sink_reached") and hj.get("effect_success"):
                            conf += 1
                            if e.get("target_call_chain"): chains.add(e["target_call_chain"])
                except Exception: pass
            rec["n_confirmed"] = conf
            rec["n_confirmed_distinct"] = len(chains)
            rec["n_hit_markers"] = conf          # kept for old readers; now = confirmed
        # Phase I static taint flows (CodeQL report written by Viper)
        import glob as _glob
        rep = _glob.glob(os.path.join(resdir, "codeql_output", "*", "report.json"))
        if rep:
            try: rec["n_static"] = len(json.load(open(rep[0])).get("vulnerabilities", []))
            except Exception: pass
        if os.path.isdir(fr):
            an = os.path.join(fr, slug, "anomalies.json")
            if os.path.exists(an):
                try: rec["n_anomalies"] = len(json.load(open(an)))
                except Exception: pass
        # oracle events = sink observations from the injected hook. hook_init
        # is the launcher's own marker (engine._is_internal_launcher_event);
        # count it separately -- its ABSENCE means the hook was never injected.
        # The engine may consume-and-clear the oracle file between rounds, so
        # the file left on disk after the run UNDER-reports. Derive injection
        # and hit evidence from the run's own log too: the hit_judge logs
        # "oracle_hits=N" every round, and the launcher logs hook_init.
        op = os.path.join(resdir, "oracle.json")
        ev = []
        if os.path.exists(op):
            ev = [l for l in open(op, errors="ignore") if l.strip()]
        flog = os.path.join(resdir, "fuzzer.log")
        max_hits, hook_seen = 0, False
        if os.path.exists(flog):
            import re as _re
            txt = open(flog, errors="ignore").read()
            hits = [int(x) for x in _re.findall(r"oracle_hits=(\d+)", txt)]
            max_hits = max(hits) if hits else 0
            hook_seen = "hook_init" in txt
        rec["n_oracle_events_on_disk"] = len(ev)
        # sink hits = hook observations EXCLUDING the hook_init marker (counting that line
        # made every repo whose hook merely loaded score >= 1 in the old H2H column)
        rec["n_sink_events"] = sum(1 for l in ev if '"hook_init"' not in l)
        rec["max_oracle_hits_in_round"] = max_hits
        # sidecar written by our hook patch (node_hook.js / mcp_fuzzer_hook.py): the engine
        # truncates oracle.json between rounds, so its hook_init line can vanish
        side = op + ".hook_init"
        rec["n_hook_inits"] = sum(1 for l in open(side, errors="ignore") if l.strip()) if os.path.exists(side) else 0
        rec["hook_injected"] = (any('"hook_init"' in l for l in ev) or hook_seen or max_hits > 0
                                or rec["n_hook_inits"] > 0)
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"").decode(errors="ignore") + "\n" + (e.stderr or b"").decode(errors="ignore"))
        rec.update(ok=False, error=f"timeout after {timeout}s")
    except Exception as e:
        out = ""; rec.update(ok=False, error=str(e)[:200])
    os.makedirs(OUT, exist_ok=True)
    logfile = os.path.join(OUT, slug + ".log")
    with open(logfile, "w") as f: f.write(out)
    lines = [l for l in out.splitlines() if l.strip()]
    if not rec.get("ok") and "error" not in rec and lines: rec["error"] = lines[-1][:200]
    rec.update(log=os.path.relpath(logfile, ROOT), seconds=round(time.time() - t0, 1))
    return rec

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--skip-codeql", action="store_true")
    ap.add_argument("--test-agent", action="store_true", help="LLM connectivity check only (one prompt)")
    ap.add_argument("--codeql", default=os.environ.get("VIPER_CODEQL", "codeql"))
    ap.add_argument("--rounds", type=int, default=int(os.environ.get("VIPER_ROUNDS", "10")))
    ap.add_argument("--timeout", type=int, default=1800, help="per-server seconds (paper: ~15 min)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--repos-file", default=None,
                    help="exact repo names, one per line; RESUMABLE: repos with an ok row in the index are skipped")
    ap.add_argument("--exact", action="store_true", help="--only entries are exact repo names, not substrings")
    ap.add_argument("--only", default=None,
                    help="comma-separated substrings; run ONLY repos matching one "
                         "(bypasses the done-set, for budget-limited subset runs)")
    a = ap.parse_args()
    if not preflight(a.skip_codeql or a.test_agent, a.codeql): sys.exit(1)
    if a.preflight: return
    base = load_yaml(BASE_CFG)
    done = {r["repo"] for r in read_jsonl(RUNS) if not r.get("test_agent")}
    ready = [t for t in read_jsonl(PREPARED) if t.get("status") == "ready"]
    # prepared.jsonl can hold a repo twice (re-prepared on another machine); keep the
    # latest row so a repo is never run -- and billed -- twice.
    ready = list({t["repo"]: t for t in ready}.values())
    if a.repos_file:
        want = [l.strip() for l in open(a.repos_file) if l.strip() and not l.startswith("#")]
        by = {t["repo"]: t for t in ready}
        missing = [r for r in want if r not in by]
        if missing:
            log(f"WARNING {len(missing)} listed repos not prepared/ready here: {missing[:10]}")
        ok_done = {r["repo"] for r in read_jsonl(RUNS) if r.get("ok") and not r.get("test_agent")}
        ready = [by[r] for r in want if r in by and r not in ok_done]
    elif a.only:
        # comma-separated substrings (or exact names with --exact); explicit targeting
        # BYPASSES the done-set so named repos re-run (subset runs to save LLM budget).
        pats = [p.strip() for p in a.only.split(",") if p.strip()]
        if a.exact:
            ready = [t for t in ready if t["repo"] in set(pats)]
        else:
            pats = [p.lower() for p in pats]
            ready = [t for t in ready if any(p in t["repo"].lower() for p in pats)]
    elif not a.test_agent:
        ready = [t for t in ready if t["repo"] not in done]
    if a.limit: ready = ready[:a.limit]
    log(f"todo={len(ready)} already_done={len(done)}")
    # --test-agent only exercises the LLM; never let it trigger a CodeQL build.
    skip_cq = a.skip_codeql or a.test_agent
    for i, t in enumerate(ready, 1):
        rec = one(t, base, skip_cq, a.codeql, a.rounds, a.timeout, a.test_agent)
        with open(RUNS, "a") as f: f.write(json.dumps(rec) + "\n")
        tag = "OK  " if rec.get("ok") else "ERR "
        log(f"{tag}[{i}/{len(ready)}] {t['repo']} {rec['seconds']}s static={rec.get('n_static','-')} "
            f"sink={rec.get('n_sink_events','-')} confirmed={rec.get('n_confirmed_distinct','-')} {rec.get('error','')[:90]}")
    log(f"index -> {RUNS}   logs -> {OUT}")

if __name__ == "__main__":
    main()
