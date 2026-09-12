#!/usr/bin/env python3
"""
BASELINE #2: MCPSafetyScanner (johnhalloran321/mcpSafetyScanner) over ToFu's
own prepared targets -- the second of the two baselines VIPER-MCP uses, so the
numbers sit next to a published competitor's.

Same discipline as run_cisco_scanner.py: read eval/state/prepared.jsonl (the
exact launch commands the ToFu campaign used), scan each server, append one
JSON line per repo to eval/state/mcpsafety_runs.jsonl. RESUMABLE.

WHAT THIS TOOL IS. Multi-agent (agno) auditor: it connects over stdio, reads
the tool list, and has LLM agents reason about dangerous capabilities. It
writes NO report file -- rich console output only -- so we capture stdout to a
per-repo .log and record a HEURISTIC flag count (lines matching risk words).
Treat n_flag_lines as a screening signal, not a finding count; read the log.

LLM held fixed at gpt-4.1 (OPENAI_MODEL) to match the ToFu gpt41-full arm and
the Cisco baseline. Its default is gpt-4o.

  python3 eval/run_mcpsafety.py --preflight
  python3 eval/run_mcpsafety.py --limit 1          # smoke
  python3 eval/run_mcpsafety.py                    # all ready servers
"""
import argparse, json, os, re, subprocess, sys, tempfile, time

ROOT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE  = os.path.join(ROOT, "eval", "state")
PREPARED = os.path.join(STATE, "prepared.jsonl")
RUNS   = os.path.join(STATE, "mcpsafety_runs.jsonl")
OUT    = os.path.join(ROOT, "eval", "mcpsafety_runs")
SCAN_DIR = os.path.join(ROOT, "Benchmarks", "MCPSafetyScanner")
SCAN_PY  = os.path.join(SCAN_DIR, ".venv", "bin", "python")
SCAN     = os.path.join(SCAN_DIR, "mcpsafety", "scanner", "scan.py")

RISK = re.compile(r"vulnerab|exploit|malicious|risk|danger|CRITICAL|HIGH|"
                  r"sensitive|leak|inject|traversal|credential", re.I)

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def read_jsonl(p):
    out = []
    if os.path.exists(p):
        for line in open(p):
            try: out.append(json.loads(line))
            except Exception: pass
    return out

def build_env():
    env = os.environ.copy()
    env["OPENAI_MODEL"] = os.environ.get("MCPSAFETY_MODEL", "gpt-4.1")
    # the scanner also probes for Azure/Ollama; make sure neither hijacks it
    for k in ("AZURE_OPENAI_API_KEY", "AZURE_OPENAI_ENDPOINT", "OLLAMA_MODEL"):
        env.pop(k, None)
    return env

def preflight():
    ok = True
    if not os.path.exists(SCAN_PY):
        log(f"PREFLIGHT FAIL: {SCAN_PY} missing -- uv venv + uv pip install -e . in {SCAN_DIR}"); ok = False
    if not os.environ.get("OPENAI_API_KEY"):
        log("PREFLIGHT FAIL: OPENAI_API_KEY not set (set -a; . ./.env; set +a)"); ok = False
    log(f"model: {build_env()['OPENAI_MODEL']}")
    ready = [t for t in read_jsonl(PREPARED) if t.get("status") == "ready"]
    log(f"targets: {len(ready)} ready servers from {PREPARED}")
    if not ready: ok = False
    return ok

def one(target, timeout):
    repo = target["repo"]; slug = repo.replace("/", "__")
    os.makedirs(OUT, exist_ok=True)
    logfile = os.path.join(OUT, slug + ".log")
    rec = {"repo": repo, "set": target.get("set"), "lang": target.get("lang"),
           "commit": target.get("commit"), "started": time.time(),
           "model": build_env()["OPENAI_MODEL"], "n_tools_expected": target.get("n_tools_probed")}
    # claude_desktop_config.json shape. It has no cwd field, so we run the
    # scanner WITH cwd = the target's directory: the stdio child inherits it
    # and relative reads resolve where the server expects (bug-21 lesson).
    cfg = {"mcpServers": {slug: {"command": target["command"], "args": target.get("args", [])}}}
    t0 = time.time()
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(cfg, f); cfgp = f.name
    try:
        p = subprocess.run([SCAN_PY, SCAN, "--config", cfgp, "--verbose"],
                           cwd=target.get("cwd", ROOT), env=build_env(),
                           capture_output=True, timeout=timeout)
        out = p.stdout.decode(errors="ignore") + "\n" + p.stderr.decode(errors="ignore")
        rec.update(returncode=p.returncode, ok=p.returncode == 0)
    except subprocess.TimeoutExpired as e:
        out = ((e.stdout or b"").decode(errors="ignore") + "\n" + (e.stderr or b"").decode(errors="ignore"))
        rec.update(returncode=None, ok=False, error=f"timeout after {timeout}s")
    except Exception as e:
        out = ""; rec.update(ok=False, error=str(e)[:200])
    finally:
        try: os.unlink(cfgp)
        except Exception: pass
    with open(logfile, "w") as f: f.write(out)
    lines = [l for l in out.splitlines() if l.strip()]
    rec.update(log=os.path.relpath(logfile, ROOT), n_lines=len(lines),
               n_flag_lines=sum(1 for l in lines if RISK.search(l)),
               seconds=round(time.time() - t0, 1))
    if not rec.get("ok") and "error" not in rec and lines:
        rec["error"] = lines[-1][:200]
    return rec

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--preflight", action="store_true")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=int, default=600, help="per-server seconds (agents can hang on cred-gated servers)")
    ap.add_argument("--only", default=None, help="substring filter on repo")
    a = ap.parse_args()
    if not preflight(): sys.exit(1)
    if a.preflight: return
    done = {r["repo"] for r in read_jsonl(RUNS)}
    ready = [t for t in read_jsonl(PREPARED) if t.get("status") == "ready" and t["repo"] not in done]
    if a.only: ready = [t for t in ready if a.only.lower() in t["repo"].lower()]
    if a.limit: ready = ready[:a.limit]
    log(f"todo={len(ready)} already_done={len(done)}")
    for i, t in enumerate(ready, 1):
        rec = one(t, a.timeout)
        with open(RUNS, "a") as f: f.write(json.dumps(rec) + "\n")
        tag = "OK  " if rec.get("ok") else "ERR "
        log(f"{tag}[{i}/{len(ready)}] {t['repo']} {rec['seconds']}s flag_lines={rec['n_flag_lines']} {rec.get('error','')[:80]}")
    log(f"index -> {RUNS}   logs -> {OUT}")

if __name__ == "__main__":
    main()
