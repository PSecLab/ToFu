#!/usr/bin/env python3
"""After a no-LLM probe (TOFU_NO_LLM=1), list the configs whose tool actually EXECUTED
successfully, so the paid LLM pass runs only on those (no LLM spend on tools that never
run). Also prints how many bugs the free probe already found.

  python3 eval/select_executable.py --arm <probe-arm> [--out eval/<name>.txt]
"""
import argparse, json, os, collections
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", required=True)
    ap.add_argument("--out", default=None)
    ap.add_argument("--min-success", type=int, default=1, help="min successful executions to keep")
    a = ap.parse_args()
    idx = os.path.join(ROOT, "eval", "state", f"runs.{a.arm}.jsonl")
    rows = [json.loads(l) for l in open(idx) if l.strip()]
    latest = {}
    for r in rows:
        if r.get("config"): latest[r["config"]] = r
    execd = [c for c, r in latest.items() if (r.get("n_exec_success") or 0) >= a.min_success]
    repos_exec = {latest[c].get("repo") for c in execd}
    hits = sum(1 for r in latest.values() if r.get("finding_hits"))
    out = a.out or os.path.join(ROOT, "eval", f"executable_{a.arm}.txt")
    with open(out, "w") as f:
        f.write(f"# configs with >={a.min_success} successful exec in probe arm {a.arm} "
                f"({len(execd)} of {len(latest)} configs, {len(repos_exec)} repos). LLM pass targets these.\n")
        f.write("\n".join(sorted(c[:-5] if c.endswith('.json') else c for c in execd)) + "\n")
    print(f"probe arm {a.arm}: {len(latest)} configs, {len(execd)} executable ({len(repos_exec)} repos); "
          f"free probe bugs (finding_hits>0 rows): {hits}")
    print(f"wrote {os.path.relpath(out, ROOT)} -> feed to the LLM pass via --only-configs-file")

if __name__ == "__main__":
    main()
