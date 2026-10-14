"""RQ4 analysis of the repo24 deep campaign (findings/repo24_20260926/REPORT.md).

Usage: python3 analyze_rq4.py <results_dir>
<results_dir> holds {vm,pc}/eval/state/ (the runs/results jsonl here) and
{vm,pc}/eval/metrics_<arm>/ (extract stitched_timelines.<arm>.tgz there).
"""
import json, csv, os, sys, collections, glob
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "eval")); from triage_findings import classify
R = sys.argv[1] if len(sys.argv) > 1 else "."
def cands(rows):
    best = {}
    for r in rows:
        if not (r.get("ok") and r.get("finding_hits")): continue
        c = classify(r.get("triggered_sanitizers"))
        if not c: continue
        k = (r["repo"], r["tool"], c[0]); best[k] = max(best.get(k, 0), r.get("exec_success_rate") or 0)
    return best
corpus = cands(json.loads(l) for l in open(os.path.join(HERE, "..", "baselines", "tofu_runs_e2_20260922.jsonl")) if l.strip())
tot = collections.Counter()
for tag, arm in (("vm", "repo24"), ("pc", "repo24-b")):
    rows = [json.loads(l) for l in open(f"{R}/{tag}/eval/state/runs.{arm}.jsonl") if l.strip()]
    res = [json.loads(l) for l in open(f"{R}/{tag}/eval/state/repo24_results.{arm}.jsonl") if l.strip()]
    b = cands(rows); repos = {r["repo"] for r in res}
    corp_here = {k: v for k, v in corpus.items() if k[0] in repos}
    new = {k: v for k, v in b.items() if k not in corpus}
    lost = {k: v for k, v in corp_here.items() if k not in b}
    ts = collections.Counter(t["status"] for x in res for t in x["tools"])
    wh = sum(x["worker_h"] for x in res)
    print(f"== {tag} ({arm}): {len(res)} repos, {sum(x['n_tools'] for x in res)} tools {dict(ts)}, "
          f"{wh:.0f} worker-h used of {sum(x['budget_h'] for x in res):.0f} budgeted")
    print(f"   candidates {len(b)} (hi {sum(1 for v in b.values() if v>=.5)}) in {len({k[0] for k in b})} repos; "
          f"corpus(60s) had {len(corp_here)} on these repos -> NEW {len(new)}, also-in-corpus {len(b)-len(new)}, corpus-only {len(lost)}")
    print("   by class:", dict(collections.Counter(k[2] for k in b)), " new by class:", dict(collections.Counter(k[2] for k in new)))
    # time of first appearance of each (tool, class) on the stitched tool clock
    first = []
    for x in res:
        for t in x["tools"]:
            p = f"{R}/{tag}/eval/metrics_{arm}/{t['config']}/stitched_findings.csv"
            if not os.path.exists(p): continue
            seen = set()
            for row in csv.DictReader(open(p)):
                c = classify(row["triggered_sanitizers"].split(","))
                if c and c[0] not in seen:
                    seen.add(c[0]); first.append(((x["repo"], t["tool"], c[0]) in new, float(row["tool_clock_s"])))
    for lab, sel in (("all", [s for _, s in first]), ("NEW", [s for n, s in first if n])):
        if sel:
            sel.sort(); q = lambda f: sel[min(len(sel)-1, int(f*len(sel)))]
            print(f"   first-appearance tool-clock ({lab}, n={len(sel)}): median {q(.5)/60:.1f} min, p90 {q(.9)/60:.1f} min, "
                  f"<=60s {sum(1 for s in sel if s<=60)}, >1h {sum(1 for s in sel if s>3600)}")
    tot["cand"] += len(b); tot["new"] += len(new)
print("TOTAL candidates", tot["cand"], "new vs corpus", tot["new"])

print("\n===== breakdown =====")
NEWOR = {"reflected-xss", "data-exfiltration"}
for tag, arm in (("vm", "repo24"), ("pc", "repo24-b")):
    rows = [json.loads(l) for l in open(f"{R}/{tag}/eval/state/runs.{arm}.jsonl") if l.strip()]
    res = [json.loads(l) for l in open(f"{R}/{tag}/eval/state/repo24_results.{arm}.jsonl") if l.strip()]
    b = cands(rows); repos = {r["repo"] for r in res}
    corp_here = {k: v for k, v in corpus.items() if k[0] in repos}
    lost = [k for k in corp_here if k not in b]
    status = {(x["repo"], t["tool"]): t["status"] for x in res for t in x["tools"]}
    reach = {(x["repo"], t["tool"]) for x in res for t in x["tools"]}
    print(f"[{tag}] corpus-only {len(lost)} by class:", dict(collections.Counter(k[2] for k in lost)))
    print(f"   their repo24 tool status:", dict(collections.Counter(status.get((k[0], k[1]), "NOT-IN-repo24(unreachable in corpus?)") for k in lost)))
    new = [k for k in b if k not in corpus]
    print(f"   NEW {len(new)}: via new oracles {sum(1 for k in new if k[2] in NEWOR)}, other classes {sum(1 for k in new if k[2] not in NEWOR)} -> {[k for k in new if k[2] not in NEWOR]}")
