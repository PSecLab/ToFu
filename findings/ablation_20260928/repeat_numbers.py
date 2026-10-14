#!/usr/bin/env python3
"""Run-to-run variation of Full ToFu: 3 independent 60 s runs (abl-full, abl-r2-full, abl-r3-full)
on the same 1,801 tools, code, budget, host and replayed LLM output. Writes repeat_numbers.json.
Run from the repo root: python3 findings/ablation_20260928/repeat_numbers.py"""
import collections, json, os, statistics, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "eval")); from triage_findings import classify
RUNS = {"run1": "runs.abl-full.jsonl", "run2": "runs.abl-r2-full.jsonl", "run3": "runs.abl-r3-full.jsonl"}
ARMS = {"nollmseeds": "runs.abl-nollmseeds.jsonl", "mandatory": "runs.abl-mandatory.jsonl",
        "nollm": "runs.abl-nollm.jsonl", "noseeds": "runs.abl-noseeds.jsonl", "allsan": "runs.abl-allsan.jsonl"}
def load(f):
    rows = [json.loads(l) for l in open(os.path.join(HERE, f)) if l.strip()]
    B = {}
    for r in rows:
        if r.get("ok") and r.get("finding_hits"):
            c = classify(r.get("triggered_sanitizers"))
            if c: B[(r["repo"], r["tool"])] = c[0]
    ex = sum(1 for r in rows if (r.get("n_exec_success") or 0) >= 1)
    return rows, B, ex
R = {k: load(f) for k, f in RUNS.items()}
bugs = {k: len(v[1]) for k, v in R.items()}; ex = {k: v[2] for k, v in R.items()}
sets = [set(v[1]) for v in R.values()]
inter, union = set.intersection(*sets), set.union(*sets)
in_k = collections.Counter(sum(k in s for s in sets) for k in union)
pair = {f"{a}-{b}": round(len(set(R[a][1]) & set(R[b][1])) / len(set(R[a][1]) | set(R[b][1])), 3)
        for a, b in (("run1", "run2"), ("run1", "run3"), ("run2", "run3"))}
cls = {k: collections.Counter(v[1].values()) for k, v in R.items()}
allc = sorted(set().union(*cls.values()))
per_class = {c: dict(values=[cls[k].get(c, 0) for k in RUNS],
                     mean=round(statistics.mean(cls[k].get(c, 0) for k in RUNS), 1),
                     min=min(cls[k].get(c, 0) for k in RUNS), max=max(cls[k].get(c, 0) for k in RUNS))
             for c in allc}
m, sd = statistics.mean(bugs.values()), statistics.stdev(bugs.values())
arms = {a: len(load(f)[1]) for a, f in ARMS.items()}
out = dict(bugs=bugs, bugs_mean=round(m, 1), bugs_sd=round(sd, 1), bugs_min=min(bugs.values()),
           bugs_max=max(bugs.values()), executed=ex, executed_mean=round(statistics.mean(ex.values()), 1),
           executed_min=min(ex.values()), executed_max=max(ex.values()),
           found_by_all_3=len(inter), found_by_any=len(union), found_in_exactly={str(k): in_k[k] for k in (1, 2, 3)},
           pairwise_jaccard=pair, per_class=per_class,
           arms_vs_full_range={a: dict(bugs=n, delta_vs_mean=round(n - m, 1),
                                       outside_full_range=not (min(bugs.values()) <= n <= max(bugs.values())),
                                       delta_in_sd=round((n - m) / sd, 1) if sd else None) for a, n in arms.items()})
json.dump(out, open(os.path.join(HERE, "repeat_numbers.json"), "w"), indent=1)
print(json.dumps(out, indent=1))
