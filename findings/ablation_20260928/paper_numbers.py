#!/usr/bin/env python3
"""Every number in PAPER_RESULTS.md, recomputed from the committed indices in this directory.
Run from the repo root: python3 findings/ablation_20260928/paper_numbers.py"""
import collections, json, os, statistics, sys
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
sys.path.insert(0, os.path.join(ROOT, "eval")); from triage_findings import classify
ARMS = ["full", "nollmseeds", "mandatory", "nollm", "noseeds", "allsan"]
CLASSES = ["path-traversal", "ssrf", "os-command-injection", "reflected-xss", "log-injection",
           "data-exfiltration", "insecure-temp-file", "hardcoded-creds"]
tr = lambda n: n.startswith("check_introspection_")
load = lambda a: [json.loads(l) for l in open(os.path.join(HERE, f"runs.abl-{a}.jsonl")) if l.strip()]

def bugs(rows, pick=lambda r: r.get("triggered_sanitizers"), need_hit=True):
    out = {}
    for r in rows:
        if not r.get("ok") or (need_hit and not r.get("finding_hits")): continue
        c = classify(pick(r))
        if c: out[(r["repo"], r["tool"])] = (c[0], r["lang"])
    return out

def summary(name, rows, B):
    ex = [r for r in rows if (r.get("n_exec_success") or 0) >= 1]
    eps = [r["n_exec"] / r["seconds"] for r in rows if r.get("n_exec") and r.get("seconds")]
    cls = collections.Counter(v[0] for v in B.values())
    lang = collections.Counter(v[1] for v in B.values())
    return dict(arm=name, configs=len(rows), ok=sum(bool(r.get("ok")) for r in rows),
                executed=len(ex), exec_py=sum(r["lang"] == "python" for r in ex),
                exec_js=sum(r["lang"] == "node" for r in ex),
                failfast=sum(bool(r.get("stopped_early")) for r in rows),
                median_eps=round(statistics.median(eps), 1), bugs=len(B),
                repos=len({k[0] for k in B}), py=lang["python"], js=lang["node"],
                **{c: cls.get(c, 0) for c in CLASSES})

R = {a: load(a) for a in ARMS}
full = bugs(R["full"]); out = []
for a in ARMS:
    B = full if a == "full" else bugs(R[a]); s = summary(a, R[a], B)
    s.update(shared=len(B.keys() & full.keys()), new=len(B.keys() - full.keys()), lost=len(full.keys() - B.keys()))
    out.append(s)
F = R["full"]
orc = {
    "tracers-only": bugs(F, lambda r: [x for x in r.get("triggered_sanitizers") or [] if tr(x)]),
    "outcome-only": bugs(F, lambda r: [x for x in r.get("triggered_sanitizers") or [] if not tr(x)]),
    "sanitizers-only": bugs(F, lambda r: [x for x in (r.get("triggered_sanitizers") or [])
                                          + (r.get("shadow_ungated_sanitizers") or []) if not tr(x)], need_hit=False),
}
for k, B in orc.items():
    s = summary(k, F, B); s.update(shared=len(B.keys() & full.keys()), new=len(B.keys() - full.keys()),
                                   lost=len(full.keys() - B.keys())); out.append(s)
json.dump(out, open(os.path.join(HERE, "paper_numbers.json"), "w"), indent=1)
cols = ["arm", "executed", "exec_py", "exec_js", "median_eps", "bugs", "repos", "py", "js", "shared", "new", "lost"] + CLASSES
print("\t".join(cols))
for s in out: print("\t".join(str(s[c]) for c in cols))
