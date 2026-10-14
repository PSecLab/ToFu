import json, re, glob, os, importlib.util, collections
spec = importlib.util.spec_from_file_location("tr", "eval/triage_findings.py"); tr = importlib.util.module_from_spec(spec); spec.loader.exec_module(tr)
SANS = collections.defaultdict(set)
for n, (c, _) in tr.REAL: SANS[c].add(n)
R = os.path.expanduser("~/pseclab/ToFu_repo24_results")
commit = {}
for p in glob.glob(f"{R}/*/eval/state/*.jsonl") + ["findings/baselines/tofu_runs_e2_20260922.jsonl"]:
    for l in open(p, errors="replace"):
        try: r = json.loads(l)
        except: continue
        if r.get("repo") and r.get("commit"): commit.setdefault(r["repo"], r["commit"])
S = json.load(open("findings/labels_20260927/sample.json"))
for i, s in enumerate(S):
    L = open(s["log"], errors="replace").read().split("\n")
    ev = []
    for j, l in enumerate(L):
        if "-> Triggered Sanitizers" in l and any(x in l for x in SANS[s["cls"]]):
            blk = L[max(0, j-4):j+1]
            g = lambda tag: next((b.split(tag, 1)[1].strip() for b in blk if tag in b), "")
            ev.append({"input": g("Faulty Input :")[:400], "output": g("Tool Output  :")[:500],
                       "analysis": g("Analysis     :")[:500], "sanitizers": g("Triggered Sanitizers :")[:200]})
            if len(ev) >= 3: break
    desc = next((L[k] for k in range(len(L)) if "description" in L[k].lower() and s["tool"] in L[k]), "")[:300]
    s.update(id=i + 1, commit=commit.get(s["repo"], ""), evidence=ev, n_ev=len(ev))
json.dump(S, open("findings/labels_20260927/evidence.json", "w"), indent=1)
print("items", len(S), "| with >=1 evidence block", sum(1 for s in S if s["n_ev"]), "| with commit", sum(1 for s in S if s["commit"]))
