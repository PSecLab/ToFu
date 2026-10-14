import json, os, collections, sys
sys.path.insert(0, "eval"); from triage_findings import classify, REAL
SANS = collections.defaultdict(set)
for n, (c, _) in REAL: SANS[c].add(n)
want = {os.path.splitext(l.strip())[0] for l in open("Benchmarks/extraction/ablation_extra15_configs.txt") if l.strip()}
def load(a):
    d = {}
    for l in open(f"eval/state/runs.abl-{a}.jsonl"):
        r = json.loads(l); k = os.path.splitext(r["config"])[0]
        if k in want: d[k] = r
    return d
A, F = load("allsan"), load("full")
def bug(r):
    if not (r.get("ok") and r.get("finding_hits")): return None
    c = classify(r.get("triggered_sanitizers")); return c[0] if c else None
out = []
for k, r in sorted(A.items()):
    cls = bug(r)
    if not cls: continue
    fr = F.get(k, {}); fcls = bug(fr) if fr else None
    L = open(r["log"], errors="replace").read().split("\n")
    ev = []
    for j, l in enumerate(L):
        if "-> Triggered Sanitizers" in l and any(x in l for x in SANS[cls]):
            blk = L[max(0, j - 4):j + 1]
            g = lambda tag: next((b.split(tag, 1)[1].strip() for b in blk if tag in b), "")
            e = {"input": g("Faulty Input :")[:400], "output": g("Tool Output  :")[:500],
                 "analysis": g("Analysis     :")[:500], "sanitizers": g("Triggered Sanitizers :")[:300]}
            if e not in ev: ev.append(e)
            if len(ev) >= 3: break
    cfg = json.load(open(f"eval/configs/{k}.json"))
    out.append(dict(repo=r["repo"], tool=r["tool"], cls=cls, lang=r["lang"], commit=r.get("commit"),
                    config=k, target=cfg.get("cwd") or "", triggered=r.get("triggered_sanitizers"),
                    n_exec=r.get("n_exec"), n_success=r.get("n_exec_success"),
                    full_class=fcls, full_triggered=fr.get("triggered_sanitizers"),
                    evidence=ev, n_ev=len(ev)))
for i, x in enumerate(out): x["id"] = i + 1
json.dump(out, open("eval/state/allsan_evidence15.json", "w"), indent=1)
c = collections.Counter(x["cls"] for x in out)
print(len(out), "bugs;", sum(1 for x in out if x["n_ev"]), "with evidence;", sum(1 for x in out if x["full_class"]), "tool also flagged by full;", dict(c))
