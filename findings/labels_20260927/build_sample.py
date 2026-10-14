"""Draw the precision-labelling sample from the 508-bug headline (RESULTS_SUMMARY 1a).
Census of classes with <=6 bugs; proportional random draw (seed 20260927) for the rest,
restricted to bugs whose evidence (an alert line for that class) survives in a local log."""
import json, os, re, random, runpy, io, contextlib, collections, glob, importlib.util
R = os.path.expanduser("~/pseclab/ToFu_repo24_results")
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path("findings/baselines/h2h_tofu_vs_viper_20260926.py")
U = g["U"]; X = sorted(k for k in U if k not in g["backend_dial"])
spec = importlib.util.spec_from_file_location("tr", "eval/triage_findings.py"); tr = importlib.util.module_from_spec(spec); spec.loader.exec_module(tr)
SANS = collections.defaultdict(set)
for name, (cls, _) in tr.REAL: SANS[cls].add(name)
dirs = [f"{R}/corpus-sbx/eval/runs/gpt41-corpus-sbx", f"{R}/recover-pc/eval/runs/gpt41-recover-pc",
        f"{R}/vm/eval/runs/repo24", f"{R}/pc/eval/runs/repo24-b"]
def logs_for(repo, tool):
    slug = repo.replace("/", "__") + "__" + tool
    out = []
    for d in dirs:
        out += [p for p in glob.glob(os.path.join(d, glob.escape(slug) + "*.log"))]
    return out
avail = {}
for k in X:
    repo, tool, cls = k
    for p in logs_for(repo, tool):
        with open(p, errors="replace") as f:
            txt = f.read()
        if any(s in txt for s in SANS[cls]) and "Faulty Input" in txt:
            avail[k] = p; break
by = collections.defaultdict(list)
for k in avail: by[k[2]].append(k)
tot = collections.Counter(k[2] for k in X)
print("class                 total  with-evidence")
for c, n in tot.most_common(): print(f"{c:22s} {n:5d}  {len(by[c]):5d}")
QUOTA = {"reflected-xss": 37, "log-injection": 20, "path-traversal": 18, "ssrf": 9}
rnd = random.Random(20260927); sample = []
for c, n in tot.items():
    pool = sorted(by[c])
    pick = pool if c not in QUOTA else rnd.sample(pool, min(QUOTA[c], len(pool)))
    sample += [{"repo": r, "tool": t, "cls": c, "log": avail[(r, t, c)]} for r, t, _ in pick]
json.dump(sample, open("findings/labels_20260927/sample.json", "w"), indent=1)
print("sample size:", len(sample), collections.Counter(s["cls"] for s in sample))
