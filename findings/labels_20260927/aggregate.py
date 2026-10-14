"""Aggregate the precision labels (labels_[A-F].json) into per-class and headline rates.
Strict precision = TP / labelled; lenient = (TP + TP-low) / labelled (UNCLEAR counts as not TP).
The headline estimate weights each class's rate by its share of the 508 bugs; classes with no
labelled item (hard-coded credentials, 1 bug) are excluded from the weights and reported."""
import json, glob, math, collections, os
HERE = os.path.dirname(os.path.abspath(__file__))
ev = {s["id"]: s for s in json.load(open(os.path.join(HERE, "evidence.json")))}
lab = {}
for p in sorted(glob.glob(os.path.join(HERE, "labels_[A-F].json"))):
    for x in json.load(open(p)):
        lab[x["id"]] = x
missing = sorted(set(ev) - set(lab))
TOTAL = {"reflected-xss": 222, "log-injection": 122, "path-traversal": 106, "ssrf": 42,
         "insecure-temp-file": 6, "os-command-injection": 5, "data-exfiltration": 4, "hardcoded-creds": 1}
def wilson(k, n, z=1.96):
    if not n: return (0, 0)
    p = k / n; d = 1 + z * z / n; c = p + z * z / (2 * n); h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - h) / d, (c + h) / d)
VIEW = os.environ.get("VIEW", "bug-exists")  # or "alert-grounded": code-only TPs count as FP
per = collections.defaultdict(collections.Counter)
for i, x in lab.items():
    l = x["label"]
    if VIEW == "alert-grounded" and x.get("basis") == "code-only": l = "FP"
    per[ev[i]["cls"]][l] += 1
print("VIEW:", VIEW)
print(f"labelled {len(lab)} / {len(ev)}; missing ids: {missing}")
print(f"{'class':22s} {'n':>3} {'TP':>3} {'low':>3} {'FP':>3} {'unc':>3}  strict  lenient")
ws = wl = W = 0.0; var_s = var_l = 0.0
for c in TOTAL:
    k = per.get(c)
    if not k: print(f"{c:22s}   0  (no labelled item; {TOTAL[c]} bug(s) excluded from the estimate)"); continue
    n = sum(k.values()); s = k["TP"] / n; l = (k["TP"] + k["TP-low"]) / n
    print(f"{c:22s} {n:3d} {k['TP']:3d} {k['TP-low']:3d} {k['FP']:3d} {k['UNCLEAR']:3d}  {s:6.0%}  {l:6.0%}")
    w = TOTAL[c]; W += w; ws += w * s; wl += w * l
    fpc = (TOTAL[c] - n) / (TOTAL[c] - 1) if TOTAL[c] > 1 else 0
    var_s += w * w * s * (1 - s) / n * fpc; var_l += w * w * l * (1 - l) / n * fpc
S, L = ws / W, wl / W; es, el = 1.96 * math.sqrt(var_s) / W, 1.96 * math.sqrt(var_l) / W
print(f"\nweighted over {int(W)} bugs: strict {S:.0%} ±{es:.0%}  (≈{S*W:.0f} bugs) | lenient {L:.0%} ±{el:.0%}  (≈{L*W:.0f} bugs)")
json.dump({"per_class": {c: dict(v) for c, v in per.items()}, "strict": S, "strict_ci95": es,
           "lenient": L, "lenient_ci95": el, "weighted_over": W, "n_labelled": len(lab)},
          open(os.path.join(HERE, f"precision.{VIEW}.json"), "w"), indent=1)
