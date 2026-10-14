"""RQ4 figure for the paper: coverage saturation and time-to-first-finding in the
repo24 deep campaign (24 worker-hours per repository, saturation stop).

Usage: python3 plot_rq4.py <timelines_dir> <out.pdf>
<timelines_dir> contains metrics_repo24/ and metrics_repo24-b/ (extract
stitched_timelines.<arm>.tgz there). First-appearance times use exactly the rule
in analyze_rq4.py: per (repo, tool, class), the tool-clock time of the first
stitched_findings.csv row whose sanitizer set classifies to that class.
"""
import csv, json, os, sys
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, "..", "..", "eval"))
from triage_findings import classify  # noqa: E402

T = sys.argv[1]
OUT = sys.argv[2]
INK, INK2, SERIES, GRID = "#0b0b0b", "#52514e", "#2a78d6", "#e6e5e1"

cov_curves, first = [], []
for arm in ("repo24", "repo24-b"):
    res = [json.loads(l) for l in open(os.path.join(HERE, f"repo24_results.{arm}.jsonl")) if l.strip()]
    for x in res:
        for t in x["tools"]:
            d = os.path.join(T, f"metrics_{arm}", t["config"])
            cp, fp = os.path.join(d, "stitched_coverage.csv"), os.path.join(d, "stitched_findings.csv")
            if os.path.exists(cp):
                rows = [(float(r["tool_clock_s"]), float(r["cov_edges_best"])) for r in csv.DictReader(open(cp))]
                if rows and rows[-1][1] > 0:
                    cov_curves.append(rows)
            if os.path.exists(fp):
                seen = set()
                for r in csv.DictReader(open(fp)):
                    c = classify(r["triggered_sanitizers"].split(","))
                    if c and c[0] not in seen:
                        seen.add(c[0]); first.append(float(r["tool_clock_s"]))

# (a) normalized coverage on a log-spaced grid (step function, carried forward)
grid = np.logspace(0, np.log10(24 * 3600), 200)
M = []
for rows in cov_curves:
    ts = np.array([a for a, _ in rows]); cs = np.array([b for _, b in rows]); fin = cs.max()
    idx = np.searchsorted(ts, grid, side="right") - 1
    v = np.where(idx >= 0, cs[np.clip(idx, 0, None)], 0.0) / fin
    v[grid > ts[-1]] = 1.0  # after its last sample a tool stays at its final coverage
    M.append(v)
M = np.array(M)
med, q1, q3 = np.median(M, 0), np.percentile(M, 25, 0), np.percentile(M, 75, 0)
at60 = np.median(M[:, np.searchsorted(grid, 60)])

first = np.sort(np.array(first)); n = len(first)
le60 = int((first <= 60).sum()); gt1h = int((first > 3600).sum())
print(f"tools with coverage: {len(M)} | median normalized coverage at 60 s: {at60:.2f}")
print(f"first appearances: {n} | <=60 s: {le60} ({le60/n:.0%}) | >1 h: {gt1h}")

plt.rcParams.update({"font.size": 7.5, "font.family": "serif", "axes.edgecolor": INK2,
                     "axes.labelcolor": INK, "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False})
fig, (a, b) = plt.subplots(1, 2, figsize=(3.4, 1.55), constrained_layout=True)
ticks = [1, 60, 3600, 86400]; labs = ["1s", "1m", "1h", "24h"]
for ax in (a, b):
    ax.set_xscale("log"); ax.set_xlim(1, 86400); ax.set_xticks(ticks); ax.set_xticklabels(labs)
    ax.set_ylim(0, 1.02); ax.grid(axis="y", color=GRID, lw=0.5); ax.set_axisbelow(True)
    for x in (60, 3600):
        ax.axvline(x, color=INK2, lw=0.6, ls=(0, (2, 2)))
    ax.set_xlabel("fuzzing time per tool")

a.fill_between(grid, q1, q3, color=SERIES, alpha=0.18, lw=0)
a.plot(grid, med, color=SERIES, lw=1.4)
a.set_ylabel("fraction of final coverage")
a.set_title(f"(a) coverage ({len(M)} tools)", fontsize=7.5, color=INK, loc="left")

b.step(first, np.arange(1, n + 1) / n, where="post", color=SERIES, lw=1.4)
b.set_ylabel("fraction of findings")
b.set_title(f"(b) first finding ({n})", fontsize=7.5, color=INK, loc="left")
b.annotate(f"{le60/n:.0%} by 1m", xy=(60, le60 / n), xytext=(150, 0.35), fontsize=6.5, color=INK,
           arrowprops=dict(arrowstyle="-", color=INK2, lw=0.5))

fig.savefig(OUT)
fig.savefig(OUT.rsplit(".", 1)[0] + ".png", dpi=300)
print("wrote", OUT)
