"""Per-repository coverage-over-time for the deep campaign's budget-exhausted repos.

Usage: python3 plot_rq4_repos.py <timelines_dir> <out.pdf>
Selection (stated, not hand-picked): every repository whose run ended with
stop_reason == budget_exhausted (it used all 24 worker-hours); within each, the tool
with the largest final coverage. Y = covered edges (libFuzzer `cov`, cov_edges_best),
not basic blocks and not a percentage: no total-code denominator is recorded.
"""
import csv, json, os, sys
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

HERE = os.path.dirname(os.path.abspath(__file__))
T, OUT = sys.argv[1], sys.argv[2]
INK, INK2, SERIES, GRID = "#0b0b0b", "#52514e", "#2a78d6", "#e6e5e1"

picks = []
for arm in ("repo24", "repo24-b"):
    for l in open(os.path.join(HERE, f"repo24_results.{arm}.jsonl")):
        x = json.loads(l)
        if x.get("stop_reason") != "budget_exhausted":
            continue
        best = None
        for t in x["tools"]:
            p = os.path.join(T, f"metrics_{arm}", t["config"], "stitched_coverage.csv")
            if not os.path.exists(p):
                continue
            rows = [(float(r["tool_clock_s"]), float(r["cov_edges_best"])) for r in csv.DictReader(open(p))]
            if rows and (best is None or rows[-1][1] > best[2][-1][1]):
                best = (x["repo"], t["tool"], rows)
        if best:
            picks.append(best)
picks.sort(key=lambda b: -b[2][-1][1])

plt.rcParams.update({"font.size": 6.5, "font.family": "serif", "axes.edgecolor": INK2,
                     "xtick.color": INK2, "ytick.color": INK2,
                     "axes.spines.top": False, "axes.spines.right": False})
fig, axes = plt.subplots(2, 4, figsize=(6.8, 2.9), constrained_layout=True)
for ax, (repo, tool, rows) in zip(axes.ravel(), picks):
    xs = [max(a, 1.0) for a, _ in rows]; ys = [b for _, b in rows]
    xs.append(max(xs[-1], 1.0)); ys.append(ys[-1])
    ax.step(xs, ys, where="post", color=SERIES, lw=1.2)
    ax.set_xscale("log"); ax.set_xlim(1, max(xs[-1] * 1.2, 3600 * 1.5))
    ax.set_xticks([1, 60, 3600]); ax.set_xticklabels(["1s", "1m", "1h"])
    for v in (60, 3600):
        ax.axvline(v, color=INK2, lw=0.5, ls=(0, (2, 2)))
    ax.grid(axis="y", color=GRID, lw=0.5); ax.set_axisbelow(True)
    ax.set_ylim(0, ys[-1] * 1.12)
    c60 = max([b for a, b in rows if a <= 60] or [0])
    ax.set_title(f"{repo.split('/')[-1]}\n{tool}", fontsize=6, color=INK, loc="left")
    ax.text(0.97, 0.05, f"{int(c60)}→{int(ys[-1])}", transform=ax.transAxes,
            ha="right", va="bottom", fontsize=6, color=INK)
    print(f"{repo:40s} {tool:32s} cov@60s {int(c60):5d} final {int(ys[-1]):5d} clock {rows[-1][0]/3600:.1f}h")
for ax in axes[:, 0]:
    ax.set_ylabel("covered edges")
for ax in axes[1, :]:
    ax.set_xlabel("fuzzing time")
fig.savefig(OUT); fig.savefig(OUT.rsplit(".", 1)[0] + ".png", dpi=300)
print("wrote", OUT)
