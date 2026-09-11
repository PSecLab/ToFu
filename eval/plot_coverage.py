#!/usr/bin/env python3
"""Coverage-over-time figures from eval/metrics/*/coverage_timeline_*.csv.

WHAT IS AND IS NOT PLOTTABLE
Only runs where the tool ACTUALLY EXECUTED are eligible. A flat line from a
target that errored on every input says nothing about ToFu, and the existing
figures in ToFu_src/figs/coverage/ come from the era when JS coverage was
inert by construction (see nazmul.todo, "COVERAGE ON JS TARGETS IS INERT") --
do not mix the two sets on one axis.

Excluded automatically:
  * executable != yes                     (never ran; a flat line is an artifact)
  * runs whose success came from an in-band error payload (bug 17) -- these
    reported success_rate 1.0 while returning {'error': ...} to every input.
    Named explicitly in IN_BAND_ERROR_RUNS until they are re-run post-fix.

AXIS NOTE: the paper's current figures are 24-HOUR runs on hand-written
targets. These are 180-SECOND budget runs on corpus targets. Same quantity,
two orders of magnitude apart in duration -- label them so, and do not present
them as the same experiment.

    python3 eval/plot_coverage.py --outdir ToFu_src/figs/coverage_20260910
"""
import argparse, csv, glob, json, os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Bug 17: these answered every input with {'error': {...}} and no isError, so
# they scored success_rate 1.0 without running their own logic.
IN_BAND_ERROR_RUNS = {
    "freestylefly__mcp-server-weread__get_book_best_reviews",
    "freestylefly__mcp-server-weread__get_book_notes_and_highlights",
    "freestylefly__mcp-server-weread__get_bookshelf",
    "freestylefly__mcp-server-weread__search_books",
}


def load_index():
    idx = {}
    for p in glob.glob(os.path.join(ROOT, "eval/state/**/runs.jsonl"), recursive=True) + \
             [os.path.join(ROOT, "eval/state/runs.jsonl")]:
        if not os.path.exists(p):
            continue
        for line in open(p):
            if line.strip():
                d = json.loads(line)
                idx.setdefault(d["config"].replace(".json", ""), d)
    return idx


def series(path):
    with open(path) as f:
        rows = list(csv.DictReader(f))
    out = []
    for r in rows:
        try:
            out.append((float(r["relative_time_sec"]), int(r["cov_edges"]),
                        int(r["features"]), int(r["corpus_count"])))
        except (KeyError, ValueError):
            continue
    return sorted(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--outdir", default=os.path.join(ROOT, "ToFu_src/figs/coverage_20260910"))
    ap.add_argument("--min-rows", type=int, default=8)
    a = ap.parse_args()
    os.makedirs(a.outdir, exist_ok=True)

    idx = load_index()
    panels, skipped = [], []
    for d in sorted(glob.glob(os.path.join(ROOT, "eval/metrics/*/"))):
        name = os.path.basename(d.rstrip("/"))
        csvs = sorted(glob.glob(os.path.join(d, "*.csv")))
        if not csvs:
            continue
        rec = idx.get(name, {})
        if name in IN_BAND_ERROR_RUNS:
            skipped.append((name, "in-band error payload (bug 17)")); continue
        if rec.get("executable") != "yes":
            skipped.append((name, f"executable={rec.get('executable')}")); continue
        s = series(csvs[-1])
        if len(s) < a.min_rows:
            skipped.append((name, f"only {len(s)} samples")); continue
        panels.append((name, rec, s))

    print(f"plottable: {len(panels)}   skipped: {len(skipped)}")
    for n, why in skipped:
        print(f"   skip  {n[:58]:<60} {why}")
    if not panels:
        print("\nNothing to plot."); return

    for name, rec, s in panels:
        t = [x[0] - s[0][0] for x in s]
        cov, feat, corp = [x[1] for x in s], [x[2] for x in s], [x[3] for x in s]
        fig, ax = plt.subplots(figsize=(4.2, 2.8))
        ax.step(t, cov, where="post", lw=1.8, label="Covered edges")
        ax.step(t, feat, where="post", lw=1.2, ls="--", alpha=.8, label="Features")
        ax.set_xlabel("Time (s)"); ax.set_ylabel("Coverage")
        ax.set_title(f"{rec.get('repo','?')}\n{rec.get('tool','?')}", fontsize=8)
        ax2 = ax.twinx()
        ax2.step(t, corp, where="post", lw=1.0, color="tab:green", alpha=.6)
        ax2.set_ylabel("Corpus", color="tab:green", fontsize=8)
        ax2.tick_params(axis="y", labelcolor="tab:green", labelsize=7)
        ax.legend(fontsize=6, loc="upper left"); ax.grid(alpha=.25)
        sr = rec.get("exec_success_rate")
        ax.annotate(f"exec {rec.get('n_exec')}, success {sr:.0%}" if sr is not None else "",
                    xy=(.98, .04), xycoords="axes fraction", ha="right", fontsize=6, alpha=.7)
        fig.tight_layout()
        out = os.path.join(a.outdir, name + ".svg")
        fig.savefig(out); plt.close(fig)
        print(f"   wrote {out}")

    n = len(panels)
    ncol = min(3, n); nrow = (n + ncol - 1) // ncol
    fig, axes = plt.subplots(nrow, ncol, figsize=(4.0 * ncol, 2.6 * nrow), squeeze=False)
    for ax, (name, rec, s) in zip([x for r in axes for x in r], panels):
        t = [x[0] - s[0][0] for x in s]
        ax.step(t, [x[1] for x in s], where="post", lw=1.8)
        ax.set_title(f"{rec.get('repo','?')}::{rec.get('tool','?')}", fontsize=7)
        ax.set_xlabel("Time (s)", fontsize=7); ax.set_ylabel("Covered edges", fontsize=7)
        ax.tick_params(labelsize=6); ax.grid(alpha=.25)
    for ax in [x for r in axes for x in r][n:]:
        ax.axis("off")
    fig.suptitle("ToFu coverage over time -- 180 s budget, gemma4:12b, temperature 0 "
                 "(2026-09-10; NOT comparable to the 24 h figures in figs/coverage/)",
                 fontsize=8)
    fig.tight_layout(rect=[0, 0, 1, .94])
    grid = os.path.join(a.outdir, "_grid_all.svg")
    fig.savefig(grid); plt.close(fig)
    print(f"   wrote {grid}")


if __name__ == "__main__":
    main()
