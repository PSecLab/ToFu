#!/usr/bin/env python3
"""Corpus-wide coverage figures: every tool on one axis, not one tool per figure.

WHAT THIS PLOTS AND WHAT IT REFUSES TO PLOT
  * Only runs whose tool ACTUALLY EXECUTED (index field executable == "yes").
    A flat line from a target that errored on every input is an artifact of the
    environment, not a measurement of ToFu, and averaging it in drags the
    median toward zero.
  * Only timelines from ONE arm+run. eval/metrics_<arm>/<tool>/ accumulates a
    CSV per invocation, so a tool fuzzed twice has two files. Mixing a
    pre-fix and a post-fix run on one axis is how you publish a graph of your
    own bugs -- see nazmul.todo bugs 20/21. --since filters by wall-clock.

Usage:
  python3 eval/plot_coverage_aggregate.py --arm gpt41-full --since "2026-09-11 07:00"
"""
import argparse, csv, glob, json, os, statistics as st
from datetime import datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_index(arm):
    p = os.path.join(ROOT, "eval", "state", f"runs.{arm}.jsonl")
    rows = {}
    if os.path.exists(p):
        for line in open(p):
            try:
                d = json.loads(line)
            except Exception:
                continue
            key = os.path.splitext(d.get("config", ""))[0]
            rows[key] = d
    return rows


def load_timelines(arm, since_ts, index):
    """Return {run_key: [(t, cov, corp, execs)]} for executable runs only."""
    out, skipped = {}, {"not_executable": 0, "too_old": 0, "empty": 0}
    base = os.path.join(ROOT, "eval", f"metrics_{arm}")
    for d in sorted(glob.glob(os.path.join(base, "*"))):
        key = os.path.basename(d)
        meta = index.get(key)
        if meta is not None and meta.get("executable") != "yes":
            skipped["not_executable"] += 1
            continue
        best = None
        for c in glob.glob(os.path.join(d, "coverage_timeline_*.csv")):
            if os.path.getmtime(c) < since_ts:
                continue
            if best is None or os.path.getmtime(c) > os.path.getmtime(best):
                best = c
        if best is None:
            skipped["too_old"] += 1
            continue
        pts = []
        with open(best) as fh:
            for r in csv.DictReader(fh):
                try:
                    pts.append((float(r["relative_time_sec"]), int(r["cov_edges"]),
                                int(r["corpus_count"]), int(r["exec_count"])))
                except Exception:
                    continue
        if len(pts) < 2:
            skipped["empty"] += 1
            continue
        out[key] = sorted(pts)
    return out, skipped


def resample(pts, grid):
    """Step-interpolate a monotone coverage curve onto a common time grid."""
    vals, i, last = [], 0, pts[0][1]
    for g in grid:
        while i < len(pts) and pts[i][0] <= g:
            last = pts[i][1]
            i += 1
        vals.append(last if g >= pts[0][0] else None)
    return vals


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="gpt41-full")
    ap.add_argument("--since", default=None,
                    help='ignore timelines older than this, e.g. "2026-09-11 07:00"')
    ap.add_argument("--outdir", default=None)
    a = ap.parse_args()

    since_ts = 0.0
    if a.since:
        since_ts = datetime.strptime(a.since, "%Y-%m-%d %H:%M").timestamp()

    index = load_index(a.arm)
    tl, skipped = load_timelines(a.arm, since_ts, index)
    if not tl:
        print("no eligible timelines; check --arm and --since"); return
    print(f"arm={a.arm}  eligible runs={len(tl)}  skipped={skipped}")

    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    horizon = max(p[0] for pts in tl.values() for p in pts)
    grid = [horizon * i / 200.0 for i in range(201)]
    curves = {k: resample(v, grid) for k, v in tl.items()}

    outdir = a.outdir or os.path.join(ROOT, "ToFu_src", "figs", f"coverage_{a.arm}")
    os.makedirs(outdir, exist_ok=True)

    fig, axes = plt.subplots(2, 2, figsize=(12, 8))

    # (a) every run + median/IQR
    ax = axes[0][0]
    for v in curves.values():
        xs = [g for g, y in zip(grid, v) if y is not None]
        ys = [y for y in v if y is not None]
        ax.plot(xs, ys, color="0.8", lw=0.6, zorder=1)
    med, lo, hi = [], [], []
    for i, g in enumerate(grid):
        col = sorted(v[i] for v in curves.values() if v[i] is not None)
        if not col:
            med.append(None); lo.append(None); hi.append(None); continue
        med.append(st.median(col))
        lo.append(col[int(0.25 * (len(col) - 1))])
        hi.append(col[int(0.75 * (len(col) - 1))])
    gx = [g for g, m in zip(grid, med) if m is not None]
    ax.fill_between(gx, [x for x in lo if x is not None],
                    [x for x in hi if x is not None], alpha=.25, color="tab:blue", zorder=2)
    ax.plot(gx, [m for m in med if m is not None], color="tab:blue", lw=2.2, zorder=3,
            label=f"median (n={len(curves)})")
    ax.set_xlabel("time (s)"); ax.set_ylabel("coverage (edges)")
    ax.set_title("(a) Coverage per tool, median and IQR"); ax.legend(fontsize=8)

    # (b) normalised -> saturation shape
    ax = axes[0][1]
    for v in curves.values():
        ys = [y for y in v if y is not None]
        if not ys or ys[-1] == 0:
            continue
        xs = [g for g, y in zip(grid, v) if y is not None]
        ax.plot(xs, [y / ys[-1] for y in ys], color="0.8", lw=0.6)
    nm = []
    for i, g in enumerate(grid):
        col = []
        for v in curves.values():
            ys = [y for y in v if y is not None]
            if ys and ys[-1] and v[i] is not None:
                col.append(v[i] / ys[-1])
        nm.append(st.median(col) if col else None)
    gx = [g for g, m in zip(grid, nm) if m is not None]
    ax.plot(gx, [m for m in nm if m is not None], color="tab:red", lw=2.2)
    ax.axhline(0.9, ls="--", lw=.8, color="0.4")
    ax.set_xlabel("time (s)"); ax.set_ylabel("fraction of final coverage")
    ax.set_title("(b) Saturation (normalised)")

    # (c) per repo
    ax = axes[1][0]
    byrepo = {}
    for k, v in curves.items():
        repo = index.get(k, {}).get("repo") or k.split("__")[0]
        byrepo.setdefault(repo, []).append(v)
    for repo, vs in sorted(byrepo.items(), key=lambda kv: -len(kv[1])):
        m = []
        for i in range(len(grid)):
            col = [v[i] for v in vs if v[i] is not None]
            m.append(st.median(col) if col else None)
        gx = [g for g, y in zip(grid, m) if y is not None]
        ax.plot(gx, [y for y in m if y is not None], lw=1.4,
                label=f"{repo.split('/')[-1]} ({len(vs)})")
    ax.set_xlabel("time (s)"); ax.set_ylabel("coverage (edges)")
    ax.set_title("(c) Median coverage per repository")
    ax.legend(fontsize=6, ncol=2)

    # (d) final coverage distribution
    ax = axes[1][1]
    finals = sorted(([y for y in v if y is not None] or [0])[-1] for v in curves.values())
    # y = (i+1)/n, NOT i/n. With i/n the curve starts at 0 (claiming no tool
    # reaches the minimum, when one does) and ends at (n-1)/n, so it never
    # reaches 1.0 -- the earlier figure topped out at 0.97 for that reason.
    n = len(finals)
    ax.step(finals, [(i + 1) / n for i in range(n)], where="post",
            color="tab:green", lw=2)
    # Log x: the distribution spans 72..1960 with 60% of tools below 250, so a
    # linear axis compresses the bulk into the leftmost eighth of the panel.
    ax.set_xscale("log")
    ax.set_xlim(max(1, finals[0] * 0.8), finals[-1] * 1.25)
    ax.set_ylim(0, 1.02)
    ax.set_xlabel("final coverage (edges, log scale)")
    ax.set_ylabel("cumulative fraction of tools")
    ax.set_title(f"(d) Final coverage, CDF over {n} tools")
    ax.grid(alpha=.3, which="both")
    med = st.median(finals)
    ax.axvline(med, ls="--", lw=.9, color="0.4")
    ax.annotate(f"median {med:.0f}", xy=(med, 0.06),
                xytext=(4, 0), textcoords="offset points", fontsize=7, color="0.3")

    fig.suptitle(f"ToFu coverage across {len(curves)} tools "
                 f"({len(byrepo)} repositories), arm={a.arm}, {int(horizon)}s budget",
                 fontsize=11)
    fig.tight_layout()
    p = os.path.join(outdir, "coverage_aggregate.png")
    fig.savefig(p, dpi=160)
    fig.savefig(p.replace(".png", ".pdf"))
    print("wrote", p)

    print(f"\nfinal coverage over {len(finals)} tools: "
          f"min {finals[0]}  p25 {finals[int(.25*(len(finals)-1))]}  "
          f"median {st.median(finals)}  p75 {finals[int(.75*(len(finals)-1))]}  max {finals[-1]}")
    flat = sum(1 for v in curves.values()
               if ([y for y in v if y is not None] or [0])[-1] ==
                  ([y for y in v if y is not None] or [0])[0])
    print(f"tools whose coverage NEVER increased: {flat}/{len(curves)}")


if __name__ == "__main__":
    main()
