#!/usr/bin/env python3
"""Select configs for the 24h deep-fuzz campaign (RQ4).

A long budget only helps where coverage has NOT saturated, so we rank each
reachable config by late-run coverage momentum from its coverage timeline:

    late_gain = cov(T_end) - cov(T_end / 2)      # edges found in the 2nd half
    recency   = t_last_new_edge / T_end          # 1.0 = still gaining at the end
    score     = late_gain * recency              # "climbing slope x surface"

late_gain grows with both how steep the curve still is and how big the reachable
program is (a larger surface yields more late edges); recency discounts a curve
that climbed early in the second half and then flattened. Saturated configs
score ~0 and are never picked. The measure is budget-agnostic, so the 60 s
corpus runs and the 300 s re-runs are comparable.

Eligible = latest run ok AND >=1 successful execution (the tool is reachable)
AND repo not on the unsafe-skip list AND a timeline with >=3 points. Selection
is greedy by score under a wall-clock budget, with a per-repo cap so the
campaign spreads over many repos instead of exhausting one.

  python3 eval/select_deep24.py                       # defaults: 5400 s, 5 workers, 24 h
  python3 eval/select_deep24.py --time 3600 --per-repo 5

Writes:
  eval/deep24_configs.txt                              (input to run_deep24.sh)
  findings/baselines/deep24_ranked_<date>.csv          (every eligible config)
  findings/baselines/deep24_selection_<date>.md        (the chosen set + baseline)
"""
import argparse, collections, csv, glob, json, math, os, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load_jsonl(p):
    out = []
    if not os.path.exists(p):
        return out
    for line in open(p):
        line = line.strip()
        if line:
            try:
                out.append(json.loads(line))
            except Exception:
                pass
    return out


def timeline(metrics_root, cfg):
    """Latest coverage timeline for a config -> sorted [(t, cov)]."""
    files = sorted(glob.glob(os.path.join(metrics_root, cfg, "coverage_timeline_*.csv")))
    if not files:
        return []
    pts = []
    try:
        for row in csv.DictReader(open(files[-1])):
            try:
                pts.append((float(row["relative_time_sec"]), int(float(row["cov_edges"]))))
            except Exception:
                pass
    except Exception:
        return []
    pts.sort()
    # coverage is cumulative; enforce monotonic so sampler jitter cannot fake a drop
    best, mono = 0, []
    for t, c in pts:
        best = max(best, c)
        mono.append((t, best))
    return mono


def cov_at(pts, t):
    c = 0
    for ti, ci in pts:
        if ti <= t:
            c = ci
        else:
            break
    return c


def momentum(pts):
    t_end = pts[-1][0]
    cov_f = pts[-1][1]
    cov_half = cov_at(pts, t_end / 2.0)
    late_gain = max(0, cov_f - cov_half)
    t_last = pts[0][0]
    prev = pts[0][1]
    for t, c in pts:
        if c > prev:
            t_last, prev = t, c
    recency = (t_last / t_end) if t_end > 0 else 0.0
    return {
        "t_end": round(t_end, 1),
        "cov_60": cov_at(pts, 60.0),
        "cov_half": cov_half,
        "cov_final": cov_f,
        "late_gain": late_gain,
        "t_last_new_edge": round(t_last, 1),
        "recency": round(recency, 3),
        "score": round(late_gain * recency, 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="gpt41-corpus", help="source arm whose runs/timelines are scored")
    ap.add_argument("--time", type=int, default=5400, help="per-config fuzz budget for the deep run (s)")
    ap.add_argument("--workers", type=int, default=5)
    ap.add_argument("--wall-hours", type=float, default=24.0)
    ap.add_argument("--overhead", type=int, default=120, help="per-config startup/teardown estimate (s)")
    ap.add_argument("--per-repo", type=int, default=4, help="max configs per repo")
    ap.add_argument("--min-cov", type=int, default=20, help="ignore trivially small programs")
    ap.add_argument("--unsafe", default="Benchmarks/extraction/set_e2_unsafe_repos.txt")
    ap.add_argument("--out-configs", default="eval/deep24_configs.txt")
    a = ap.parse_args()

    date = time.strftime("%Y%m%d")
    runs = load_jsonl(os.path.join(ROOT, "eval", "state", f"runs.{a.arm}.jsonl"))
    metrics_root = os.path.join(ROOT, "eval", f"metrics_{a.arm}")
    unsafe = set()
    up = os.path.join(ROOT, a.unsafe)
    if os.path.exists(up):
        unsafe = {p.strip().lower() for p in open(up).read().replace("\n", ",").split(",") if p.strip()}

    # latest row per config wins (re-runs append)
    latest = {}
    for r in runs:
        cfg = (r.get("config") or "").strip()
        if cfg.endswith(".json"):
            cfg = cfg[:-5]
        if cfg:
            latest[cfg] = r

    elig, reasons = [], collections.Counter()
    for cfg, r in latest.items():
        repo = r.get("repo") or ""
        if repo.lower() in unsafe:
            reasons["unsafe"] += 1; continue
        if not r.get("ok"):
            reasons["not ok"] += 1; continue
        if not (r.get("n_exec_success") or 0) > 0:
            reasons["unreachable (0 successful execs)"] += 1; continue
        pts = timeline(metrics_root, cfg)
        if len(pts) < 3:
            reasons["no/short timeline"] += 1; continue
        m = momentum(pts)
        if m["cov_final"] < a.min_cov:
            reasons[f"cov < {a.min_cov}"] += 1; continue
        m.update({
            "config": cfg, "repo": repo, "lang": r.get("lang") or "?", "tool": r.get("tool") or "",
            "succ": round(r.get("exec_success_rate") or 0, 3),
            "finding_hits": r.get("finding_hits") or 0,
            "classes": ",".join(r.get("finding_classes") or []) if isinstance(r.get("finding_classes"), list) else (r.get("finding_classes") or ""),
        })
        elig.append(m)

    elig.sort(key=lambda x: -x["score"])
    cap = int(a.workers * a.wall_hours * 3600 // (a.time + a.overhead))
    picked, per_repo = [], collections.Counter()
    for m in elig:
        if len(picked) >= cap:
            break
        if m["score"] <= 0:
            break  # saturated from here down
        if per_repo[m["repo"]] >= a.per_repo:
            continue
        picked.append(m); per_repo[m["repo"]] += 1

    # ---- outputs ----
    os.makedirs(os.path.join(ROOT, "findings", "baselines"), exist_ok=True)
    cols = ["config", "repo", "lang", "tool", "score", "late_gain", "recency", "cov_60",
            "cov_half", "cov_final", "t_end", "t_last_new_edge", "succ", "finding_hits", "classes"]
    ranked_p = os.path.join(ROOT, "findings", "baselines", f"deep24_ranked_{date}.csv")
    with open(ranked_p, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=cols); w.writeheader()
        for m in elig:
            w.writerow({k: m.get(k, "") for k in cols})

    with open(os.path.join(ROOT, a.out_configs), "w") as f:
        f.write(f"# deep24 selection {date}: {len(picked)} configs, time={a.time}s, "
                f"workers={a.workers}, wall={a.wall_hours}h, per-repo<={a.per_repo}\n")
        for m in picked:
            f.write(m["config"] + "\n")

    langs = collections.Counter(m["lang"] for m in picked)
    repos = collections.OrderedDict()
    for m in picked:
        repos.setdefault(m["repo"], []).append(m)
    wall = len(picked) * (a.time + a.overhead) / a.workers / 3600
    md = [f"# 24h deep-fuzz selection ({date})\n",
          f"Source arm `{a.arm}`; scored {len(latest)} configs, **{len(elig)} eligible**, "
          f"**{len(picked)} picked across {len(repos)} repos** "
          f"(cap {cap} = {a.workers} workers x {a.wall_hours}h / ({a.time}+{a.overhead})s; "
          f"per-repo <= {a.per_repo}). Estimated wall: **{wall:.1f} h**.\n",
          "Score = late_gain x recency, where late_gain = cov(T_end) - cov(T_end/2) "
          "and recency = time of last new edge / T_end. Saturated curves score 0.\n",
          f"Languages picked: {dict(langs)}\n",
          "Excluded: " + ", ".join(f"{k} {v}" for k, v in reasons.most_common()) + "\n",
          "## Picked (baseline recorded for the before/after comparison)\n",
          "| repo | lang | tool | score | cov@60s | cov_final (prior) | prior t_end | recency | succ | prior hits |",
          "|---|---|---|---|---|---|---|---|---|---|"]
    for repo, ms in repos.items():
        for m in ms:
            md.append(f"| {repo} | {m['lang']} | `{m['tool']}` | {m['score']} | {m['cov_60']} | "
                      f"{m['cov_final']} | {m['t_end']}s | {m['recency']} | {m['succ']} | {m['finding_hits']} |")
    sel_p = os.path.join(ROOT, "findings", "baselines", f"deep24_selection_{date}.md")
    open(sel_p, "w").write("\n".join(md) + "\n")

    print(f"eligible {len(elig)} / scored {len(latest)}; picked {len(picked)} configs "
          f"across {len(repos)} repos; est wall {wall:.1f}h; langs {dict(langs)}")
    print("excluded:", dict(reasons))
    print("wrote", os.path.relpath(os.path.join(ROOT, a.out_configs), ROOT),
          os.path.relpath(ranked_p, ROOT), os.path.relpath(sel_p, ROOT))


if __name__ == "__main__":
    main()
