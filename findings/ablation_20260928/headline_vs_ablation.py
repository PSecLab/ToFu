#!/usr/bin/env python3
"""Why the ablation's Full ToFu (one fresh 60 s run) differs from the 508 headline (union of all
campaigns). Run from the repo root: python3 findings/ablation_20260928/headline_vs_ablation.py"""
import collections, contextlib, io, json, os, runpy, sys
sys.path.insert(0, "eval"); from triage_findings import classify
X = lambda f: [l.strip() for l in open(f"Benchmarks/extraction/{f}") if l.strip() and not l.startswith("#")]
D = set(X("h2h_273_dynamic_repos.txt"))
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path("findings/baselines/h2h_tofu_vs_viper_20260926.py")
    u = runpy.run_path("findings/union_20260926/analyze_union.py")
T = g["U"] - g["backend_dial"]; assert len(T) == 508
H = {(r, t) for r, t, c in T if r in D}
A, B, C = ({(x[0], x[1]) for x in u[k]} for k in ("A", "B", "C"))
rows = {(r["repo"], r["tool"]): r for r in map(json.loads, open("findings/ablation_20260928/runs.abl-full.jsonl"))}
F = {k for k, r in rows.items() if r.get("ok") and r.get("finding_hits") and classify(r.get("triggered_sanitizers"))}
ho = H - F
src = lambda k: "+".join(n for n, S in (("60s", A), ("24h", B), ("errored-call", C)) if k in S)
print(f"headline on 266: {len(H)} | ablation full: {len(F)} | both: {len(H & F)} | headline-only: {len(ho)} | ablation-only: {len(F - H)}")
print("headline-only by source:", dict(collections.Counter(src(k) for k in ho)))
