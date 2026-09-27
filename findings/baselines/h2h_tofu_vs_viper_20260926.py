#!/usr/bin/env python3
"""ToFu vs Viper-MCP head-to-head on the 45-repo H2H set. Regenerates
findings/baselines/h2h_tofu_vs_viper_20260926.{md,json}. Run from the repo root:
  python3 findings/baselines/h2h_tofu_vs_viper_20260926.py

ToFu  = the consolidated 648 set U from findings/union_20260926/analyze_union.py
        (RESULTS_SUMMARY 1a), restricted to the H2H repos.
Viper = findings/baselines/viper_h2h_corrected_20260926.json (recounted from Viper's
        own outputs: static = Phase I CodeQL flows, sink = Phase II hook hits excl.
        hook_init, confirmed = hit_judge sink_reached && effect_success).
CodeQL / Cisco columns = findings/baselines/head_to_head_per_repo_20260922.json
        (static tools, unchanged, not re-run).
"""
import json, os, runpy, collections, contextlib, io
ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
F = lambda *p: os.path.join(ROOT, "findings", *p)
load = lambda p: [json.loads(l) for l in open(p) if l.strip()]

with contextlib.redirect_stdout(io.StringIO()):            # analyze_union prints + rewrites its REPORT
    g = runpy.run_path(F("union_20260926", "analyze_union.py"))
U = g["U"]
assert len(U) == 648, f"union is {len(U)}, expected 648 -- RESULTS_SUMMARY 1a changed?"

h2h = {r["repo"]: r for r in json.load(open(F("baselines", "head_to_head_per_repo_20260922.json")))["rows"]}
vip = {r["repo"]: r for r in json.load(open(F("baselines", "viper_h2h_corrected_20260926.json")))["rows"]}
unsafe = set(open(os.path.join(ROOT, "Benchmarks", "extraction", "set_e2_unsafe_repos.txt")).read().strip().split(","))
ran = set()
# SSRF bugs resting ONLY on check_introspection_ssrf (no check_url_* outcome oracle): that tracer fires on
# any loopback/private connect and does not check the host came from input. Every logged case (47/140)
# is one fixed host:port per repo = the server's own default backend (e.g. meilisearch 127.0.0.1:7700,
# freecad 9875, dolphinscheduler 12345, boto3 IMDS 169.254.169.254) -> likely tracer FPs. Reported separately.
ssrf_sans = collections.defaultdict(set)
for p in (F("corpus_sbx_20260926", "runs.gpt41-corpus-sbx.jsonl"), F("recover_pc_20260926", "runs.gpt41-recover-pc.jsonl"),
          F("repo24_20260926", "runs.repo24.jsonl"), F("repo24_20260926", "runs.repo24-b.jsonl"),
          F("baselines", "tofu_runs_e2_20260922.jsonl")):
    for r in load(p):
        if not r.get("ok"):
            continue
        ran.add(r.get("repo"))
        c = g["classify"](r.get("triggered_sanitizers")) if r.get("finding_hits") else None
        if c and c[0] == "ssrf":
            ssrf_sans[(r.get("repo"), r.get("tool"), "ssrf")] |= set(r.get("triggered_sanitizers") or [])
backend_dial = {k for k in U if k[2] == "ssrf" and "check_introspection_ssrf" in ssrf_sans[k]
                and not any(x.startswith("check_url") for x in ssrf_sans[k])}

bugs = collections.defaultdict(set)
for repo, tool, cls in U:
    if repo in h2h:
        bugs[repo].add((tool, cls))

rows = []
for repo, h in h2h.items():
    v = vip.get(repo, {})
    b = bugs.get(repo, set())
    bx = {(t, c) for t, c in b if (repo, t, c) not in backend_dial}
    rows.append(dict(repo=repo, lang=h["lang"],
                     tofu_status="unsafe-skipped" if repo in unsafe else ("ran" if repo in ran else "not-run"),
                     tofu=len(b), tofu_tools=len({t for t, _ in b}), tofu_classes=sorted({c for _, c in b}),
                     tofu_x=len(bx), tofu_x_classes=sorted({c for _, c in bx}),
                     codeql=h.get("codeql"), cisco=h.get("cisco"),
                     v_static=v.get("static", 0), v_sink=v.get("sink_events", 0),
                     v_confirmed=v.get("distinct_chains", 0), v_confirmed_entries=v.get("confirmed", 0),
                     v_chains=v.get("chains", []), v_hook=v.get("hook")))
rows.sort(key=lambda r: (-r["tofu_x"], -r["tofu"], r["repo"].lower()))

n = lambda f: sum(1 for r in rows if f(r))
xstat = lambda r: r["tofu_x"] > 0
stat = lambda r: (r["codeql"] or 0) > 0 or (r["cisco"] or 0) > 0 or r["v_static"] > 0 or r["v_sink"] > 0 or r["v_confirmed"] > 0
tally = {
    "repos": len(rows), "tofu_ran": n(lambda r: r["tofu_status"] == "ran"),
    "tofu>0": n(lambda r: r["tofu"] > 0), "tofu_bugs_total": sum(r["tofu"] for r in rows),
    "tofu_tools_total": sum(r["tofu_tools"] for r in rows),
    "viper_static>0": n(lambda r: r["v_static"] > 0), "viper_static_total": sum(r["v_static"] for r in rows),
    "viper_sink>0": n(lambda r: r["v_sink"] > 0), "viper_confirmed>0": n(lambda r: r["v_confirmed"] > 0),
    "viper_confirmed_distinct": sum(r["v_confirmed"] for r in rows),
    "viper_any>0": n(lambda r: r["v_static"] > 0 or r["v_sink"] > 0 or r["v_confirmed"] > 0),
    "both(tofu&viper_static)": n(lambda r: r["tofu"] > 0 and r["v_static"] > 0),
    "tofu_only(vs viper_static)": n(lambda r: r["tofu"] > 0 and r["v_static"] == 0),
    "viper_static_only": n(lambda r: r["tofu"] == 0 and r["v_static"] > 0),
    "viper_sink_where_tofu0": [r["repo"] for r in rows if r["tofu"] == 0 and r["v_sink"] > 0],
    "tofu_exclusive(vs codeql+cisco+viper)": [r["repo"] for r in rows if r["tofu"] > 0 and not stat(r)],
    "no_tool_flags": [r["repo"] for r in rows if r["tofu"] == 0 and not stat(r)],
    "tofu_x>0": n(lambda r: r["tofu_x"] > 0), "tofu_x_bugs_total": sum(r["tofu_x"] for r in rows),
    "backend_dial_ssrf_in_h2h": sum(r["tofu"] - r["tofu_x"] for r in rows),
    "backend_dial_ssrf_in_648": len(backend_dial),
    "both_x(tofu_x&viper_static)": n(lambda r: r["tofu_x"] > 0 and r["v_static"] > 0),
    "tofu_x_only(vs viper_static)": n(lambda r: r["tofu_x"] > 0 and r["v_static"] == 0),
    "tofu_x_exclusive(vs codeql+cisco+viper)": [r["repo"] for r in rows if r["tofu_x"] > 0 and not stat(r)],
    "tofu_by_class": dict(collections.Counter(c for r in rows for c in [c for _, c in bugs.get(r["repo"], ())]).most_common()),
}
conf = [r for r in rows if r["v_confirmed"] > 0]
json.dump({"rows": rows, "tally": tally}, open(F("baselines", "h2h_tofu_vs_viper_20260926.json"), "w"), indent=1)

T = tally
md = [
 "# Head-to-head: ToFu vs Viper-MCP on the 45-repo H2H set (2026-09-26)", "",
 "Regenerated by `h2h_tofu_vs_viper_20260926.py`. **ToFu** = the consolidated headline set",
 "(RESULTS_SUMMARY §1a, `findings/union_20260926/analyze_union.py`: 648 bugs / 154 repos / 647 tools,",
 "all sandboxed campaigns, distinct repo×tool×class) restricted to the H2H repos. Unconfirmed candidates,",
 "no confidence tier. **Viper** = recounted from Viper's own output files (`viper_h2h_corrected_20260926.md`):",
 "static = Phase I CodeQL taint flows; sink hits = Phase II hook observations (excl. `hook_init`);",
 "confirmed = distinct vulns with a Viper hit-judge verdict (`sink_reached && effect_success`).", "",
 f"> **Instrument caveat (2026-09-26):** {T['backend_dial_ssrf_in_648']} of the 648 (all SSRF) rest ONLY on",
 "> `check_introspection_ssrf`, which fires on any loopback/private connect without checking the host came",
 "> from input. All 47 of those with a surviving log show one fixed host:port per repo = the server's own",
 "> default backend (meilisearch 127.0.0.1:7700, freecad 9875, dolphinscheduler 12345, trino 8080, boto3 IMDS",
 "> 169.254.169.254). Likely tracer FPs; the **ToFu (excl. backend-dial)** column drops them. On this set:",
 f"> {T['backend_dial_ssrf_in_h2h']} of {T['tofu_bugs_total']}. Not yet reflected in RESULTS_SUMMARY §1a.", "",
 "> Units differ: ToFu and Viper-static are *candidate* counts (runtime oracle vs static taint);",
 f"> Viper-confirmed is a judged-exploit count. Compare at repo level; never add them.", "",
 "## Summary",
 "| | repos flagged (of 45) | count |", "|---|---|---|",
 f"| **ToFu** (runtime candidates) | **{T['tofu>0']}** | {T['tofu_bugs_total']} bugs on {T['tofu_tools_total']} tools |",
 f"| ToFu excl. backend-dial SSRF | {T['tofu_x>0']} | {T['tofu_x_bugs_total']} bugs |",
 f"| Viper static (Phase I taint flows) | {T['viper_static>0']} | {T['viper_static_total']} flows |",
 f"| Viper runtime sink hits (Phase II) | {T['viper_sink>0']} | |",
 f"| Viper confirmed (hit judge) | {T['viper_confirmed>0']} | {T['viper_confirmed_distinct']} distinct vulns |",
 f"| Viper, any signal | {T['viper_any>0']} | |", "",
 f"- **Overlap:** {T['both(tofu&viper_static)']} of {T['viper_static>0']} Viper-static repos are also ToFu-flagged; "
 f"Viper-static-only = {T['viper_static_only']}. ToFu flags {T['tofu_only(vs viper_static)']} repos Viper's static stage misses "
 f"({T['tofu_x_only(vs viper_static)']} excl. backend-dial).",
 "- **Viper-confirmed bugs vs ToFu:** " + "; ".join(
     f"{r['repo']} ({', '.join(r['v_chains'])}; ToFu: {', '.join(r['tofu_classes']) or 'none'})" for r in conf) + ".",
 "- **Viper runtime hits where ToFu reports 0:** " + (", ".join(
     f"{r['repo']} ({r['v_sink']}{', unsafe-skipped' if r['tofu_status'] == 'unsafe-skipped' else ''})"
     for r in rows if r["repo"] in T["viper_sink_where_tofu0"]) or "none")
     + " — sink observations, not confirmed exploits; worth a manual look.",
 f"- **ToFu-exclusive** (no CodeQL / Cisco / Viper signal): {len(T['tofu_exclusive(vs codeql+cisco+viper)'])} repos — "
 + ", ".join(T["tofu_exclusive(vs codeql+cisco+viper)"]) + ". "
 f"Excl. backend-dial: {len(T['tofu_x_exclusive(vs codeql+cisco+viper)'])} (drops "
 + ", ".join(sorted(set(T["tofu_exclusive(vs codeql+cisco+viper)"]) - set(T["tofu_x_exclusive(vs codeql+cisco+viper)"]))) + ").",
 f"- **No tool flags anything:** {len(T['no_tool_flags'])} repos.",
 f"- ToFu covered {T['tofu_ran']}/45 (" + ", ".join(r["repo"] for r in rows if r["tofu_status"] != "ran")
 + " on the unsafe-skip list).",
 "- ToFu classes on this set: " + ", ".join(f"{c} {k}" for c, k in T["tofu_by_class"].items()) + ".",
 "- Viper models 3 classes (command injection, path traversal, SSRF); ToFu's reflected-xss / log-injection /",
 "  data-exfiltration candidates have no Viper counterpart by design — part of why ToFu-only is large.", "",
 "## Per repo",
 "| repo | lang | ToFu bugs | ToFu excl. backend-dial | ToFu classes | CodeQL | Cisco | Viper static | Viper sink hits | Viper confirmed |",
 "|---|---|---|---|---|---|---|---|---|---|",
]
for r in rows:
    t = f"**{r['tofu']}**" if r["tofu"] else ("0 (unsafe-skipped)" if r["tofu_status"] == "unsafe-skipped" else "0")
    vc = (f"**{r['v_confirmed']}** ({'; '.join(r['v_chains'])}; {r['v_confirmed_entries']} verdict(s))"
          if r["v_confirmed"] else "0")
    md.append(f"| {r['repo']} | {r['lang']} | {t} | {r['tofu_x']} | {', '.join(r['tofu_classes']) or '–'} | {r['codeql']} | "
              f"{r['cisco']} | {r['v_static']} | {r['v_sink']} | {vc} |")
md += ["", "Sources: ToFu `findings/union_20260926/analyze_union.py` (committed indices); Viper VM + PC",
       "`eval/viper_runs/` (recount in `viper_h2h_corrected_20260926.json`); CodeQL/Cisco",
       "`head_to_head_per_repo_20260922.json` (static tools, unchanged, not re-run)."]
open(F("baselines", "h2h_tofu_vs_viper_20260926.md"), "w").write("\n".join(md) + "\n")
print(json.dumps({k: v for k, v in T.items() if not isinstance(v, list)}, indent=0))
print("tofu-exclusive:", len(T["tofu_exclusive(vs codeql+cisco+viper)"]), "| no flags:", len(T["no_tool_flags"]))
