#!/usr/bin/env python3
"""Cisco MCP Scanner (yara + llm + behavioral) on the H2H-273 set (campaign c273, 2026-09-29) vs ToFu.
Regenerates findings/cisco_c273_20260929/{REPORT.md,per_repo.json}. Run from the repo root:
  python3 findings/cisco_c273_20260929/analyze_cisco_c273.py

Inputs (committed here):
  runs.c273.jsonl          one row per repo (VM eval/state/cisco_runs.c273.jsonl)
  raw_outputs.c273.tgz     per-repo scanner JSON (yara+llm, stdio) and <slug>.behavioral.json
  llm_ledger_summary.json  measured LLM traffic (record/replay cache ledger)
ToFu = the 508 paper headline (analyze_union U minus the backend-dial SSRF set, as computed by
       findings/baselines/h2h_tofu_vs_viper_20260926.py). Old YARA-only column =
       findings/baselines/cisco_runs_h2h_20260921.jsonl.
"""
import json, os, runpy, collections, contextlib, io, tarfile, tempfile, glob
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
P = lambda *p: os.path.join(HERE, *p)
X = lambda f: [l.strip() for l in open(os.path.join(ROOT, "Benchmarks", "extraction", f)) if l.strip() and not l.startswith("#")]
REPOS = X("h2h_273_repos.txt")
UNSAFE = set(REPOS) - set(X("h2h_273_dynamic_repos.txt"))

last = {}
for l in open(P("runs.c273.jsonl")):
    if l.strip():
        r = json.loads(l); last[r["repo"]] = r
ledger = json.load(open(P("llm_ledger_summary.json")))

# per-tool analyzer verdicts from the raw outputs
yl = collections.defaultdict(lambda: {"yara": set(), "llm": set()})
beh = {}
with tempfile.TemporaryDirectory() as d:
    tarfile.open(P("raw_outputs.c273.tgz")).extractall(d)
    for f in glob.glob(os.path.join(d, "c273", "*.json")):
        slug = os.path.basename(f)[:-5]
        if slug.endswith(".behavioral"):
            beh[slug[:-11]] = json.load(open(f)); continue
        try: data = json.load(open(f))
        except Exception: continue
        for t in (data.get("scan_results") or []) if isinstance(data, dict) else []:
            for an, key in (("yara_analyzer", "yara"), ("llm_analyzer", "llm")):
                v = (t.get("findings") or {}).get(an) or {}
                if int(v.get("total_findings") or 0) > 0:
                    yl[slug][key].add(t.get("tool_name"))

cwd = os.getcwd(); os.chdir(ROOT)
with contextlib.redirect_stdout(io.StringIO()):            # side effect: rewrites the 09-26 H2H files identically
    g = runpy.run_path(os.path.join(ROOT, "findings", "baselines", "h2h_tofu_vs_viper_20260926.py"))
os.chdir(cwd)
TOFU = g["U"] - g["backend_dial"]
assert len(TOFU) == 508, f"ToFu set is {len(TOFU)}, expected the 508 headline"
tofu = collections.defaultdict(set)
for repo, tool, cls in TOFU:
    tofu[repo].add((tool, cls))
old = {}
for l in open(os.path.join(ROOT, "findings", "baselines", "cisco_runs_h2h_20260921.jsonl")):
    r = json.loads(l)
    if r.get("analyzers") == ["yara"] and r.get("ok"): old[r["repo"]] = r

rows = []
for repo in REPOS:
    slug = repo.replace("/", "__"); r = last.get(repo, {}); b = beh.get(slug) or {}
    brows = b.get("rows") or []
    flag = [x for x in brows if (x.get("severity") or "").upper() not in ("SAFE", "", "UNKNOWN", "INFO")]
    bv = sorted({x["function_name"] for x in flag if x.get("classification") == "VULNERABILITY"})
    bt = sorted({x["function_name"] for x in flag if x.get("classification") == "THREAT"})
    t = tofu.get(repo, set()); ttools = {tl for tl, _ in t}
    ytools, ltools = sorted(yl[slug]["yara"]), sorted(yl[slug]["llm"])
    rows.append(dict(
        repo=repo, unsafe_list=repo in UNSAFE, ok=bool(r.get("ok")), error=(r.get("error") or "")[:90] or None,
        n_tools=r.get("n_tools_scanned"), yara_tools=ytools, llm_tools=ltools,
        beh_functions=b.get("n_analyzed_functions") or 0, beh_rows=len(brows),
        beh_inconclusive=sum(1 for x in brows if (x.get("severity") or "").upper() == "UNKNOWN"),
        beh_vuln_tools=bv, beh_threat_tools=bt,
        beh_flag_detail=[{"fn": x.get("function_name"), "sev": x.get("severity"), "class": x.get("classification"),
                          "summary": (x.get("summary") or "")[:220]} for x in flag],
        old_yara_flagged=(old.get(repo) or {}).get("n_tools_flagged"),
        tofu=len(t), tofu_classes=sorted({c for _, c in t}),
        tofu_same_tool=sorted(ttools & (set(ytools) | set(ltools) | set(bv) | set(bt))),
        seconds=r.get("seconds")))
json.dump(rows, open(P("per_repo.json"), "w"), indent=1)

ok = [x for x in rows if x["ok"]]
n = lambda f, s=rows: sum(1 for x in s if f(x))
Y = lambda x: bool(x["yara_tools"]); L = lambda x: bool(x["llm_tools"])
BV = lambda x: bool(x["beh_vuln_tools"]); BT = lambda x: bool(x["beh_threat_tools"]); B = lambda x: BV(x) or BT(x)
ANY = lambda x: Y(x) or L(x) or B(x)
T = lambda x: x["tofu"] > 0
pt, ct = ledger["prompt_tokens"], ledger["completion_tokens"]
inc, tot = sum(x["beh_inconclusive"] for x in ok), sum(x["beh_rows"] for x in ok)
md = [
 "# Cisco MCP Scanner (yara + llm + behavioral) on the H2H-273 set (campaign c273, 2026-09-29)", "",
 "Regenerated by `analyze_cisco_c273.py` from the committed files in this directory.",
 f"**Set:** `Benchmarks/extraction/h2h_273_repos.txt` ({len(REPOS)}), incl. the 7 unsafe-list repos: Cisco only",
 "lists tools and reads source, it never invokes a tool.",
 "**Configuration:** Cisco mcp-scanner v4.8.4 @ 16e684d; analyzers `yara`, `llm` (tool-description LLM judge)",
 "and `behavioral` (source-code dataflow + docstring/behaviour alignment); **all LLM roles gpt-4.1-mini**",
 "(Ananto's choice, for cost). `api` (Cisco AI Defense cloud) not run: the key returned 401 on every region",
 "(nazmul.todo item 27). Each repo in its own bubblewrap sandbox with a throwaway target copy.",
 "**Behavioral is run via `eval/cisco_behavioral.py`**, not the CLI: in `stdio` mode the scanner never",
 "reads source (placeholder SAFE rows), and the `behavioral` subcommand drops VULNERABILITY findings.",
 f"**ToFu** = the 508 headline restricted to the 273: {sum(x['tofu'] for x in rows)} bugs in {n(T)} repos.", "",
 "> Units differ: Cisco flags are unconfirmed static / LLM verdicts per tool; ToFu bugs are runtime",
 "> candidates (repo×tool×class). Compare at repo / tool level; never add them.", "",
 "## Run health",
 f"- **{len(ok)}/{len(REPOS)} ok**; failed: " + "; ".join(f"{x['repo']} ({x['error']})" for x in rows if not x["ok"]) + ".",
 f"- Behavioral: **{inc:,} of {tot:,} function checks inconclusive ({100 * inc / max(tot, 1):.0f}%)**: gpt-4.1-mini",
 "  drops the `summary` field Cisco's batch validator requires, so those functions are never judged",
 "  (smoke: tmux-mcp 21-26/32 inconclusive on gpt-4.1-mini; gpt-4.1 flagged its `execute-command`).",
 "  Behavioral counts below are therefore a LOWER BOUND.",
 f"- Behavioral found 0 functions on {n(lambda x: x['ok'] and not x['beh_functions'])} ok repos (its extractor",
 "  misses some tool registrations; e.g. memory-bank-mcp: 8 functions for 15 tools).",
 f"- LLM traffic (measured): {ledger['calls']:,} calls, {ledger['replayed_from_cache']:,} replayed, "
 f"{ledger['upstream']:,} upstream (status {ledger['upstream_status']}); {pt:,} prompt / {ct:,} completion tokens.",
 f"  At gpt-4.1-mini list price ($0.40/M in, $1.60/M out -- not verified against the invoice) ≈ ${pt * 0.4e-6 + ct * 1.6e-6:,.2f}.", "",
 "## Headline (repos of 273)",
 "| analyzer | repos flagged | tools flagged | shared with ToFu (repos) |", "|---|---|---|---|",
 f"| yara | {n(Y)} | {sum(len(x['yara_tools']) for x in rows)} | {n(lambda x: Y(x) and T(x))} |",
 f"| llm (tool descriptions) | {n(L)} | {sum(len(x['llm_tools']) for x in rows)} | {n(lambda x: L(x) and T(x))} |",
 f"| behavioral VULNERABILITY | {n(BV)} | {sum(len(x['beh_vuln_tools']) for x in rows)} | {n(lambda x: BV(x) and T(x))} |",
 f"| behavioral THREAT | {n(BT)} | {sum(len(x['beh_threat_tools']) for x in rows)} | {n(lambda x: BT(x) and T(x))} |",
 f"| **any Cisco analyzer** | **{n(ANY)}** | | **{n(lambda x: ANY(x) and T(x))}** |", "",
 f"- vs the earlier YARA-only run (09-21, same 273): {n(lambda x: (x['old_yara_flagged'] or 0) > 0)} repos flagged.",
 f"- Repo overlap with ToFu (any analyzer): both {n(lambda x: ANY(x) and T(x))}, ToFu-only {n(lambda x: T(x) and not ANY(x))}, "
 f"Cisco-only {n(lambda x: ANY(x) and not T(x))}.",
 f"- Same tool flagged by Cisco and ToFu: {sum(len(x['tofu_same_tool']) for x in rows)} tools in {n(lambda x: x['tofu_same_tool'])} repos.",
 f"- Cisco's LLM/behavioral layers add {n(lambda x: (L(x) or B(x)) and not Y(x))} repos YARA alone does not flag.", "",
 "## Behavioral findings per repo",
 "| repo | VULNERABILITY tools | THREAT tools | flagged rows | ToFu bugs |", "|---|---|---|---|---|",
 *[f"| {x['repo']} | {len(x['beh_vuln_tools'])} | {len(x['beh_threat_tools'])} | {len(x['beh_flag_detail'])} | {x['tofu']} |"
   for x in sorted([x for x in rows if B(x)], key=lambda x: -len(x["beh_flag_detail"]))],
 "",
 f"- **Concentration:** {max((len(x['beh_flag_detail']) for x in rows), default=0)} of "
 f"{sum(len(x['beh_flag_detail']) for x in rows)} flagged behavioral rows come from one repo "
 f"({max(rows, key=lambda x: len(x['beh_flag_detail']))['repo']}); repo counts are the robust unit.",
 "- **Checked against source (2026-09-29, mcp-sitecore-server):** two behavioral claims are NOT in the code --",
 "  `common-get-item-field` \"writes an attacker's SSH public key to ~/.ssh\" (no `.ssh`/`authorized_keys` anywhere",
 "  outside node_modules/dist) and `security-new-role` \"reads /etc/passwd\" (`/etc/passwd` occurs only in",
 "  tests/unit/media.test.ts). Those are LLM fabrications on undocumented functions. The PowerShell-injection",
 "  claims are plausible (the server builds PowerShell from parameters via runGenericPowershellCommand, 85 uses)",
 "  but this is a remote-administration server by design. Treat behavioral flags as unverified leads.", "",
 "## Behavioral VULNERABILITY / THREAT findings (Cisco's own summary text; not hand-verified)",
 "| repo | class | function | severity | summary | ToFu on repo |", "|---|---|---|---|---|---|",
]
for x in sorted([x for x in rows if B(x)], key=lambda x: x["repo"].lower()):
    for f in x["beh_flag_detail"]:
        summ = " ".join(f["summary"].replace("|", "/").split())[:160]
        md.append(f"| {x['repo']} | {f['class']} | {f['fn']} | {f['sev']} | {summ} | "
                  f"{x['tofu']} ({', '.join(x['tofu_classes']) or '–'}) |")
md += ["",
 "## Open",
 "- Behavioral recall is limited by the model choice (55% of checks inconclusive on gpt-4.1-mini). A gpt-4.1",
 "  re-run of behavioral only (CISCO_BEHAVIORAL_MODEL=openai/gpt-4.1) would lift it; the cache replays the",
 "  llm-analyzer calls for free.",
 "- `api` analyzer pending a working Cisco AI Defense inspection key.",
 "- Hand-check the behavioral findings before quoting them as vulnerabilities.", "",
 "Files: `runs.c273.jsonl`, `per_repo.json` (all 273, tool lists per analyzer + ToFu), `raw_outputs.c273.tgz`,",
 "`llm_ledger_summary.json`. Raw: VM `~/toolfuzzer/eval/cisco_runs/c273/`.",
]
open(P("REPORT.md"), "w").write("\n".join(md) + "\n")
print("\n".join(md[md.index("## Headline (repos of 273)"):md.index("## Behavioral VULNERABILITY / THREAT findings (Cisco's own summary text; not hand-verified)")]))
