#!/usr/bin/env python3
"""ToolFuzz over the H2H-273 dynamic set (266 repos; VM + merged PSU H2H run, 2026-09-28) vs ToFu's 508.
Regenerates findings/toolfuzz_h2h273_20260928/{REPORT.md,per_repo.json,per_tool.json}. Run from the repo root:
  python3 findings/toolfuzz_h2h273_20260928/analyze_toolfuzz_273.py

Inputs (all committed here):
  runs.toolfuzz_h2h273.jsonl  ToolFuzz index, one row per (repo, tool) attempt (VM eval/state/toolfuzz_runs.jsonl;
                              296 rows carry merged_from=psu-h2h-20260925: same config, run on the PSU PC)
  raw.tar.gz -> raw/<slug>/<tool>.{runtime,correctness}.json   ToolFuzz's own per-tool result files
  llm_calls_vm.json           cross-process real-call counter of the VM run
Tool universe: Benchmarks/extraction/tofu_exec_index_273.jsonl (every tool ToFu executed successfully).
ToolFuzz outcomes are counted with ToolFuzz's own criteria and classified by eval/score_toolfuzz.py
(HARNESS / ENV / REJECT / CRASH / UNCLASS). ToFu = the 508 paper headline, loaded exactly as
findings/viper_c251_20260928/analyze_viper_c251.py does.
"""
import json, os, runpy, collections, contextlib, io, importlib.util
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
P = lambda *p: os.path.join(HERE, *p)
X = lambda f: [l.strip() for l in open(os.path.join(ROOT, "Benchmarks", "extraction", f)) if l.strip() and not l.startswith("#")]

REPOS = X("h2h_273_dynamic_repos.txt")
R273 = set(X("h2h_273_repos.txt")); EXCL = sorted(R273 - set(REPOS))
exe = collections.defaultdict(set)
for r in map(json.loads, open(os.path.join(ROOT, "Benchmarks", "extraction", "tofu_exec_index_273.jsonl"))):
    exe[r["repo"]].add(r["tool"])

sp = importlib.util.spec_from_file_location("score", os.path.join(ROOT, "eval", "score_toolfuzz.py"))
S = importlib.util.module_from_spec(sp); sp.loader.exec_module(S)
S.OUT = P("raw")
if not os.path.isdir(S.OUT) and os.path.exists(P("raw.tar.gz")):   # raw results ship compressed
    import tarfile; tarfile.open(P("raw.tar.gz")).extractall(HERE)

last = {}
for l in open(P("runs.toolfuzz_h2h273.jsonl")):
    if l.strip():
        r = json.loads(l); last[(r["repo"], r["tool"])] = r
load_err = {r["repo"]: (r.get("error") or "")[:120] for (repo, tool), r in last.items() if tool == "*" and not r.get("ok")}

cwd = os.getcwd(); os.chdir(ROOT)
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(ROOT, "findings", "baselines", "h2h_tofu_vs_viper_20260926.py"))
os.chdir(cwd)
TOFU = g["U"] - g["backend_dial"]
assert len(TOFU) == 508, f"ToFu set is {len(TOFU)}, expected the 508 headline"
tofu = collections.defaultdict(set)
for repo, tool, cls in TOFU:
    tofu[repo].add((tool, cls))


def err_kind(r):
    e = (r.get("error") or "")
    if r.get("final") and "exceeded" in e: return "timeout (600 s)"
    if "load_tools" in e: return "MCP bridge could not load server"
    return "ToolFuzz internal error"


tools, classes, crash_list = [], collections.Counter(), []
for repo in REPOS:
    for tool in sorted(exe.get(repo, ())):
        r = last.get((repo, tool))
        t = dict(repo=repo, tool=tool, tofu_bugs=sorted(c for tl, c in tofu.get(repo, ()) if tl == tool))
        if r is None:
            t["status"] = "not run (server not loadable)" if repo in load_err else "not run"
        elif not r.get("ok"):
            t["status"] = err_kind(r); t["error"] = (r.get("error") or "")[:120]
        else:
            s = S.score_tool(repo.replace("/", "__"), tool)
            classes.update(s["classes"])
            t.update(status="ok", merged=bool(r.get("merged_from")), llm_calls=r.get("llm_calls"),
                     prompt_tokens=r.get("prompt_tokens"), completion_tokens=r.get("completion_tokens"),
                     rt_tests=s["rt_tests"], tf_runtime=s["tf_runtime"], tf_crash=s["tf_crash"],
                     tf_correct_formula=s["tf_correct"], tf_correct_exec=s["tf_correct_exec"],
                     ct_sets=s["ct_sets"], crash_msgs=sorted(s["crash_msgs"]),
                     crash_kinds=dict(s.get("crash_kinds", {})))
            crash_list += [(repo, tool, m) for m in s["crash_msgs"]]
        tools.append(t)
json.dump(tools, open(P("per_tool.json"), "w"), indent=1)

ok = [t for t in tools if t["status"] == "ok"]
by_repo = collections.defaultdict(list)
for t in tools: by_repo[t["repo"]].append(t)
rows = []
for repo in REPOS:
    ts = by_repo.get(repo, []); oks = [t for t in ts if t["status"] == "ok"]
    rows.append(dict(repo=repo, tools_executed=len(ts), toolfuzz_ok=len(oks),
                     tf_runtime_tools=sum(1 for t in oks if t["tf_runtime"]), tf_crash_tools=sum(1 for t in oks if t["tf_crash"]),
                     tf_correct_formula_tools=sum(1 for t in oks if t["tf_correct_formula"]),
                     tf_correct_exec_tools=sum(1 for t in oks if t["tf_correct_exec"]),
                     tofu=len(tofu.get(repo, ())), tofu_classes=sorted({c for _, c in tofu.get(repo, ())}),
                     load_error=load_err.get(repo)))
json.dump(rows, open(P("per_repo.json"), "w"), indent=1)

n = lambda f, rs=rows: sum(1 for x in rs if f(x))
st = collections.Counter(t["status"] for t in tools)
tofu_tools = {(t["repo"], t["tool"]) for t in ok if t["tofu_bugs"]}
tf_any = {(t["repo"], t["tool"]) for t in ok if t["tf_runtime"] or t["tf_correct_exec"]}
tf_crash = {(t["repo"], t["tool"]) for t in ok if t["tf_crash"]}
calls = sorted(t["llm_calls"] for t in ok if t.get("llm_calls") is not None)
vm = json.load(open(P("llm_calls_vm.json")))
merged = [t for t in ok if t.get("merged")]
psu_calls = sum(t.get("llm_calls") or 0 for t in merged)
psu_in = sum(t.get("prompt_tokens") or 0 for t in merged); psu_out = sum(t.get("completion_tokens") or 0 for t in merged)
tofu_on_ok = sum(len(t["tofu_bugs"]) for t in ok)
tofu_on_set = sum(len(tofu.get(r, ())) for r in REPOS)

L = ["# ToolFuzz on the H2H-273 dynamic set vs ToFu (2026-09-28)", "",
     f"**Set:** `Benchmarks/extraction/h2h_273_dynamic_repos.txt` ({len(REPOS)} repos = the H2H-273 minus the "
     f"{len(EXCL)} unsafe host-control servers). **Tools:** the {sum(len(v) for v in exe.values())} tools ToFu executed "
     f"successfully on them (`tofu_exec_index_273.jsonl`). ToolFuzz is given exactly these tools.", "",
     "> Units differ. ToFu bugs are runtime silent-bug candidates (distinct repo×tool×class, the 508 headline).",
     "> ToolFuzz reports test outcomes, counted with ToolFuzz's own criteria (its `tool_stats.py`): a *runtime",
     "> failure* is an agent prompt that drove the tool into an error; a *correctness failure* needs argument AND",
     "> output inconsistency across paraphrases AND an LLM-judge score ≤ 5/10. ToolFuzz targets tool-documentation",
     "> errors, not security (Milev et al. 2025). Compare per tool, per axis — never one summed count.", "",
     "## Coverage", "",
     "| status | tools |", "|---|---|"] + [f"| {k} | {v} |" for k, v in st.most_common()] + ["",
     f"ToolFuzz completed **{len(ok)} / {len(tools)} tools** ({100*len(ok)/len(tools):.1f}%) in "
     f"{n(lambda x: x['toolfuzz_ok'] > 0)} / {len(REPOS)} repos; {len(merged)} of them are merged from the "
     f"PSU H2H run (identical configuration). Repos ToolFuzz could not load at all: "
     f"{', '.join(f'`{r}`' for r in sorted(load_err)) or 'none'}.", "",
     "## Runtime failures by class (all triggers, before per-tool dedup)", "",
     "| class | triggers | meaning |", "|---|---|---|",
     f"| HARNESS | {classes.get('HARNESS', 0)} | ToolFuzz / MCP-bridge error (non-ToolException or disconnect), not the tool |",
     f"| ENV | {classes.get('ENV', 0)} | upstream service / credential / host app unavailable |",
     f"| REJECT | {classes.get('REJECT', 0)} | the tool correctly refused the input |",
     f"| CRASH | {classes.get('CRASH', 0)} | unhandled internal error leaking out (robustness bug) |",
     f"| UNCLASS | {classes.get('UNCLASS', 0)} | cause not evident from the text; not counted |", "",
     "## Headline (tools ToolFuzz completed)", "",
     "| | tools | repos |", "|---|---|---|",
     f"| ToolFuzz runtime failure, its own definition (HARNESS removed; incl. ENV/REJECT) | {sum(1 for t in ok if t['tf_runtime'])} | {n(lambda x: x['tf_runtime_tools'] > 0)} |",
     f"| ToolFuzz genuine crash (CRASH class) | **{len(tf_crash)}** | **{n(lambda x: x['tf_crash_tools'] > 0)}** |",
     f"| ToolFuzz correctness failure, code formula | {sum(1 for t in ok if t['tf_correct_formula'])} | {n(lambda x: x['tf_correct_formula_tools'] > 0)} |",
     f"| ToolFuzz correctness failure, tool actually executed | **{sum(1 for t in ok if t['tf_correct_exec'])}** | **{n(lambda x: x['tf_correct_exec_tools'] > 0)}** |",
     f"| **ToFu (508 headline) bugs on these tools** | **{len(tofu_tools)}** ({tofu_on_ok} bugs) | **{len({r for r, _ in tofu_tools})}** |", "",
     f"ToFu has {tofu_on_set} of its 508 bugs on these {len(REPOS)} repos; {tofu_on_ok} sit on tools ToolFuzz completed. "
     f"The {len(EXCL)} excluded unsafe repos carry {sum(len(tofu.get(r, ())) for r in EXCL)} ToFu bugs.", "",
     "**Correctness, formula vs executed:** ToolFuzz stores a tool that throws during a correctness prompt as output",
     "`Tool FAILURE` with judge score 0, so its code formula counts tool errors as correctness failures. The paper",
     "defines correctness failures as incorrect results; the executed-only row keeps only runs where the tool returned",
     "a real (non-error) output.", "",
     "## Overlap on the same tools", "",
     f"- ToFu-flagged tools that ToolFuzz flagged for anything (runtime own-def or executed correctness): "
     f"**{len(tofu_tools & tf_any)} / {len(tofu_tools)}**; as a genuine crash: **{len(tofu_tools & tf_crash)}**.",
     f"- ToolFuzz crash tools that ToFu also flags: {len(tf_crash & tofu_tools)} / {len(tf_crash)}; ToFu's class on them: "
     + ", ".join(f"{c} {v}" for c, v in collections.Counter(c for t in ok if t["tf_crash"] for c in t["tofu_bugs"]).most_common()) + ".",
     f"- ToFu-only tools (ToFu bug, ToolFuzz nothing): {len(tofu_tools - tf_any)}.", "",
     "## ToolFuzz genuine crashes (for manual confirmation)", "",
     "Crash tools by kind: " + "; ".join(f"{k}: {v}" for k, v in collections.Counter(
         (max(t["crash_kinds"], key=t["crash_kinds"].get) if t.get("crash_kinds") else "other") for t in ok if t["tf_crash"]).most_common()) + ".", ""] + \
    [f"- `{r}::{t}` — {m[:170]}" + (f"  *(ToFu: {', '.join(c for tl, c in sorted(tofu.get(r, ())) if tl == t)})*" if any(tl == t for tl, _ in tofu.get(r, ())) else "")
     for r, t, m in sorted(crash_list)] + ["",
     "## Cost", "",
     f"- ToolFuzz real LLM calls: VM run **{vm['calls']:,}** (tokens {vm['prompt_tokens']:,} in / {vm['completion_tokens']:,} out, "
     f"{vm.get('cache_hits', 0):,} cache hits) + merged PSU tools **{psu_calls:,}** ({psu_in:,} in / {psu_out:,} out).",
     f"- Per completed tool: median {calls[len(calls)//2]}, max {calls[-1]} calls (cap 40, never hit).",
     "- ToFu: 2 LLM steps per tool at initialisation (sanitizer selection + seeds), none while fuzzing.", "",
     "## Configuration (recorded in every index row)", "",
     "gpt-4.1-mini for every ToolFuzz LLM role (the authors used GPT-4o / GPT-4o-mini); 10 direct fuzz iterations;",
     "≤ 3 failing inputs per error type, 1 agent prompt each; 1 correctness prompt set × 3 paraphrases; cap 40 calls",
     "per tool; 600 s per tool; every target server in bwrap (filesystem read-only except its scratch + own dir,",
     "own PID/IPC namespace). Two ToolFuzz bugs fixed (`PATCH (ToFu)`: literal braces in templates, array schema",
     "without `items`), plus two harness artefacts (pydantic error recorded as a trigger; results appended across retries).", "",
     "## Caveats for the paper", "",
     "- **ToolFuzz's own correctness FDR is 46%** (Milev et al. 2025, Table 3: authors hand-checked every positive).",
     "- The paper's \"runtime detection has no false positives\" holds for LangChain tools, where an error is a crash;",
     "  MCP servers return errors as protocol replies, hence the ENV / REJECT / CRASH split above.",
     "- ToolFuzz's taint-guided argument generation is in-process Python only; over MCP the server is a separate",
     "  process, so it degrades to type-based Faker values.",
     "- Budget-capped configuration (above) to keep cost small; ToFu's arm used gpt-4.1.",
     f"- Not tested: {len(EXCL)} unsafe repos by design ({', '.join(EXCL)}); servers ToolFuzz's MCP bridge could not load; "
     f"{st.get('timeout (600 s)', 0)} timeouts; {st.get('ToolFuzz internal error', 0)} ToolFuzz internal errors.", ""]
open(P("REPORT.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L[:60]))
