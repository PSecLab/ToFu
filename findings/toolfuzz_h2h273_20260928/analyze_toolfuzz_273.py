#!/usr/bin/env python3
"""ToolFuzz over the H2H-273 dynamic set (266 repos; VM + merged PSU H2H run, 2026-09-28).
Reports ONLY what ToolFuzz is designed to report, counted the way ToolFuzz counts it
(Milev et al. 2025, §4.1-4.2, Tables 1-3; its evaluation code src/eval/toolfuzz/utils/tool_stats.py):

  runtime failure     an agent query during which the tool raised a runtime error = an "erroneous
                      prompt" (TestFailureResult.successful_trigger). Reported as erroneous prompts,
                      tested prompts, unique errors, vulnerable tools.
  correctness failure an individual prompt of a synonymous prompt set where all checks fail:
                      tool_arguments_inconsistency AND tool_output_inconsistency AND the LLM oracle's
                      score <= 5 (tool_stats.py, verbatim). Reported as erroneous prompts / total prompts.
                      The paper's TP/FP split needs manual inspection, which this run does not have.

Only exclusion: a trigger whose exception was raised by ToolFuzz's own code rather than by the tool
(any exception class other than ToolException -- every tool error reaches ToolFuzz as ToolException,
see make_sync in eval/run_toolfuzz.py). That is not a tool execution error under the paper's definition.

Comparison side (context only): ToFu = the 508 paper headline, loaded exactly as
findings/viper_c251_20260928/analyze_viper_c251.py does.

Regenerates REPORT.md, per_repo.json, per_tool.json here. Run from the repo root:
  python3 findings/toolfuzz_h2h273_20260928/analyze_toolfuzz_273.py
"""
import json, os, re, runpy, collections, contextlib, io, tarfile
HERE = os.path.dirname(os.path.abspath(__file__)); ROOT = os.path.dirname(os.path.dirname(HERE))
P = lambda *p: os.path.join(HERE, *p)
X = lambda f: [l.strip() for l in open(os.path.join(ROOT, "Benchmarks", "extraction", f)) if l.strip() and not l.startswith("#")]
RAW = P("raw")
if not os.path.isdir(RAW) and os.path.exists(P("raw.tar.gz")):       # raw results ship compressed
    tarfile.open(P("raw.tar.gz")).extractall(HERE)

REPOS = X("h2h_273_dynamic_repos.txt")
R273 = set(X("h2h_273_repos.txt")); EXCL = sorted(R273 - set(REPOS))
exe = collections.defaultdict(set)
for r in map(json.loads, open(os.path.join(ROOT, "Benchmarks", "extraction", "tofu_exec_index_273.jsonl"))):
    exe[r["repo"]].add(r["tool"])
last = {}
for l in open(P("runs.toolfuzz_h2h273.jsonl")):
    if l.strip():
        r = json.loads(l); last[(r["repo"], r["tool"])] = r
load_err = {r["repo"] for (repo, tool), r in last.items() if tool == "*" and not r.get("ok")}

cwd = os.getcwd(); os.chdir(ROOT)
with contextlib.redirect_stdout(io.StringIO()):
    g = runpy.run_path(os.path.join(ROOT, "findings", "baselines", "h2h_tofu_vs_viper_20260926.py"))
os.chdir(cwd)
TOFU = g["U"] - g["backend_dial"]
assert len(TOFU) == 508, f"ToFu set is {len(TOFU)}, expected the 508 headline"
tofu = collections.defaultdict(set)
for repo, tool, cls in TOFU:
    tofu[repo].add((tool, cls))

TOOLEXC = "<class 'langchain_core.tools.base.ToolException'>"
norm = lambda m: re.sub(r"[0-9a-f]{8,}|\d+", "N", (m or "").strip())[:160]
truthy = lambda v: v is True or v == "True"


def load(path):
    try:
        return json.load(open(path))
    except Exception:
        return []


def score(repo, tool):
    base = os.path.join(RAW, repo.replace("/", "__"), tool.replace("/", "_"))
    rt = load(base + ".runtime.json"); ct = load(base + ".correctness.json")
    s = dict(rt_tested=len(rt), rt_erroneous=0, rt_toolfuzz_internal=0, ct_sets=len(ct), ct_prompts=0, ct_erroneous=0)
    errs = set()
    for t in rt:
        if not truthy(t.get("successful_trigger")):
            continue
        m = t.get("exception") or ""
        if m.startswith("<class '") and not m.startswith(TOOLEXC):
            s["rt_toolfuzz_internal"] += 1; continue
        s["rt_erroneous"] += 1; errs.add(norm(m))
    for st in ct:                                   # tool_stats.py, verbatim criterion
        runs = st.get("individual_run_test_results", [])
        s["ct_prompts"] += len(runs)
        if st.get("tool_arguments_inconsistency") and st.get("tool_output_inconsistency"):
            s["ct_erroneous"] += sum(1 for run in runs if run.get("unexpected_agent_output") is not None
                                     and run["unexpected_agent_output"] <= 5)
    s["rt_unique_errors"] = len(errs)
    return s


def status(repo, tool):
    r = last.get((repo, tool))
    if r is None: return "not run (server not loadable by ToolFuzz's MCP bridge)" if repo in load_err else "not run"
    if r.get("ok"): return "ok"
    if r.get("final") and "exceeded" in (r.get("error") or ""): return "timeout (600 s)"
    return "ToolFuzz error"


tools = []
for repo in REPOS:
    for tool in sorted(exe.get(repo, ())):
        t = dict(repo=repo, tool=tool, status=status(repo, tool),
                 tofu_bugs=sorted(c for tl, c in tofu.get(repo, ()) if tl == tool))
        if t["status"] == "ok":
            r = last[(repo, tool)]
            t.update(score(repo, tool), merged=bool(r.get("merged_from")), llm_calls=r.get("llm_calls"))
        tools.append(t)
json.dump(tools, open(P("per_tool.json"), "w"), indent=1)

ok = [t for t in tools if t["status"] == "ok"]
rows = []
for repo in REPOS:
    ts = [t for t in ok if t["repo"] == repo]
    rows.append(dict(repo=repo, tools_executed=len(exe.get(repo, ())), toolfuzz_tools=len(ts),
                     rt_erroneous_prompts=sum(t["rt_erroneous"] for t in ts),
                     rt_vulnerable_tools=sum(1 for t in ts if t["rt_erroneous"]),
                     ct_erroneous_prompts=sum(t["ct_erroneous"] for t in ts),
                     ct_faulty_tools=sum(1 for t in ts if t["ct_erroneous"]),
                     tofu=len(tofu.get(repo, ())), tofu_classes=sorted({c for _, c in tofu.get(repo, ())}),
                     not_loadable=repo in load_err))
json.dump(rows, open(P("per_repo.json"), "w"), indent=1)

sm = lambda k: sum(t[k] for t in ok)
nt = lambda f: sum(1 for t in ok if f(t))
nr = lambda f: len({t["repo"] for t in ok if f(t)})
rt_v = lambda t: t["rt_erroneous"] > 0
ct_v = lambda t: t["ct_erroneous"] > 0
st = collections.Counter(t["status"] for t in tools)
tofu_tools = {(t["repo"], t["tool"]) for t in ok if t["tofu_bugs"]}
tf_tools = {(t["repo"], t["tool"]) for t in ok if rt_v(t) or ct_v(t)}
vm = json.load(open(P("llm_calls_vm.json")))
merged = [t for t in ok if t.get("merged")]
calls = sorted(t["llm_calls"] for t in ok if t.get("llm_calls") is not None)

# --- verification: ToolFuzz's OWN counting functions (tool_stats.py), executed verbatim ---
import ast, tempfile
src = open(os.path.join(ROOT, "Benchmarks", "ToolFuzz", "src", "eval", "toolfuzz", "utils", "tool_stats.py")).read()
ns = {"json": json, "Counter": collections.Counter}
for node in ast.parse(src).body:
    if isinstance(node, ast.FunctionDef) and node.name in ("failure_stats", "correctness_stats"):
        exec(compile(ast.Module([node], []), "tool_stats.py", "exec"), ns)
allrt, allct = [], []
for t in ok:
    b = os.path.join(RAW, t["repo"].replace("/", "__"), t["tool"].replace("/", "_"))
    for suf, lst in ((".runtime.json", allrt), (".correctness.json", allct)):
        for x in load(b + suf):
            x["tool"] = f"{t['repo']}::{x['tool']}"; lst.append(x)   # never merge same-named tools across repos
with tempfile.TemporaryDirectory() as td:
    fr, fc = os.path.join(td, "rt.json"), os.path.join(td, "ct.json")
    json.dump(allrt, open(fr, "w")); json.dump(allct, open(fc, "w"))
    b1, b2 = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(b1): ns["failure_stats"](fr)
    with contextlib.redirect_stdout(b2): ns["correctness_stats"](fc)
succ = [tuple(map(int, m)) for m in re.findall(r"Number of succ triggers:\s+(\d+) out of (\d+)", b1.getvalue())]
m2 = re.search(r"Total bugs found: (\d+)\. Total prompts set: (\d+)\. Total prompts: (\d+)\.", b2.getvalue())
V = dict(tf_rt_erroneous=sum(a for a, _ in succ), tf_rt_tested=sum(b for _, b in succ),
         tf_rt_tools=sum(1 for a, _ in succ if a), tf_ct_bugs=int(m2.group(1)), tf_ct_prompts=int(m2.group(3)),
         tf_ct_tools=sum(1 for x in re.findall(r"Correctness bugs: (\d+),", b2.getvalue()) if int(x)))
idx_rt = sum(last[(t["repo"], t["tool"])].get("n_runtime_trigger") or 0 for t in ok)
idx_ct = sum(last[(t["repo"], t["tool"])].get("n_correctness_bug") or 0 for t in ok)

L = ["# ToolFuzz on the H2H-273 dynamic set (2026-09-28)", "",
     "Reported exactly as ToolFuzz reports: **runtime failures** and **correctness failures**, in ToolFuzz's",
     "units (Milev et al. 2025, Tables 1–3; criteria from its `tool_stats.py`). Nothing else is counted.", "",
     f"**Set:** `Benchmarks/extraction/h2h_273_dynamic_repos.txt` ({len(REPOS)} repos = H2H-273 minus the {len(EXCL)} "
     f"unsafe host-control servers). **Tools:** the {sum(len(v) for v in exe.values())} tools ToFu executed successfully on "
     f"them (`tofu_exec_index_273.jsonl`); ToolFuzz was given exactly these.", "",
     "## Coverage", "", "| status | tools |", "|---|---|"] + [f"| {k} | {v} |" for k, v in st.most_common()] + ["",
     f"ToolFuzz completed **{len(ok)} / {len(tools)} tools** in {len({t['repo'] for t in ok})} / {len(REPOS)} repos "
     f"({len(merged)} of them run on the PSU PC with the identical configuration and merged). Servers ToolFuzz's MCP "
     f"bridge could not load: {', '.join(f'`{r}`' for r in sorted(load_err))}.", "",
     "## Runtime failures (ToolFuzz §4.1; Tables 1–2 units)", "",
     "| erroneous prompts | tested prompts | unique errors (tool × error) | vulnerable tools | repos |", "|---|---|---|---|---|",
     f"| **{sm('rt_erroneous')}** | {sm('rt_tested')} | {sm('rt_unique_errors')} | **{nt(rt_v)}** | **{nr(rt_v)}** |", "",
     f"Excluded: {sm('rt_toolfuzz_internal')} trigger(s) whose exception was raised inside ToolFuzz's own code, not by the "
     "tool (not a tool execution error under the paper's definition).", "",
     "## Correctness failures (ToolFuzz §4.2; Table 3 units)", "",
     "| erroneous prompts | total prompts | faulty tools | repos | TP / FP |", "|---|---|---|---|---|",
     f"| **{sm('ct_erroneous')}** | {sm('ct_prompts')} | **{nt(ct_v)}** | **{nr(ct_v)}** | not inspected |", "",
     "ToolFuzz's paper separates true from false positives by manual inspection (its own FDR is **46%**, Table 3).",
     "This run has no manual inspection, so these are ToolFuzz's raw erroneous prompts.", "",
     "## Any ToolFuzz failure (runtime or correctness)", "",
     f"**{len(tf_tools)} tools** in **{len({r for r, _ in tf_tools})} repos**.", "",
     "## Comparison with ToFu on the same tools (context)", "",
     f"- ToFu (508 headline) flags **{len(tofu_tools)}** of the tools ToolFuzz completed "
     f"({sum(len(t['tofu_bugs']) for t in ok)} bugs, {len({r for r, _ in tofu_tools})} repos); ToFu has "
     f"{sum(len(tofu.get(r, ())) for r in REPOS)} of its 508 on these {len(REPOS)} repos.",
     f"- Tools flagged by both: **{len(tofu_tools & tf_tools)}**; ToolFuzz only: **{len(tf_tools - tofu_tools)}**; "
     f"ToFu only: **{len(tofu_tools - tf_tools)}**.",
     "- Units differ (ToFu: security silent-bug candidates; ToolFuzz: tool-documentation failures). Compare per tool.", "",
     "## Cost", "",
     f"- Real LLM calls: VM **{vm['calls']:,}** ({vm['prompt_tokens']:,} in / {vm['completion_tokens']:,} out tokens) + "
     f"merged PSU tools **{sum(t.get('llm_calls') or 0 for t in merged):,}**; median {calls[len(calls)//2]} per tool, max {calls[-1]} (cap 40).",
     "", "## Verification (three independent counts)", "",
     "| | runtime erroneous / tested prompts | vulnerable tools | correctness erroneous / total prompts | faulty tools |",
     "|---|---|---|---|---|",
     f"| ToolFuzz's own `tool_stats.py` (executed verbatim on these results) | {V['tf_rt_erroneous']} / {V['tf_rt_tested']} | {V['tf_rt_tools']} | {V['tf_ct_bugs']} / {V['tf_ct_prompts']} | {V['tf_ct_tools']} |",
     f"| counts recorded live in the run index | {idx_rt} / {sum(last[(t['repo'], t['tool'])].get('n_runtime_tests') or 0 for t in ok)} | — | {idx_ct} / — | — |",
     f"| this report | {sm('rt_erroneous')} / {sm('rt_tested')} | {nt(rt_v)} | {sm('ct_erroneous')} / {sm('ct_prompts')} | {nt(ct_v)} |", "",
     f"The only difference: `tool_stats.py` also counts the {sm('rt_toolfuzz_internal')} trigger(s) raised by ToolFuzz's own code; "
     "the tool count is unaffected.", "",
     "", "## Configuration", "",
     "ReAct agent over a langchain-MCP bridge; gpt-4.1-mini for every ToolFuzz LLM role (the authors used GPT-4o /",
     "GPT-4o-mini); 10 fuzz iterations; ≤ 3 failing inputs per error type, 1 agent query each; 1 correctness prompt set",
     "× 3 synonymous prompts; cap 40 LLM calls and 600 s per tool; every target server in a bwrap sandbox. Two",
     "ToolFuzz crashes fixed (`PATCH (ToFu)`: literal braces in generated templates; array schema without `items`)",
     "and two harness artefacts removed (an internal pydantic error recorded as a trigger; results appended across",
     "retries). Unsafe host-control repos not run: " + ", ".join(EXCL) + ".", ""]
open(P("REPORT.md"), "w").write("\n".join(L) + "\n")
print("\n".join(L))
