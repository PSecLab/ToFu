#!/usr/bin/env python3
"""Score ToolFuzz results correctly and compare them with ToFu on the same tools.

ToolFuzz reports no vulnerabilities. It reports two kinds of test outcome, and we
count them with ToolFuzz's OWN criteria (Benchmarks/ToolFuzz/src/eval/toolfuzz/
utils/tool_stats.py), read from the raw per-tool JSON it writes:

  runtime failure  : a TestFailureResult with successful_trigger == True (the
                     agent, prompted in natural language, drove the tool into an
                     exception). Deduplicated per tool by normalised message.
  correctness bug  : an individual run inside a prompt set whose
                     tool_arguments_inconsistency AND tool_output_inconsistency are
                     both True and whose judge score unexpected_agent_output <= 5.

On MCP servers a "runtime failure" is any error the server returns, so each one is
classified deterministically (regex on the exception text, no LLM), in order:
  HARNESS  - bug in ToolFuzz / the MCP bridge, not the tool (e.g. pydantic error
             building TestFailureResult, sync-invocation, LLM/agent errors)
  ENV      - backend / credential / network / platform unavailable
  REJECT   - the tool correctly refused the input with a handled error
  CRASH    - unhandled internal exception leaking out (TypeError, "Cannot read
             properties of undefined", Traceback, ...) = a genuine robustness bug
  UNCLASS  - none of the above; listed for manual review, NOT counted as a bug

Headline per tool:
  ToolFuzz runtime (ToolFuzz definition, HARNESS removed) -> "tf_runtime"
  ToolFuzz robustness bugs (CRASH only)                   -> "tf_crash"
  ToolFuzz correctness bugs (ToolFuzz formula)             -> "tf_correct"
  ToFu security candidates (triage_findings.REAL classes)  -> "tofu_sec"
  ToFu robustness (crash/exhaustion/type-confusion hits)   -> "tofu_rob"

Axes differ, so the comparison is tool-level set overlap on tools BOTH tools ran,
axis by axis -- never one summed bug count.

  python3 eval/score_toolfuzz.py [--repos-file F] [--write findings/baselines/x.md]
"""
import os, re, sys, json, glob, argparse, collections, importlib.util

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.environ.get("TOOLFUZZ_OUT", os.path.join(ROOT, "eval", "toolfuzz_runs"))
INDEX = os.environ.get("TOOLFUZZ_INDEX", os.path.join(ROOT, "eval", "state", "toolfuzz_runs.jsonl"))
TOFU_IDX = os.environ.get("TOOLFUZZ_TOFU_INDEX", os.path.join(ROOT, "eval", "state", "runs.gpt41-corpus.jsonl"))

_spec = importlib.util.spec_from_file_location("triage", os.path.join(ROOT, "eval", "triage_findings.py"))
_triage = importlib.util.module_from_spec(_spec); _spec.loader.exec_module(_triage)
TOFU_ROBUST = {"check_unexpected_crash", "check_resource_exhaustion", "check_invalid_json",
               "check_introspection_type_confusion"}

HARNESS = re.compile(r"for TestFailureResult|StructuredTool does not support sync|^<class 'KeyError'>|"
                     r"openai\.|RateLimit|APIConnection|APITimeout|GraphRecursion|Recursion limit|"
                     r"maximum recursion depth|McpError: Connection closed|TaskGroup|BrokenResource|"
                     r"ClosedResource|tool exceeded \d+s|Broken pipe|LLMToolCap|LLMBudget|bwrap:", re.I)
ENV = re.compile(r"fetch failed|ECONNREFUSED|ENOTFOUND|EAI_AGAIN|getaddrinfo|Connection refused|connect ECON|"
                 r"API[ _-]?key|not configured|authenticat|unauthori[sz]ed|\b401\b|\b403\b|credential|"
                 r"No active project|not connected|No frontend client|AppleScript|osascript|Base URL|"
                 r"No model registered|Name or service not known|Network is unreachable|ETIMEDOUT|timed out", re.I)
REJECT = re.compile(r"validation error|Input validation|Invalid (argument|input|param|request|value)|-32602|"
                    r"Field required|is required|required (field|property|parameter|argument)|missing required|"
                    r"should be a valid|must (be|provide|specify|contain)|Supply exactly|Access denied|"
                    r"outside (of )?(the )?(permitted|allowed)|not allowed|not permitted|not found|does not exist|"
                    r"No such file|unsupported|Unknown (tool|action|command|option|type)|Expected .{0,40}(got|received)|"
                    r"\"success\":\s*false", re.I)
CRASH = re.compile(r"TypeError|AttributeError|KeyError|IndexError|ReferenceError|RangeError|Cannot read propert|"
                   r"is not a function|undefined is not|of undefined|of null|NoneType|UnboundLocalError|"
                   r"ZeroDivision|Traceback|Maximum call stack|RecursionError|JSONDecodeError|Unexpected token|"
                   r"SyntaxError|ValueError|AssertionError|Internal (server )?error|unhandled|segmentation", re.I)


def classify(msg):
    m = msg or ""
    for name, rx in (("HARNESS", HARNESS), ("ENV", ENV), ("REJECT", REJECT), ("CRASH", CRASH)):
        if rx.search(m):
            return name
    return "UNCLASS"


def norm(msg):
    return re.sub(r"[0-9a-f]{8,}|\d+", "N", (msg or "").strip())[:160]


def truthy(v):
    return v is True or v == "True"


def load_jsonl(p):
    out = []
    if os.path.exists(p):
        for l in open(p):
            try: out.append(json.loads(l))
            except Exception: pass
    return out


def score_tool(slug, tool):
    base = os.path.join(OUT, slug, tool.replace("/", "_"))
    r = {"rt_tests": 0, "rt_trigger_raw": 0, "classes": collections.Counter(), "crash_msgs": set(),
         "unclass_msgs": set(), "tf_runtime": 0, "tf_crash": 0, "ct_sets": 0, "tf_correct": 0,
         "tf_correct_exec": 0}
    try:
        rt = json.load(open(base + ".runtime.json"))
    except Exception:
        rt = []
    seen = {}
    for t in rt:
        r["rt_tests"] += 1
        if not truthy(t.get("successful_trigger")):
            continue
        r["rt_trigger_raw"] += 1
        msg = t.get("exception") or ""
        c = classify(msg)
        r["classes"][c] += 1
        seen.setdefault((c, norm(msg)), msg)
    for (c, _), msg in seen.items():          # distinct failures per tool
        if c != "HARNESS":
            r["tf_runtime"] += 1
        if c == "CRASH":
            r["tf_crash"] += 1; r["crash_msgs"].add(msg.replace("\n", " ")[:200])
        if c == "UNCLASS":
            r["unclass_msgs"].add(msg.replace("\n", " ")[:200])
    try:
        ct = json.load(open(base + ".correctness.json"))
    except Exception:
        ct = []
    for s in ct:
        r["ct_sets"] += 1
        if s.get("tool_arguments_inconsistency") and s.get("tool_output_inconsistency"):
            for run in s.get("individual_run_test_results", []):
                d = run.get("unexpected_agent_output")
                if isinstance(d, int) and not isinstance(d, bool) and d <= 5:
                    r["tf_correct"] += 1
                    # executed-only view: the tool actually ran (its output is not a
                    # backend/credential/harness error), so the inconsistency is in
                    # real tool behaviour rather than in error messages.
                    if classify(run.get("tool_output") or "") not in ("HARNESS", "ENV") \
                            and not run.get("tool_failure"):
                        r["tf_correct_exec"] += 1
    return r


def tofu_by_tool():
    out = {}
    for r in load_jsonl(TOFU_IDX):
        if not r.get("ok"):
            continue
        k = ((r.get("repo") or "").lower(), r.get("tool"))
        e = out.setdefault(k, {"tofu_sec": set(), "tofu_rob": 0})
        if r.get("finding_hits"):
            cls = _triage.classify(r.get("triggered_sanitizers"))
            if cls:
                e["tofu_sec"].add(cls[0])
            if set(r.get("triggered_sanitizers") or []) & TOFU_ROBUST:
                e["tofu_rob"] += 1
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repos-file", default=None)
    ap.add_argument("--write", default=None)
    ap.add_argument("--index", default=None, help="toolfuzz index (default eval/state/toolfuzz_runs.jsonl)")
    ap.add_argument("--out", default=None, help="toolfuzz raw results dir (default eval/toolfuzz_runs)")
    a = ap.parse_args()
    global INDEX, OUT
    INDEX, OUT = a.index or INDEX, a.out or OUT
    only = None
    if a.repos_file:
        only = {x.strip().lower() for x in open(a.repos_file).read().replace("\n", ",").split(",") if x.strip()}

    latest = {}
    for r in load_jsonl(INDEX):
        if r.get("tool") == "*":
            continue
        latest[(r["repo"], r["tool"])] = r
    rows = {k: v for k, v in latest.items() if v.get("ok") and (only is None or k[0].lower() in only)}
    tofu = tofu_by_tool()

    per_tool, classes = {}, collections.Counter()
    calls = []
    for (repo, tool), rec in rows.items():
        s = score_tool(repo.replace("/", "__"), tool)
        classes.update(s["classes"])
        t = tofu.get((repo.lower(), tool))
        s["tofu_ran"] = t is not None
        s["tofu_sec"] = sorted(t["tofu_sec"]) if t else []
        s["tofu_rob"] = t["tofu_rob"] if t else 0
        s["llm_calls"] = rec.get("llm_calls")
        if rec.get("llm_calls") is not None:
            calls.append(rec["llm_calls"])
        per_tool[(repo, tool)] = s

    both = {k: v for k, v in per_tool.items() if v["tofu_ran"]}
    def flagged(d, key):
        return {k for k, v in d.items() if (len(v[key]) if isinstance(v[key], list) else v[key]) > 0}
    tf_rt, tf_cr, tf_co = flagged(both, "tf_runtime"), flagged(both, "tf_crash"), flagged(both, "tf_correct")
    tf_cx = flagged(both, "tf_correct_exec")
    tu_sec, tu_rob = flagged(both, "tofu_sec"), flagged(both, "tofu_rob")
    tf_any = tf_rt | tf_co

    L = [f"# ToolFuzz vs ToFu — scored with ToolFuzz's own criteria\n",
         f"Tools with a completed ToolFuzz run: **{len(per_tool)}** in "
         f"{len({k[0] for k in per_tool})} repos; also run by ToFu: **{len(both)}** (comparison set).\n",
         "## Runtime-failure triggers by class (all ToolFuzz triggers, before dedup)",
         "| class | triggers | meaning |", "|---|---|---|"]
    meaning = {"HARNESS": "ToolFuzz/bridge bug, not the tool", "ENV": "backend/cred/network unavailable",
               "REJECT": "tool correctly refused input", "CRASH": "unhandled internal exception (real bug)",
               "UNCLASS": "unclassified — manual review, not counted"}
    for c in ("HARNESS", "ENV", "REJECT", "CRASH", "UNCLASS"):
        L.append(f"| {c} | {classes.get(c, 0)} | {meaning[c]} |")
    L += ["", "## Tool-level results on the comparison set (tools both tools ran)",
          "| axis | ToolFuzz tools flagged | ToFu tools flagged | both |", "|---|---|---|---|",
          f"| robustness (ToolFuzz CRASH vs ToFu crash/exhaustion hits) | {len(tf_cr)} | {len(tu_rob)} | {len(tf_cr & tu_rob)} |",
          f"| security (ToFu triaged classes; ToolFuzz has no security oracle) | — | {len(tu_sec)} | — |",
          f"| functional correctness (ToolFuzz formula; ToFu has no such oracle) | {len(tf_co)} | — | — |",
          f"| ↳ same, tool actually executed (outputs not backend/harness errors) | {len(tf_cx)} | — | — |",
          f"| ToolFuzz runtime, its own definition minus HARNESS (incl. ENV/REJECT) | {len(tf_rt)} | — | — |",
          "",
          f"ToFu security-flagged tools that ToolFuzz flagged for *anything*: "
          f"**{len(tu_sec & tf_any)} / {len(tu_sec)}**; of those, as a genuine crash: {len(tu_sec & tf_cr)}.",
          ""]
    if calls:
        calls.sort()
        L.append(f"ToolFuzz real LLM calls per tool (this configuration): median {calls[len(calls)//2]}, "
                 f"mean {sum(calls)/len(calls):.1f}, total {sum(calls)} over {len(calls)} tools. "
                 f"ToFu: 2 LLM steps per tool at initialisation (sanitizer selection + seeds), none while fuzzing.\n")
    L += ["## Per repo", "| repo | tools | tf_runtime | tf_crash | tf_correct | tofu_sec | tofu_rob |",
          "|---|---|---|---|---|---|---|"]
    by_repo = collections.defaultdict(list)
    for (repo, tool), s in both.items():
        by_repo[repo].append(s)
    for repo in sorted(by_repo, key=lambda r: -sum(len(x["tofu_sec"]) for x in by_repo[r])):
        ss = by_repo[repo]
        L.append(f"| {repo} | {len(ss)} | {sum(1 for x in ss if x['tf_runtime'])} | "
                 f"{sum(1 for x in ss if x['tf_crash'])} | {sum(1 for x in ss if x['tf_correct'])} | "
                 f"{sum(1 for x in ss if x['tofu_sec'])} | {sum(1 for x in ss if x['tofu_rob'])} |")
    crash_examples = [(k, m) for k, v in both.items() for m in v["crash_msgs"]][:30]
    if crash_examples:
        L += ["", "## ToolFuzz CRASH findings (for manual confirmation)", ""]
        L += [f"- `{k[0]}::{k[1]}` — {m}" for k, m in crash_examples]
    unc = [(k, m) for k, v in both.items() for m in v["unclass_msgs"]]
    if unc:
        L += ["", f"## UNCLASS triggers ({len(unc)}, not counted) — sample", ""]
        L += [f"- `{k[0]}::{k[1]}` — {m}" for k, m in unc[:25]]
    txt = "\n".join(L) + "\n"
    print(txt)
    if a.write:
        open(a.write, "w").write(txt)
        json.dump({f"{k[0]}::{k[1]}": {kk: (sorted(vv) if isinstance(vv, set) else vv)
                                         for kk, vv in v.items() if kk != "classes"} | {"classes": dict(v["classes"])}
                   for k, v in per_tool.items()},
                  open(os.path.splitext(a.write)[0] + ".json", "w"), indent=1)


if __name__ == "__main__":
    main()
