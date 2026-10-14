#!/usr/bin/env python3
"""Turn ToolFuzz output into reportable, class-split counts.

ToolFuzz's runtime oracle is "the tool raised". For an MCP server that lumps
together very different events, so every recorded runtime exception is
classified by its text before anything is counted:

  internal   ToolFuzz's own reporter failing (pydantic ValidationError for
             TestFailureResult, "Invocation was interrupted") -- noise
  graceful   the server answered with an error (MCP -326xx, isError,
             "Invalid params", "not found", validation text) -- correct
             behaviour for bad input, NOT a crash
  transport  the server process died or hung (Connection closed, BrokenPipe,
             EOF, TaskGroup, timeout) -- the only class comparable to a ToFu
             crash alert
  other      anything else -- read by hand

Correctness: per prompt set, tool_output_inconsistency / tool_arguments_
inconsistency flags from ToolFuzz's oracle, plus per-prompt tool_failure and
unexpected_agent_output (ToolFuzz degree; <5 = concern). These are agent-
behaviour observations, not security findings; reported as-is with that label.

Usage: python3 eval/summarize_toolfuzz.py [--runs eval/toolfuzz_runs_vm]
          [--state eval/state/toolfuzz_runs_vm.jsonl] [--csv eval/state/toolfuzz_runtime_exceptions.csv]
"""
import argparse, collections, csv, json, os, re, sys

INTERNAL  = re.compile(r"validation error for TestFailureResult|Invocation was interrupted|NotImplementedError.*sync invocation|KeyError.>.error.$|KeyError.>.error.\b", re.I)
TRANSPORT = re.compile(r"Connection closed|BrokenPipe|EOF|TaskGroup|timed? ?out|Timeout|ConnectionReset|exceeded \d+s|process exited|Broken pipe", re.I)
GRACEFUL  = re.compile(r"MCP error -32\d\d\d|isError|Invalid params|validation|not found|does not exist|required|invalid|missing|must be|unauthori[sz]ed|forbidden|permission|ToolException", re.I)

def classify(exc):
    e = exc or ""
    if INTERNAL.search(e):  return "internal"
    if TRANSPORT.search(e): return "transport"
    if GRACEFUL.search(e):  return "graceful"
    return "other"

def load(p):
    try: return json.load(open(p))
    except Exception: return None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs",  default="eval/toolfuzz_runs_vm")
    ap.add_argument("--state", default="eval/state/toolfuzz_runs_vm.jsonl")
    ap.add_argument("--csv",   default="eval/state/toolfuzz_runtime_exceptions.csv")
    ap.add_argument("--include-stale", action="store_true",
                    help="keep run-#1 rows (expected_exception NotImplementedError = sync-invocation era; "
                         "ToolFuzz save() APPENDS to an existing .runtime.json, so relaunches merge them in)")
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(a.state)]
    ok = {}
    for r in rows:
        if r.get("ok"): ok[(r["repo"], r["tool"])] = r
    err = {(r["repo"], r["tool"]) for r in rows if not r.get("ok")} - set(ok)

    per_repo = collections.defaultdict(lambda: collections.Counter())
    exc_rows = []
    corr = collections.Counter()
    for (repo, tool), rec in sorted(ok.items()):
        slug = repo.replace("/", "__"); base = os.path.join(a.runs, slug, tool.replace("/", "_"))
        per_repo[repo]["tools_ok"] += 1
        rt = load(base + ".runtime.json")
        if rt is not None:
            if not a.include_stale:
                rt = [e for e in rt if "NotImplementedError" not in str(e.get("expected_exception"))]
            per_repo[repo]["rt_entries"] += len(rt)
            for e in rt:
                k = classify(e.get("exception"))
                per_repo[repo]["rt_" + k] += 1
                exc_rows.append(dict(repo=repo, tool=tool, cls=k, expected=str(e.get("expected_exception"))[:60],
                                     exception=(e.get("exception") or "")[:240].replace("\n", " "),
                                     fuzzed=str(e.get("fuzzed_params"))[:120], triggered=e.get("successful_trigger")))
        ct = load(base + ".correctness.json")
        if ct is not None:
            per_repo[repo]["ct_sets"] += len(ct)
            for ps in ct:
                if ps.get("tool_output_inconsistency"):    per_repo[repo]["ct_out_incons"] += 1
                if ps.get("tool_arguments_inconsistency"): per_repo[repo]["ct_arg_incons"] += 1
                for ind in ps.get("individual_run_test_results", []):
                    corr["prompts"] += 1
                    if ind.get("tool_failure"): corr["tool_failure"] += 1
                    u = ind.get("unexpected_agent_output")
                    if isinstance(u, (int, float)) and u < 5: corr["agent_out_concern"] += 1
                    if ind.get("agent_output_not_relevant"): corr["agent_out_not_relevant"] += 1

    print(f"{'repo':45} ok  rtN  int  grace trans other | ctSets outInc argInc")
    tot = collections.Counter()
    for repo, c in sorted(per_repo.items()):
        tot.update(c)
        print(f"{repo:45} {c['tools_ok']:2}  {c['rt_entries']:3}  {c['rt_internal']:3}  {c['rt_graceful']:4}  {c['rt_transport']:4}  {c['rt_other']:4} | {c['ct_sets']:5}  {c['ct_out_incons']:5}  {c['ct_arg_incons']:5}")
    print("-" * 110)
    print(f"{'TOTAL  (' + str(len(per_repo)) + ' repos)':45} {tot['tools_ok']:2}  {tot['rt_entries']:3}  {tot['rt_internal']:3}  {tot['rt_graceful']:4}  {tot['rt_transport']:4}  {tot['rt_other']:4} | {tot['ct_sets']:5}  {tot['ct_out_incons']:5}  {tot['ct_arg_incons']:5}")
    print(f"\nstate: ok tools {len(ok)} | still-ERR tools {len(err)} | repos with >=1 ok tool {len(per_repo)}")
    print(f"correctness prompts {corr['prompts']}: tool_failure {corr['tool_failure']}, agent_out_concern(<5) {corr['agent_out_concern']}, agent_out_not_relevant {corr['agent_out_not_relevant']}")
    print("\nruntime exception classes: only `transport` is comparable to a ToFu crash-class alert;"
          " `graceful` = server validated bad input correctly; `internal` = ToolFuzz reporter noise.")
    print("transport rows:")
    for r in exc_rows:
        if r["cls"] == "transport": print(f"  {r['repo']} / {r['tool']}: {r['exception'][:110]}")
    print("other rows (read by hand):")
    for r in exc_rows:
        if r["cls"] == "other": print(f"  {r['repo']} / {r['tool']}: {r['exception'][:110]}")

    os.makedirs(os.path.dirname(a.csv), exist_ok=True)
    with open(a.csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["repo", "tool", "cls", "expected", "exception", "fuzzed", "triggered"])
        w.writeheader(); w.writerows(exc_rows)
    print(f"\nexceptions -> {a.csv} ({len(exc_rows)} rows)")

if __name__ == "__main__":
    sys.exit(main())
