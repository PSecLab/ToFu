# ToolFuzz baseline — how findings are counted and compared (2026-09-23)

## What ToolFuzz reports
ToolFuzz (eth-sri) reports no vulnerabilities and no single bug count. It writes
per-tool test results of two kinds. We count them with ToolFuzz's **own** criteria,
taken from its evaluation code (`Benchmarks/ToolFuzz/src/eval/toolfuzz/utils/tool_stats.py`):

| ToolFuzz outcome | criterion (verbatim logic) |
|---|---|
| runtime failure | `TestFailureResult.successful_trigger == True` — the agent, prompted in natural language, drove the tool into an exception |
| correctness bug | per individual run in a prompt set with `tool_arguments_inconsistency and tool_output_inconsistency and unexpected_agent_output <= 5` |

## Why the first campaign's ToolFuzz numbers are withdrawn
`findings/baselines/toolfuzz_runs_20260919.jsonl` (59 repos) must not be cited:
1. `n_runtime_fail` read a field (`is_failure`) that does not exist → always 0.
2. `n_correctness` was `len(ct.results)` = prompt sets **tested**, not bugs. The
   "2,030 discrepancies" figure is a count of tests.
3. ToolFuzz harness bug: when the agent did not pass tool arguments, building
   `TestFailureResult(invocation_params=None)` raised a pydantic ValidationError that
   ToolFuzz's own `except Exception` recorded as `successful_trigger=True`
   (2,163 of 6,594 triggers).
4. `save_test_results` appends to an existing file, so retried tools accumulated
   duplicate results.
5. Two different models were in play (agent gpt-4.1, generators/oracle hardcoded gpt-4o).

Re-scored with the correct criteria (zero LLM calls), the first campaign's 6,594
triggers split into HARNESS 2,677 · ENV 2,201 · REJECT 1,309 · CRASH 8 · UNCLASS 373.

## Fixed harness (commit f87d953 and follow-ups)
- `eval/toolfuzz_llm_guard.py`: one model for every ToolFuzz LLM role (gpt-4.1 = ToFu's
  arm), persistent response cache, cross-process count of **real** API calls, global
  hard stop and per-tool cap, per-call `max_tokens` bound.
- `eval/run_toolfuzz.py`: bugs 3 and 4 fixed at source; secrets and `$TMUX` scrubbed
  from target servers' env; budget-capped testers (same algorithm, bounded breadth:
  ≤3 failing arg sets per exception type, ≤2 prompts each; 2 correctness prompt sets of
  ≤4 paraphrases); knobs recorded in every index row; sharded and resumable.
- `--executable-only`: ToolFuzz runs only on tools ToFu saw return success at least once
  (same server environment). A tool that always errors gives neither tool a finding.

## Classification of runtime failures (deterministic, no LLM)
On MCP servers every server-side error becomes a runtime "failure", so each trigger is
classified by its exception text, in order: **HARNESS** (ToolFuzz/bridge bug) →
**ENV** (backend/credential/network/platform unavailable) → **REJECT** (tool correctly
refused the input) → **CRASH** (unhandled internal exception = genuine robustness bug)
→ **UNCLASS** (listed for manual review, never counted). Regexes: `eval/score_toolfuzz.py`.

## Comparison with ToFu (the only valid form)
ToolFuzz and ToFu answer different questions, so there is **no single leaderboard number**.
Comparison is tool-level set overlap on tools **both** ran, axis by axis:

| axis | ToolFuzz side | ToFu side |
|---|---|---|
| robustness | CRASH-class runtime failures | crash / exhaustion / type-confusion hits |
| security | none (no security oracle) | triaged security classes |
| functional correctness | ToolFuzz formula (+ executed-only view) | none (no such oracle) |
| cost | real LLM calls per tool (measured) | 2 LLM steps per tool at init, 0 while fuzzing |

Plus: of the tools ToFu flags for security, how many ToolFuzz flags for anything.
All ToolFuzz counts are its own outcome definitions; ToolFuzz correctness bugs are
LLM-judged and unverified.

Scored output: `python3 eval/score_toolfuzz.py --write findings/baselines/toolfuzz_h2h_scored_<date>.md`.
