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

## Verified against the paper (Milev et al. 2025, "ToolFuzz — Automated Agent Tool Testing", read 2026-09-25)
- **Goal:** detect tool-*documentation* errors (under-/ill-specified docs) that make agents misuse
  tools; autofix rewrites descriptions. Not a security tester (§3, §5.3).
- **Runtime failures (§4.1, Tables 1–2):** taint-guided fuzzer (taint objects capture syntax priors;
  Faker for semantic priors) finds failing arguments → agent sanity check → LLM writes a user query →
  counted as an *erroneous prompt* if the agent run raises a runtime error. Reported as erroneous /
  tested prompts, unique errors (ToolFuzz: 999 / 3,297, 41 unique) and vulnerable tools per error type.
  Paper states runtime detection has no false positives — true for LangChain tools where an exception
  is a crash; on MCP servers errors are graceful protocol replies, hence our ENV/REJECT/CRASH split.
- **Correctness failures (§4.2, Table 3):** positive only if all three checks fail — argument
  inconsistency, output inconsistency, LLM oracle score vs. a majority-vote expected answer at or
  below 5 on 1–10. **All positives were manually inspected: 622 TP / 534 FP, FDR 46%.**
- **Setup (§5.1):** ReAct agent, LangChain, GPT-4o / GPT-4o-mini, 32 LangChain community tools
  without API keys + 35 synthetic tools.

### Consequences for our comparison
- Our scorer's criteria match the paper (code `<= 5` = paper threshold 5); runtime reported as unique
  errors per tool, as in Tables 1–2.
- **Taint guidance is lost over MCP:** taint tracking is in-process Python only; an MCP server is a
  separate process receiving JSON, so ToolFuzz's fuzzer degrades to type-based Faker generation here.
  State this as a limitation of applying ToolFuzz to MCP.
- **Correctness positives need manual inspection** (as the authors did) before any count is compared;
  otherwise report raw counts next to the authors' own 46% FDR. The executed-only view is a pre-filter.
- Deviation (final config, 2026-09-25): **gpt-4.1-mini** for every ToolFuzz LLM role — a mini-class
  model as in the authors' own GPT-4o-mini experiments, chosen for cost; ToFu's arm used gpt-4.1.
  Budget: 1 correctness prompt set x 3 paraphrases, 1 prompt per failing runtime input, <=3 failing
  inputs per error type, 10 fuzz iterations, cap 40 calls/tool. All recorded in every index row.
