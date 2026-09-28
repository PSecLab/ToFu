# ToolFuzz baseline — brief for the paper (H2H-273, 2026-09-28)

Report ToolFuzz **only as ToolFuzz reports itself**: runtime failures and correctness failures, in its
own units (Milev et al. 2025, §4.1–4.2, Tables 1–3). Every number below is in `REPORT.md`, which
recomputes them with ToolFuzz's own evaluation code (`tool_stats.py`, run verbatim) and matches it.
Regenerate: `python3 findings/toolfuzz_h2h273_20260928/analyze_toolfuzz_273.py`.

## What ToolFuzz reports (definitions from its paper)
- **Runtime failure:** an agent query during which the tool raised a runtime error ("erroneous prompt").
  Reported as erroneous prompts, tested prompts, unique errors, vulnerable tools.
- **Correctness failure:** a prompt from a set of synonymous prompts for which all checks fail — the tool
  arguments are inconsistent, the tool outputs are inconsistent, and the LLM oracle scores the answer ≤ 5
  on 1–10. Reported as erroneous prompts / total prompts; the authors then hand-check true vs false positives.

## What was run
- **Set:** H2H-273 dynamic set, 266 repos (H2H-273 minus 7 unsafe host-control servers; same set as Viper).
  **Tools:** the 1,585 tools ToFu executed successfully there (`tofu_exec_index_273.jsonl`).
- **Completed:** 1,516 / 1,585 tools in 258 / 266 repos. Not completed: 48 tools on 8 servers ToolFuzz's
  MCP bridge could not load, 15 ToolFuzz errors, 5 timeouts (600 s), 1 not run.
- **Configuration:** ReAct agent via a langchain-MCP bridge; gpt-4.1-mini for every ToolFuzz LLM role;
  10 fuzz iterations; ≤ 3 failing inputs per error type, 1 agent query each; 1 correctness prompt set × 3
  synonymous prompts; cap 40 LLM calls and 600 s per tool; every target server in a bwrap sandbox.
  296 of the 1,516 tools were run on a second machine with the identical configuration and merged.
- **Cost:** 21,697 real LLM calls (median 16 per tool). ToFu: 2 LLM steps per tool at initialisation,
  none while fuzzing.

## Results
| | erroneous prompts | tested / total prompts | tools | repos |
|---|---|---|---|---|
| **Runtime failures** | **200** | 517 tested | **200** vulnerable (200 unique errors) | **77** |
| **Correctness failures** | **342** | 3,441 total | **114** faulty | **52** |
| **Either** | — | — | **237** | **92** |

- Correctness true/false positives were **not** hand-checked in our run. ToolFuzz's authors report a
  **46% false-discovery rate** for these positives (their Table 3: 622 TP / 534 FP) — state it next to
  the 342 / 114.
- Runtime: 2 further triggers were exceptions raised inside ToolFuzz's own code, not by a tool; they are
  excluded (ToolFuzz's `tool_stats.py` would count 202 erroneous prompts; the tool count stays 200).

## Comparison with ToFu on the same 1,516 tools (context)
- ToFu (508 headline) flags 428 of them (129 repos). Both flag **62** tools; ToolFuzz only **175**;
  ToFu only **366**.
- The two answer different questions: ToolFuzz tests whether a tool's documentation lets an agent use it
  correctly (its paper's stated goal); ToFu tests whether the implementation keeps the security contract
  its documentation implies. Compare per tool and per axis; never add the counts.

## Caveats the paper should state
- ToolFuzz's own 46% correctness FDR (above).
- ToolFuzz's taint-guided argument generation works in-process on Python tools; over MCP the server is a
  separate process, so argument generation falls back to type-based (Faker) values.
- Budget-capped configuration for cost (above); the ToolFuzz authors used GPT-4o / GPT-4o-mini, ToFu's
  arm used gpt-4.1.
- To make ToolFuzz run on MCP servers we fixed two ToolFuzz crashes (literal braces in generated templates;
  array schemas without `items`) and two harness artefacts (an internal pydantic error recorded as a tool
  failure; results appended across retries). The first ToolFuzz campaign's figures are withdrawn
  (`findings/baselines/toolfuzz_method_20260923.md`).
- The 8 servers ToolFuzz's MCP bridge could not load are ToolFuzz-untested, not ToolFuzz-clean.
