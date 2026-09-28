# ToolFuzz baseline — brief for the paper (H2H-273, 2026-09-28)

Every number below is in `REPORT.md` (regenerate: `python3 findings/toolfuzz_h2h273_20260928/analyze_toolfuzz_273.py`).
Method detail and the ToolFuzz-paper verification: `findings/baselines/toolfuzz_method_20260923.md`.

## What was run
- **Set:** the H2H-273 dynamic set, 266 repos = H2H-273 minus the 7 unsafe host-control servers
  (same set as Viper c251). **Tools:** the 1,585 tools ToFu executed successfully on them
  (`Benchmarks/extraction/tofu_exec_index_273.jsonl`). ToolFuzz was given exactly these tools.
- **Completed:** 1,516 / 1,585 tools (95.6%) in 258 / 266 repos. Not completed: 48 tools on 8 servers
  ToolFuzz's MCP bridge could not load, 15 ToolFuzz internal errors, 5 timeouts (600 s), 1 not run.
- **Configuration:** ToolFuzz (eth-sri) through a langchain-MCP bridge; ReAct agent; **gpt-4.1-mini** for
  every ToolFuzz LLM role; 10 direct fuzz iterations; ≤3 failing inputs per error type, 1 agent prompt
  each; 1 correctness prompt set × 3 paraphrases; cap 40 LLM calls per tool; 600 s per tool; every target
  in a bwrap sandbox. 296 of the 1,516 tools were run on the PSU PC with the identical configuration and
  merged; the rest on the VM.
- **Cost:** 21,697 real LLM calls (VM 17,076 + PSU 4,621); median 16 per completed tool, max 36.
  ToFu uses 2 LLM steps per tool at initialisation and none while fuzzing.

## Results (per tool, ToolFuzz's own criteria)
| outcome | tools | repos |
|---|---|---|
| runtime failure, ToolFuzz's own definition (includes backend-unavailable and correct-rejection errors) | 194 | 76 |
| **genuine crash** (unhandled internal error) | **14** | **10** |
| correctness failure, ToolFuzz's code formula | 114 | 52 |
| **correctness failure with a real tool output** | **0** | **0** |
| **ToFu (508 headline) bugs on the same completed tools** | **428 tools (429 bugs)** | **129** |

- Runtime triggers by class: backend/credential/host unavailable 86 · tool correctly rejected input 92 ·
  genuine crash 14 · ToolFuzz/bridge error 8 · unclassified 2 (not counted).
- The 14 crashes: 12 are file-name-length errors (an unvalidated argument reaches a filesystem call:
  ENAMETOOLONG / Errno 36), 2 a missing-`scheme` type error (opendal).
- **Overlap:** all 14 ToolFuzz crash tools are also ToFu-flagged; of ToFu's 428 flagged tools, ToolFuzz
  flags 48 for anything and 14 as a crash; **380 ToFu-flagged tools get no ToolFuzz finding at all.**
- Correctness: every one of the 114 formula positives is a tool *error* during a correctness prompt,
  which ToolFuzz records as output "Tool FAILURE" with judge score 0. The ToolFuzz paper defines
  correctness failures as incorrect results, so none survive once only real outputs count.

## Suggested framing (claims the data supports)
- ToolFuzz and ToFu answer different questions: ToolFuzz tests whether a tool's documentation lets an
  agent use it correctly (its paper's stated goal); ToFu tests whether the implementation keeps the
  security contract its documentation implies. Report per axis, never one combined bug count.
- On the same 1,516 tools, ToolFuzz's genuine findings (14 crashes) all fall on tools ToFu already flags,
  as the symptom (a long file name crashes) where ToFu reports the security property violated: on 12 of
  the 14, ToFu reports path traversal on the same tool (the other 2: log injection). ToFu flags 380 tools
  where ToolFuzz reports nothing.

## Caveats the paper must state
- **ToolFuzz's own correctness false-discovery rate is 46%** (Milev et al. 2025, Table 3: the authors
  hand-checked every positive, 622 TP / 534 FP).
- Its claim that runtime detection has no false positives holds for LangChain tools, where an error is a
  crash; MCP servers return errors as protocol replies, so we separate backend-unavailable, correct
  rejection and genuine crash (ToolFuzz's own number is also reported).
- ToolFuzz's taint-guided argument generation works in-process on Python tools only; over MCP the server
  is a separate process, so it falls back to type-based (Faker) values.
- Budget-capped configuration for cost (above); the ToolFuzz authors used GPT-4o / GPT-4o-mini, ToFu's
  arm used gpt-4.1.
- We fixed two ToolFuzz bugs (crash on literal braces in generated templates; array schemas without
  `items`) and two harness artefacts (an internal pydantic error recorded as a tool failure; results
  appended across retries). The first ToolFuzz campaign's figures are withdrawn for these reasons
  (`findings/baselines/toolfuzz_method_20260923.md`).
- 8 servers could not be loaded by ToolFuzz's MCP bridge (e.g. NASA-MCP-server sends notifications before
  its initialize reply); they are ToolFuzz-untested, not ToolFuzz-clean.
