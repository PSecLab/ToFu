# ToolFuzz on the H2H-273 dynamic set (2026-09-28)

Reported exactly as ToolFuzz reports: **runtime failures** and **correctness failures**, in ToolFuzz's
units (Milev et al. 2025, Tables 1–3; criteria from its `tool_stats.py`). Nothing else is counted.

**Set:** `Benchmarks/extraction/h2h_273_dynamic_repos.txt` (266 repos = H2H-273 minus the 7 unsafe host-control servers). **Tools:** the 1585 tools ToFu executed successfully on them (`tofu_exec_index_273.jsonl`); ToolFuzz was given exactly these.

## Coverage

| status | tools |
|---|---|
| ok | 1516 |
| not run (server not loadable by ToolFuzz's MCP bridge) | 48 |
| ToolFuzz error | 15 |
| timeout (600 s) | 5 |
| not run | 1 |

ToolFuzz completed **1516 / 1585 tools** in 258 / 266 repos (296 of them run on the PSU PC with the identical configuration and merged). Servers ToolFuzz's MCP bridge could not load: `AppiumTestDistribution/mcp-appium-gestures`, `ProgramComputer/NASA-MCP-server`, `T1nker-1220/memories-with-lessons-mcp-server`, `alexatnordnet/mcp-google-custom-search-server`, `gerred/mcp-server-replicate`, `renyumeng1/mcp_scholar`, `teddyzxcv/ntfy-mcp`, `tomekkorbak/oura-mcp-server`.

## Runtime failures (ToolFuzz §4.1; Tables 1–2 units)

| erroneous prompts | tested prompts | unique errors (tool × error) | vulnerable tools | repos |
|---|---|---|---|---|
| **200** | 517 | 200 | **200** | **77** |

Excluded: 2 trigger(s) whose exception was raised inside ToolFuzz's own code, not by the tool (not a tool execution error under the paper's definition).

## Correctness failures (ToolFuzz §4.2; Table 3 units)

| erroneous prompts | total prompts | faulty tools | repos | TP / FP |
|---|---|---|---|---|
| **342** | 3441 | **114** | **52** | not inspected |

ToolFuzz's paper separates true from false positives by manual inspection (its own FDR is **46%**, Table 3).
This run has no manual inspection, so these are ToolFuzz's raw erroneous prompts.

## Any ToolFuzz failure (runtime or correctness)

**237 tools** in **92 repos**.

## Comparison with ToFu on the same tools (context)

- ToFu (508 headline) flags **428** of the tools ToolFuzz completed (429 bugs, 129 repos); ToFu has 493 of its 508 on these 266 repos.
- Tools flagged by both: **62**; ToolFuzz only: **175**; ToFu only: **366**.
- Units differ (ToFu: security silent-bug candidates; ToolFuzz: tool-documentation failures). Compare per tool.

## Cost

- Real LLM calls: VM **17,076** (15,163,984 in / 1,554,906 out tokens) + merged PSU tools **4,621**; median 16 per tool, max 36 (cap 40).

## Verification (three independent counts)

| | runtime erroneous / tested prompts | vulnerable tools | correctness erroneous / total prompts | faulty tools |
|---|---|---|---|---|
| ToolFuzz's own `tool_stats.py` (executed verbatim on these results) | 202 / 517 | 200 | 342 / 3441 | 114 |
| counts recorded live in the run index | 202 / 517 | — | 342 / — | — |
| this report | 200 / 517 | 200 | 342 / 3441 | 114 |

The only difference: `tool_stats.py` also counts the 2 trigger(s) raised by ToolFuzz's own code; the tool count is unaffected.


## Configuration

ReAct agent over a langchain-MCP bridge; gpt-4.1-mini for every ToolFuzz LLM role (the authors used GPT-4o /
GPT-4o-mini); 10 fuzz iterations; ≤ 3 failing inputs per error type, 1 agent query each; 1 correctness prompt set
× 3 synonymous prompts; cap 40 LLM calls and 600 s per tool; every target server in a bwrap sandbox. Two
ToolFuzz crashes fixed (`PATCH (ToFu)`: literal braces in generated templates; array schema without `items`)
and two harness artefacts removed (an internal pydantic error recorded as a trigger; results appended across
retries). Unsafe host-control repos not run: PhialsBasement/CMD-MCP-Server, SimonB97/win-cli-mcp-server, dnakov/frida-mcp, mobile-next/mobile-mcp, nickgnd/tmux-mcp, r-huijts/xcode-mcp-server, wonderwhy-er/ClaudeComputerCommander.

