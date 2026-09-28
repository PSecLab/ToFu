# ToolFuzz on the H2H-273 dynamic set vs ToFu (2026-09-28)

**Set:** `Benchmarks/extraction/h2h_273_dynamic_repos.txt` (266 repos = the H2H-273 minus the 7 unsafe host-control servers). **Tools:** the 1585 tools ToFu executed successfully on them (`tofu_exec_index_273.jsonl`). ToolFuzz is given exactly these tools.

> Units differ. ToFu bugs are runtime silent-bug candidates (distinct repo×tool×class, the 508 headline).
> ToolFuzz reports test outcomes, counted with ToolFuzz's own criteria (its `tool_stats.py`): a *runtime
> failure* is an agent prompt that drove the tool into an error; a *correctness failure* needs argument AND
> output inconsistency across paraphrases AND an LLM-judge score ≤ 5/10. ToolFuzz targets tool-documentation
> errors, not security (Milev et al. 2025). Compare per tool, per axis — never one summed count.

## Coverage

| status | tools |
|---|---|
| ok | 1516 |
| not run (server not loadable) | 48 |
| ToolFuzz internal error | 15 |
| timeout (600 s) | 5 |
| not run | 1 |

ToolFuzz completed **1516 / 1585 tools** (95.6%) in 258 / 266 repos; 296 of them are merged from the PSU H2H run (identical configuration). Repos ToolFuzz could not load at all: `AppiumTestDistribution/mcp-appium-gestures`, `ProgramComputer/NASA-MCP-server`, `T1nker-1220/memories-with-lessons-mcp-server`, `alexatnordnet/mcp-google-custom-search-server`, `gerred/mcp-server-replicate`, `renyumeng1/mcp_scholar`, `teddyzxcv/ntfy-mcp`, `tomekkorbak/oura-mcp-server`.

## Runtime failures by class (all triggers, before per-tool dedup)

| class | triggers | meaning |
|---|---|---|
| HARNESS | 8 | ToolFuzz / MCP-bridge error (non-ToolException or disconnect), not the tool |
| ENV | 86 | upstream service / credential / host app unavailable |
| REJECT | 92 | the tool correctly refused the input |
| CRASH | 14 | unhandled internal error leaking out (robustness bug) |
| UNCLASS | 2 | cause not evident from the text; not counted |

## Headline (tools ToolFuzz completed)

| | tools | repos |
|---|---|---|
| ToolFuzz runtime failure, its own definition (HARNESS removed; incl. ENV/REJECT) | 194 | 76 |
| ToolFuzz genuine crash (CRASH class) | **14** | **10** |
| ToolFuzz correctness failure, code formula | 114 | 52 |
| ToolFuzz correctness failure, tool actually executed | **0** | **0** |
| **ToFu (508 headline) bugs on these tools** | **428** (429 bugs) | **129** |

ToFu has 493 of its 508 bugs on these 266 repos; 429 sit on tools ToolFuzz completed. The 7 excluded unsafe repos carry 0 ToFu bugs.

**Correctness, formula vs executed:** ToolFuzz stores a tool that throws during a correctness prompt as output
`Tool FAILURE` with judge score 0, so its code formula counts tool errors as correctness failures. The paper
defines correctness failures as incorrect results; the executed-only row keeps only runs where the tool returned
a real (non-error) output.

## Overlap on the same tools

- ToFu-flagged tools that ToolFuzz flagged for anything (runtime own-def or executed correctness): **48 / 428**; as a genuine crash: **14**.
- ToolFuzz crash tools that ToFu also flags: 14 / 14; ToFu's class on them: path-traversal 12, log-injection 2.
- ToFu-only tools (ToFu bug, ToolFuzz nothing): 380.

## ToolFuzz genuine crashes (for manual confirmation)

Crash tools by kind: file-name-length (unvalidated arg reaches a filesystem call): 12; other: 2.

- `Sheshiyer/framer-plugin-mcp::create_plugin` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: Failed to create plugin: ENAMETOOLONG: name too long, mkdir '/scratch/tofu/eval/targets_tf/Sh  *(ToFu: path-traversal)*
- `Xuanwo/mcp-server-opendal::get_info` — argument 'scheme': 'NoneType' object cannot be converted to 'PyString'  *(ToFu: log-injection)*
- `Xuanwo/mcp-server-opendal::read` — argument 'scheme': 'NoneType' object cannot be converted to 'PyString'  *(ToFu: path-traversal)*
- `aaronsb/google-workspace-mcp::manage_workspace` — <class 'langchain_core.tools.base.ToolException'>Error: ENAMETOOLONG: name too long, realpath '/home/mza6485/.tofu_scratch/toolfuzz/aaronsb__google-workspace-mcp/home/.lo  *(ToFu: path-traversal)*
- `bsmi021/mcp-file-context-server::get_chunk_count` — <class 'langchain_core.tools.base.ToolException'>File operation error: Failed to get chunk count: ENAMETOOLONG: name too long, stat '/home/mza6485/toolfuzzer/eval/targets  *(ToFu: path-traversal)*
- `davidteren/claude-server::save_conversation_context` — <class 'langchain_core.tools.base.ToolException'>McpError: ENAMETOOLONG: name too long, open '/scratch/tofu/.tofu_scratch/toolfuzz/davidteren__claude-server/home/.claude/  *(ToFu: log-injection)*
- `famano/mcp-server-office::write_docx` — <class 'langchain_core.tools.base.ToolException'>[Errno 36] File name too long: '27952 Carla Viaduct Port Toddfort, IA 17566 6198 Deleon Motorway Lake Jocelyn, PA 52376 7  *(ToFu: path-traversal)*
- `movibe/memory-bank-mcp::write_memory_bank_file` — <class 'langchain_core.tools.base.ToolException'>Error writing file 2735 Deborah Bypass Lake Chrischester, MT 37904 614 Ashley Walks North Brandonville, NE 51911 5430 Cod  *(ToFu: path-traversal)*
- `newtype-01/obsidian-mcp::create_note` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: ENAMETOOLONG: name too long, open '/scratch/tofu/eval/targets_tf/newtype-01__obsidian-mcp/vau  *(ToFu: path-traversal)*
- `newtype-01/obsidian-mcp::manage_folder` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: ENAMETOOLONG: name too long, mkdir '/scratch/tofu/eval/targets_tf/newtype-01__obsidian-mcp/va  *(ToFu: path-traversal)*
- `openags/paper-search-mcp::download_hal` — <class 'langchain_core.tools.base.ToolException'>Error executing tool download_hal: [Errno 36] File name too long: '95458 Jessica Plains Jeffreybury, MA 66066 999 Ryan Ke  *(ToFu: path-traversal)*
- `openags/paper-search-mcp::download_scihub` — <class 'langchain_core.tools.base.ToolException'>Error executing tool download_scihub: [Errno 36] File name too long: '5744 Jason Ranch Suite 115 East Lori, FM 36759 9697  *(ToFu: path-traversal)*
- `openags/paper-search-mcp::read_hal_paper` — <class 'langchain_core.tools.base.ToolException'>Error executing tool read_hal_paper: [Errno 36] File name too long: '87692 Brown Walks New Amber, MH 95225 58344 Angel Vi  *(ToFu: path-traversal)*
- `thomasgazzoni/vsc-mcp::write_file` — <class 'langchain_core.tools.base.ToolException'>Error writing file: ENAMETOOLONG: name too long, open '/home/mza6485/toolfuzzer/eval/targets/thomasgazzoni__vsc-mcp/7837   *(ToFu: path-traversal)*

## Cost

- ToolFuzz real LLM calls: VM run **17,076** (tokens 15,163,984 in / 1,554,906 out, 1,307 cache hits) + merged PSU tools **4,621** (3,603,053 in / 367,140 out).
- Per completed tool: median 16, max 36 calls (cap 40, never hit).
- ToFu: 2 LLM steps per tool at initialisation (sanitizer selection + seeds), none while fuzzing.

## Configuration (recorded in every index row)

gpt-4.1-mini for every ToolFuzz LLM role (the authors used GPT-4o / GPT-4o-mini); 10 direct fuzz iterations;
≤ 3 failing inputs per error type, 1 agent prompt each; 1 correctness prompt set × 3 paraphrases; cap 40 calls
per tool; 600 s per tool; every target server in bwrap (filesystem read-only except its scratch + own dir,
own PID/IPC namespace). Two ToolFuzz bugs fixed (`PATCH (ToFu)`: literal braces in templates, array schema
without `items`), plus two harness artefacts (pydantic error recorded as a trigger; results appended across retries).

## Caveats for the paper

- **ToolFuzz's own correctness FDR is 46%** (Milev et al. 2025, Table 3: authors hand-checked every positive).
- The paper's "runtime detection has no false positives" holds for LangChain tools, where an error is a crash;
  MCP servers return errors as protocol replies, hence the ENV / REJECT / CRASH split above.
- ToolFuzz's taint-guided argument generation is in-process Python only; over MCP the server is a separate
  process, so it degrades to type-based Faker values.
- Budget-capped configuration (above) to keep cost small; ToFu's arm used gpt-4.1.
- Not tested: 7 unsafe repos by design (PhialsBasement/CMD-MCP-Server, SimonB97/win-cli-mcp-server, dnakov/frida-mcp, mobile-next/mobile-mcp, nickgnd/tmux-mcp, r-huijts/xcode-mcp-server, wonderwhy-er/ClaudeComputerCommander); servers ToolFuzz's MCP bridge could not load; 5 timeouts; 15 ToolFuzz internal errors.

