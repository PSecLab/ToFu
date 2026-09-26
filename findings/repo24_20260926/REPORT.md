# repo24 — per-repository deep fuzzing (24 worker-h budget, saturation stop) — 2026-09-26

RQ4 source of truth. Every number here is recomputed by `analyze_rq4.py` from the
files in this directory (and `findings/baselines/tofu_runs_e2_20260922.jsonl` for
the 60 s corpus comparison). Candidates are auto-triaged (`eval/triage_findings.py`),
**unconfirmed**, mandatory sanitizer layer not subtracted — same status as the 627.

## Protocol (report exactly this — do not write "fuzzed for 24 h")
- **Budget:** 24 worker-hours per repository on one core; repositories run in parallel.
- **Scheduling:** a repo's reachable tools (≥1 successful exec in the corpus run) are
  fuzzed in round-robin 70-min slices; each slice resumes from the tool's saved corpus.
- **Saturation:** a tool is saturated after 1 h of its own fuzz time with no new
  coverage edge **and** no new finding signature (new triggered-sanitizer set).
  A repo stops when all tools are saturated/dead (`all_saturated`) or the budget is
  spent (`budget_exhausted`). Hours actually used are recorded per repo.
- **Settings:** gpt-4.1, temperature 0, seed 20260910; LLM replay cache;
  `TOFU_REQUIRE_LLM_SEEDS=1` (cached seeds only if tagged `llm`, else live, else the
  tool ends `no_llm_seeds`); fail-fast after 5000 successless execs;
  **bubblewrap sandbox** per fuzzer (`/` read-only, private `/tmp`, private `$HOME`,
  only the config's own dirs writable); findings timeline on.
- **Machines:** Monika VM (5 vCPU) ran `repo24` = top-10 repos by coverage momentum;
  Ananto PSU PC (12 workers) ran `repo24-b` = the next 24 (3 code-execution targets
  excluded). Code: `new_eval` at 7ba41b3 (+ 5a431e2, todo only).
- **Earlier attempts are quarantined, not evidence** (each has a `WHY.md`):
  `quarantine-2026-09-24-repo24-obsidian-wipe` (unsandboxed; obsidian-mcp deleted
  harness files), `…-repo24-prehome`, `…-repo24b-bwrap-uidmap` (sandbox could not
  start on the PC; tools falsely marked dead), `…-repo24b-failfast500`.

## Headline
| | repos | stop: saturated / budget | tools: saturated / budget / dead | worker-h used / budgeted | candidates (hi-conf) |
|---|---|---|---|---|---|
| VM `repo24` | 10 | 6 / 4 | 85 / 56 / 21 (of 162) | 136 / 240 | 29 (23) in 6 repos |
| PC `repo24-b` | 24 | 20 / 4 | 140 / 87 / 9 (of 236) | 272 / 576 | 100 (75) in 17 repos |
| **total** | **34** | **26 / 8** | 225 / 143 / 30 (of 398) | **408 / 816** | **129 (98)** |

Classes — VM: path-traversal 21, reflected-xss 4, log-injection 2, data-exfiltration 2.
PC: reflected-xss 73, log-injection 18, path-traversal 8, data-exfiltration 1.

## RQ4 — what did the long budget add?
Compared per (repo, tool, class) with the 60 s corpus run on the same repos:

| | repo24 candidates | also in 60 s corpus | **new** | corpus-only |
|---|---|---|---|---|
| VM | 29 | 23 | **6** | 47 |
| PC | 100 | 42 | **58** | 12 |

**The 64 "new" are not a budget effect.** 63 of 64 are reflected-xss or
data-exfiltration — the two oracles added *after* the corpus run
(`check_reflected_output`, `check_introspection_exfil`). 44 of 64 first appeared within
the first 60 s of fuzzing, so the corpus run would have caught them had those oracles
existed. **Only 1 new candidate is attributable to budget alone under unchanged
oracles:** `bradrisse/kanban-mcp::mcp_kanban_comment_manager` (log-injection).
→ The oracle extension is the C4 result; the budget is not.

**Bugs surface early.** Time on the stitched tool clock at which each (tool, class)
first appeared:

| | first appearances | median | p90 | ≤ 60 s | > 1 h |
|---|---|---|---|---|---|
| VM | 48 | 0.1 min | 2.6 min | 41 | 0 |
| PC | 109 | 0.2 min | 10.6 min | 75 | 2 |

116 of 157 (74%) within the first minute; 2 of 157 after an hour. Reading for the
paper: once the oracles can see a bug, a short budget finds it; 24 h mostly confirms
saturation (26 of 34 repos saturated, half the budget unused).

## Open item — corpus-only candidates (59)
Found in the 60 s corpus run but not in repo24. VM: insecure-temp-file 27,
log-injection 14, path-traversal 5, hardcoded-creds 1. PC: path-traversal 5,
insecure-temp-file 3, log-injection 3, ssrf 1. Their repo24 tool status: saturated
12, budget 18, dead 14, not in repo24 at all 15 (tool had 0 successes in the corpus
run, so it was excluded as unreachable).
**Unverified hypothesis:** the corpus run shared one `/tmp` across 5 concurrent
configs, so some temp-file "leaks" belonged to other configs; the sandbox's private
`/tmp` removes them. Decision (Ananto, 2026-09-26): do not verify separately — a
sandboxed 60 s corpus re-run settles it and puts both runs on identical oracles.

## Exclusions / limits to state
- `dead` tools (30) = unreachable in isolation (stateful: need data another tool
  creates) or fail-fast; not evidence of a clean tool.
- One trial per repo. Sandbox blocks writes but allows reads anywhere (e.g.
  file-context-server `read_context` read a harness file) — tighten before the next run.

## Re-run estimate (60 s budget, sandboxed), from the corpus run's own timings
Corpus configs at 60 s took 78.4 s wall on average (median 69.3 s, p90 119.3 s,
304 timeouts), with **no** LLM cache hits; a re-run replays the cache, so expect
somewhat less.

| scope | configs | worker-h | PC (12 workers) | VM (5 workers) |
|---|---|---|---|---|
| full corpus | 6,153 | ~134 | **~11 h** | ~27 h |
| reachable only (≥1 success) | 1,410 | ~36 | ~3 h | ~7 h |

## Files
| file | what |
|---|---|
| `runs.<arm>.jsonl` | one row per slice (the run index) |
| `repo24_results.<arm>.jsonl` | one row per repo: budget, hours used, stop reason, per-tool status |
| `repo24_state.<arm>.json.gz` | scheduler ledger at finish |
| `stitched_timelines.<arm>.tgz` | per-tool coverage + findings over cumulative tool time |
| `analyze_rq4.py` | regenerates every number above |

Slice logs (15 GB, gitignored) are on the machines (`~/toolfuzzer/eval/runs/repo24`,
`/scratch/tofu/eval/runs/repo24-b`) and on Ananto's laptop at
`~/pseclab/ToFu_repo24_results/{vm,pc}/eval/runs/`.

## Per-repo
| machine | repo | lang | tools | worker-h | fuzz-h | stop | sat / budget / dead | candidates (hi) | new vs 60s corpus |
|---|---|---|---|---|---|---|---|---|---|
| VM | ProgramComputer/NASA-MCP-server | node | 23 | 24.0 | 23.93 | budget_exhausted | 13 / 10 / 0 | 0 (0) | 0 |
| VM | openags/paper-search-mcp | python | 36 | 24.0 | 23.92 | budget_exhausted | 11 / 25 / 0 | 19 (19) | 4 |
| VM | Vortiago/mcp-outline | python | 37 | 24.0 | 23.97 | budget_exhausted | 20 / 17 / 0 | 0 (0) | 0 |
| VM | revit-mcp/revit-mcp | node | 24 | 24.0 | 23.94 | budget_exhausted | 20 / 4 / 0 | 1 (1) | 0 |
| VM | bsmi021/mcp-file-context-server | node | 5 | 15.21 | 15.17 | all_saturated | 5 / 0 / 0 | 3 (1) | 0 |
| VM | CodeLogicIncEngineering/codelogic-mcp-server | python | 8 | 9.35 | 9.33 | all_saturated | 8 / 0 / 0 | 1 (1) | 1 |
| VM | blazickjp/arxiv-mcp-server | python | 7 | 7.13 | 7.11 | all_saturated | 5 / 0 / 2 | 2 (1) | 1 |
| VM | newtype-01/obsidian-mcp | node | 8 | 5.91 | 5.87 | all_saturated | 3 / 0 / 5 | 3 (0) | 0 |
| VM | T1nker-1220/memories-with-lessons-mcp-server | node | 5 | 2.1 | 2.07 | all_saturated | 0 / 0 / 5 | 0 (0) | 0 |
| VM | aurda012/cursor10x-mcp | node | 9 | 0.78 | 0.73 | all_saturated | 0 / 0 / 9 | 0 (0) | 0 |
| PC | CheMiguel23/MemoryMesh | node | 21 | 24.0 | 23.95 | budget_exhausted | 8 / 13 / 0 | 14 (11) | 0 |
| PC | kukapay/crypto-indicators-mcp | node | 78 | 24.0 | 23.95 | budget_exhausted | 19 / 59 / 0 | 21 (21) | 21 |
| PC | aviveldan/datagov-mcp | python | 13 | 24.0 | 23.95 | budget_exhausted | 9 / 4 / 0 | 13 (13) | 0 |
| PC | rishijatia/fantasy-pl-mcp | python | 19 | 24.0 | 23.92 | budget_exhausted | 8 / 11 / 0 | 6 (5) | 6 |
| PC | baranwang/mcp-trends-hub | node | 12 | 23.38 | 23.33 | all_saturated | 12 / 0 / 0 | 0 (0) | 0 |
| PC | cdugo/package-documentation-mcp | node | 3 | 16.36 | 16.33 | all_saturated | 3 / 0 / 0 | 3 (2) | 3 |
| PC | PuroDelphi/mcpFirebird | node | 9 | 14.02 | 14.0 | all_saturated | 9 / 0 / 0 | 4 (2) | 2 |
| PC | aaronjmars/web3-research-mcp | node | 6 | 12.85 | 12.83 | all_saturated | 6 / 0 / 0 | 4 (3) | 4 |
| PC | openSVM/zig-mcp-server | node | 7 | 11.68 | 11.67 | all_saturated | 7 / 0 / 0 | 4 (4) | 4 |
| PC | antoinebou12/uml-mcp | python | 5 | 11.68 | 11.67 | all_saturated | 5 / 0 / 0 | 5 (2) | 0 |
| PC | ddukbg/github-enterprise-mcp | node | 7 | 11.68 | 11.67 | all_saturated | 7 / 0 / 0 | 3 (1) | 2 |
| PC | hijaz/postmancer | node | 6 | 10.52 | 10.5 | all_saturated | 6 / 0 / 0 | 5 (5) | 5 |
| PC | AzDeltaQQ/Mcp-Reasoning-Server | node | 8 | 10.51 | 10.5 | all_saturated | 8 / 0 / 0 | 8 (5) | 8 |
| PC | bradrisse/kanban-mcp | node | 7 | 9.35 | 9.33 | all_saturated | 7 / 0 / 0 | 2 (0) | 2 |
| PC | dazeb/cline-mcp-memory-bank | node | 4 | 7.01 | 7.0 | all_saturated | 4 / 0 / 0 | 4 (0) | 0 |
| PC | Selenium39/mcp-server-weibo | node | 3 | 5.85 | 5.83 | all_saturated | 3 / 0 / 0 | 0 (0) | 0 |
| PC | obra/private-journal-mcp | node | 4 | 5.85 | 5.83 | all_saturated | 4 / 0 / 0 | 0 (0) | 0 |
| PC | IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | 4 | 5.84 | 5.83 | all_saturated | 4 / 0 / 0 | 2 (0) | 0 |
| PC | Pimzino/agentic-tools-mcp | node | 9 | 4.96 | 4.93 | all_saturated | 3 / 0 / 6 | 1 (0) | 0 |
| PC | baranwang/mcp-tung-shing | node | 1 | 4.67 | 4.67 | all_saturated | 1 / 0 / 0 | 0 (0) | 0 |
| PC | arabold/docs-mcp-server | node | 4 | 2.52 | 2.51 | all_saturated | 2 / 0 / 2 | 0 (0) | 0 |
| PC | nickclyde/duckduckgo-mcp-server | python | 3 | 2.49 | 2.48 | all_saturated | 2 / 0 / 1 | 1 (1) | 1 |
| PC | jinzcdev/markmap-mcp-server | node | 2 | 2.34 | 2.33 | all_saturated | 2 / 0 / 0 | 0 (0) | 0 |
| PC | Coding-Solo/godot-mcp | node | 1 | 2.34 | 2.33 | all_saturated | 1 / 0 / 0 | 0 (0) | 0 |
