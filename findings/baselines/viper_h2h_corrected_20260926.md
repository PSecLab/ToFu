# Viper-MCP on the 45-repo H2H set — recounted from Viper's own output (2026-09-26)

**Supersedes** `viper_h2h_corrected_20260926.md` v1 (which wrongly said confirmed = 0) and the Viper column in
`head_to_head_per_repo_20260922.md` / RESULTS_SUMMARY §5. No re-run needed: every number below is recounted
from the existing run outputs (node: Monika VM; python: PSU PC, after the item-95 + console-script fixes).

## What Viper produces, per repo (three layers)
| layer | file | meaning |
|---|---|---|
| **static** | `codeql_output/*/report.json` `vulnerabilities` | Phase I CodeQL taint flows (candidates) |
| **sink hits** | `oracle.json`, lines with `sink != hook_init` | Phase II: the injected hook saw fuzz input reach a sink (e.g. `fs.writeFile`) |
| **confirmed** | `fuzz_results/*/triggered_vulnerability_prompts.json`, entries with `hit_judge.sink_reached && effect_success` | Viper's own hit judge confirmed the effect |

## Why the old numbers were wrong
- Old column = number of lines in `oracle.json` **including the `hook_init` marker**, so any repo where the hook merely
  loaded scored ≥ 1 (e.g. matlab 5 = 4 sink hits + hook_init). "Viper 23 of 35" = hook loaded, not findings.
- `run_viper.py` `n_hit_markers` searched result files for `"vulnerable": true` / `exploit_success`, strings Viper never
  writes, so it was 0 on every run. Confirmed verdicts live in `triggered_vulnerability_prompts.json` (fixed in run_viper).
- v1 of this file then read the zero as "Viper confirmed nothing" — wrong: 2 repos are confirmed.

| repo | lang | confirmed (distinct vulns) | sink hits | static flows | hook | old column |
|---|---|---|---|---|---|---|
| movibe/memory-bank-mcp | node | **8** (1: initialize_memory_bank -> path_traversal@19) | 5 | 6 | True | 6 |
| openags/paper-search-mcp | python | **1** (1: arxivsearcher.download_pdf -> path_traversal@84) | 0 | 35 | False | na |
| WilliamCloudQi/matlab-mcp-server | node | 0 | 4 | 4 | True | 5 |
| AminForou/mcp-gsc | python | 0 | 3 | 0 | True | na |
| joshrutkowski/applescript-mcp | node | 0 | 3 | 0 | True | 4 |
| 34892002/bilibili-mcp-js | node | 0 | 2 | 0 | True | 3 |
| aaronjmars/web3-research-mcp | node | 0 | 2 | 0 | True | 3 |
| pixelsock/directus-mcp | node | 0 | 1 | 18 | True | 2 |
| PhialsBasement/CMD-MCP-Server | node | 0 | 1 | 0 | True | 2 |
| jinzcdev/leetcode-mcp-server | node | 0 | 1 | 0 | True | 2 |
| newtype-01/obsidian-mcp | node | 0 | 0 | 41 | False | 1 |
| Sheshiyer/framer-plugin-mcp | node | 0 | 0 | 16 | True | 1 |
| dazeb/Cline-Memory-Bank | node | 0 | 0 | 11 | False | 0 |
| dazeb/cline-mcp-memory-bank | node | 0 | 0 | 11 | False | 0 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | 0 | 0 | 5 | True | 1 |
| davidteren/claude-server | node | 0 | 0 | 5 | True | 1 |
| sworddut/mcp-ffmpeg-helper | node | 0 | 0 | 2 | True | 1 |
| Antonytm/mcp-sitecore-server | node | 0 | 0 | 0 | False | 0 |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | node | 0 | 0 | 0 | True | 1 |
| AzDeltaQQ/Mcp-Reasoning-Server | node | 0 | 0 | 0 | True | 1 |
| Jacck/mcp-reasoner | node | 0 | 0 | 0 | True | 3 |
| ProgramComputer/NASA-MCP-server | node | 0 | 0 | 0 | True | 1 |
| RegiByte/todo-list-mcp | node | 0 | 0 | 0 | False | 0 |
| StevenStavrakis/mcp-starter-template | node | 0 | 0 | 0 | False | 0 |
| T1nker-1220/memories-with-lessons-mcp-server | node | 0 | 0 | 0 | True | 1 |
| Tisik79/MCP-Facebook | node | 0 | 0 | 0 | False | 0 |
| alaturqua/mcp-trino-python | python | 0 | 0 | 0 | True | na |
| alioshr/memory-bank-mcp | node | 0 | 0 | 0 | True | 1 |
| aliyun/alibabacloud-dms-mcp-server | python | 0 | 0 | 0 | False | na |
| antvis/mcp-server-chart | node | 0 | 0 | 0 | False | 1 |
| bradrisse/kanban-mcp | node | 0 | 0 | 0 | True | 2 |
| doggybee/mcp-server-ccxt | node | 0 | 0 | 0 | False | 0 |
| fireproof-storage/mcp-database-server | node | 0 | 0 | 0 | True | 1 |
| gdli6177/mcp-prompt-server | node | 0 | 0 | 0 | True | 1 |
| graphlit/graphlit-mcp-server | node | 0 | 0 | 0 | False | 0 |
| maoxiaoke/mcp-media-processor | node | 0 | 0 | 0 | False | 0 |
| meilisearch/meilisearch-mcp | python | 0 | 0 | 0 | False | na |
| neka-nat/freecad-mcp | python | 0 | 0 | 0 | False | na |
| ocean-zhc/dolphinscheduler-mcp | python | 0 | 0 | 0 | False | na |
| prathammanocha/wordpress-mcp-server | node | 0 | 0 | 0 | False | 0 |
| revit-mcp/revit-mcp | node | 0 | 0 | 0 | False | 0 |
| rishijatia/fantasy-pl-mcp | python | 0 | 0 | 0 | False | na |
| taylorwilsdon/google_workspace_mcp | python | 0 | 0 | 0 | False | na |
| vinayak-mehta/mcp-browser-use | python | 0 | 0 | 0 | False | na |
| yokingma/time-mcp | node | 0 | 0 | 0 | False | 0 |

## Tally (45 repos: 35 node + 10 python)
| metric | repos |
|---|---|
| **confirmed by Viper's hit judge** | **2** (node 1, python 1); 2 distinct vulns |
| runtime sink hits > 0 | 9 |
| static taint flows > 0 | 11 |
| hook loaded | 23 |

## Reading for the paper
- Report Viper as three numbers: static 11/45, runtime sink hits 9/45, confirmed 2/45.
- Both confirmed repos are also ToFu-flagged (memory-bank-mcp: path traversal via initialize_memory_bank; paper-search).
- hook=False repos: the server could not start (missing backend/credentials); Phase II could not run there — same condition on node and python.
