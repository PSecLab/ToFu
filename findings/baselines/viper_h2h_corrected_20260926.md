# Viper-MCP on the 45-repo H2H set — corrected (2026-09-26)

**Supersedes the Viper column in `head_to_head_per_repo_20260922.md` / RESULTS_SUMMARY §5.**
That column used the fallback `n_hit_markers or n_oracle_events_on_disk or max_oracle_hits_in_round`.
`n_hit_markers` (Viper's own confirmed verdicts: `"vulnerable": true` / `exploit_success`) is **0 on every run**,
so the column silently fell through to `max_oracle_hits_in_round` — the hit judge's `oracle_hits=N`, which is
~10 × the number of tool calls the hook observed in a round (meilisearch: 1 call→10, 4→40, 7→70). That is
**runtime activity, not findings**. The old "Viper 23 of 35" = repos with hook activity.

Columns now reported separately:
- **static** — Phase I CodeQL taint flows in `report.json` (Viper's static stage)
- **confirmed** — Phase II exploits Viper itself confirmed (`n_hit_markers`)
- **activity** — max `oracle_hits` in a round (hook observed tool calls; NOT a finding count)
- **hook** — whether Viper's runtime hook was injected (Phase II can only observe when True)

Python rows: PSU PC, 2026-09-26, after the item-95 query fix (5df1e2a) and the console-script launch fix (8e144a6),
10 rounds, gpt-4.1 temp 0, bwrap-sandboxed, LLM record/replay cache. Node rows: Monika VM H2H run (10 rounds).

| repo | lang | static flows | confirmed | activity | hook | old column |
|---|---|---|---|---|---|---|
| newtype-01/obsidian-mcp | node | 41 | 0 | 1 | True | 1 |
| openags/paper-search-mcp | python | 35 | 0 | 4 | True | na |
| pixelsock/directus-mcp | node | 18 | 0 | 1 | True | 2 |
| Sheshiyer/framer-plugin-mcp | node | 16 | 0 | 0 | True | 1 |
| dazeb/Cline-Memory-Bank | node | 11 | 0 | 0 | False | 0 |
| dazeb/cline-mcp-memory-bank | node | 11 | 0 | 0 | False | 0 |
| movibe/memory-bank-mcp | node | 6 | 0 | 5 | True | 6 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | 5 | 0 | 0 | True | 1 |
| davidteren/claude-server | node | 5 | 0 | 0 | True | 1 |
| WilliamCloudQi/matlab-mcp-server | node | 4 | 0 | 7 | True | 5 |
| sworddut/mcp-ffmpeg-helper | node | 2 | 0 | 0 | True | 1 |
| 34892002/bilibili-mcp-js | node | 0 | 0 | 2 | True | 3 |
| AminForou/mcp-gsc | python | 0 | 0 | 3 | True | na |
| Antonytm/mcp-sitecore-server | node | 0 | 0 | 0 | False | 0 |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | node | 0 | 0 | 1 | True | 1 |
| AzDeltaQQ/Mcp-Reasoning-Server | node | 0 | 0 | 0 | True | 1 |
| Jacck/mcp-reasoner | node | 0 | 0 | 0 | True | 3 |
| PhialsBasement/CMD-MCP-Server | node | 0 | 0 | 1 | True | 2 |
| ProgramComputer/NASA-MCP-server | node | 0 | 0 | 0 | True | 1 |
| RegiByte/todo-list-mcp | node | 0 | 0 | 0 | False | 0 |
| StevenStavrakis/mcp-starter-template | node | 0 | 0 | 0 | False | 0 |
| T1nker-1220/memories-with-lessons-mcp-server | node | 0 | 0 | 0 | True | 1 |
| Tisik79/MCP-Facebook | node | 0 | 0 | 0 | False | 0 |
| aaronjmars/web3-research-mcp | node | 0 | 0 | 6 | True | 3 |
| alaturqua/mcp-trino-python | python | 0 | 0 | 0 | True | na |
| alioshr/memory-bank-mcp | node | 0 | 0 | 0 | True | 1 |
| aliyun/alibabacloud-dms-mcp-server | python | 0 | 0 | 0 | False | na |
| antvis/mcp-server-chart | node | 0 | 0 | 1 | True | 1 |
| bradrisse/kanban-mcp | node | 0 | 0 | 0 | True | 2 |
| doggybee/mcp-server-ccxt | node | 0 | 0 | 0 | False | 0 |
| fireproof-storage/mcp-database-server | node | 0 | 0 | 0 | True | 1 |
| gdli6177/mcp-prompt-server | node | 0 | 0 | 0 | True | 1 |
| graphlit/graphlit-mcp-server | node | 0 | 0 | 0 | False | 0 |
| jinzcdev/leetcode-mcp-server | node | 0 | 0 | 1 | True | 2 |
| joshrutkowski/applescript-mcp | node | 0 | 0 | 3 | True | 4 |
| maoxiaoke/mcp-media-processor | node | 0 | 0 | 0 | False | 0 |
| meilisearch/meilisearch-mcp | python | 0 | 0 | 70 | True | na |
| neka-nat/freecad-mcp | python | 0 | 0 | 0 | False | na |
| ocean-zhc/dolphinscheduler-mcp | python | 0 | 0 | 0 | False | na |
| prathammanocha/wordpress-mcp-server | node | 0 | 0 | 0 | False | 0 |
| revit-mcp/revit-mcp | node | 0 | 0 | 0 | False | 0 |
| rishijatia/fantasy-pl-mcp | python | 0 | 0 | 0 | False | na |
| taylorwilsdon/google_workspace_mcp | python | 0 | 0 | 0 | False | na |
| vinayak-mehta/mcp-browser-use | python | 0 | 0 | 4 | True | na |
| yokingma/time-mcp | node | 0 | 0 | 0 | False | 0 |

## Tally
| | value |
|---|---|
| repos with a Viper row | 45 of 45 (35 node, 10 python) |
| **static flows > 0** | **11** (node 10, python 1) |
| **confirmed exploits > 0** | **0** |
| activity > 0 (old column's basis) | 15 |
| hook injected | 28 |

## Reading
- Viper's **dynamic** stage confirmed **no** exploit on any H2H repo. Its **static** stage flags taint flows on
  11 repos. Compare ToFu against Viper-static (a candidate count, like ToFu's) and report
  Viper-confirmed = 0 separately; do not use the activity counter as findings.
- Python hooks still False on repos whose servers need an external backend/credentials and exit early
  (their Phase II could not run); static results for them are still valid.
- Sources: PC `eval/state/viper_runs.jsonl` + `eval/viper_runs/*/codeql_output/*/report.json`; VM same paths.
