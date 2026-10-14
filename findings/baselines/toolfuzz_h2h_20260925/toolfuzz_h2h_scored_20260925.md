# ToolFuzz vs ToFu — scored with ToolFuzz's own criteria

Tools with a completed ToolFuzz run: **298** in 31 repos; also run by ToFu: **298** (comparison set).

## Runtime-failure triggers by class (all ToolFuzz triggers, before dedup)
| class | triggers | meaning |
|---|---|---|
| HARNESS | 0 | ToolFuzz/bridge bug, not the tool |
| ENV | 36 | backend/cred/network unavailable |
| REJECT | 6 | tool correctly refused input |
| CRASH | 8 | unhandled internal exception (real bug) |
| UNCLASS | 1 | unclassified — manual review, not counted |

## Tool-level results on the comparison set (tools both tools ran)
| axis | ToolFuzz tools flagged | ToFu tools flagged | both |
|---|---|---|---|
| robustness (ToolFuzz CRASH vs ToFu crash/exhaustion hits) | 8 | 55 | 1 |
| security (ToFu triaged classes; ToolFuzz has no security oracle) | — | 125 | — |
| functional correctness (ToolFuzz formula; ToFu has no such oracle) | 35 | — | — |
| ↳ same, tool actually executed (outputs not backend/harness errors) | 0 | — | — |
| ToolFuzz runtime, its own definition minus HARNESS (incl. ENV/REJECT) | 51 | — | — |

ToFu security-flagged tools that ToolFuzz flagged for *anything*: **16 / 125**; of those, as a genuine crash: 8.

ToolFuzz real LLM calls per tool (this configuration): median 16, mean 15.6, total 4655 over 298 tools. ToFu: 2 LLM steps per tool at initialisation (sanitizer selection + seeds), none while fuzzing.

## Per repo
| repo | tools | tf_runtime | tf_crash | tf_correct | tofu_sec | tofu_rob |
|---|---|---|---|---|---|---|
| openags/paper-search-mcp | 36 | 3 | 3 | 0 | 26 | 14 |
| neka-nat/freecad-mcp | 14 | 0 | 0 | 0 | 14 | 2 |
| AminForou/mcp-gsc | 18 | 0 | 0 | 0 | 13 | 1 |
| maoxiaoke/mcp-media-processor | 10 | 0 | 0 | 0 | 10 | 0 |
| ocean-zhc/dolphinscheduler-mcp | 11 | 0 | 0 | 0 | 9 | 0 |
| sworddut/mcp-ffmpeg-helper | 8 | 0 | 0 | 0 | 8 | 0 |
| pixelsock/directus-mcp | 14 | 0 | 0 | 0 | 7 | 6 |
| Tisik79/MCP-Facebook | 39 | 0 | 0 | 1 | 6 | 14 |
| newtype-01/obsidian-mcp | 8 | 4 | 2 | 1 | 5 | 1 |
| movibe/memory-bank-mcp | 13 | 3 | 1 | 2 | 5 | 0 |
| dazeb/Cline-Memory-Bank | 4 | 0 | 0 | 1 | 4 | 1 |
| jinzcdev/leetcode-mcp-server | 8 | 0 | 0 | 0 | 3 | 2 |
| joshrutkowski/applescript-mcp | 33 | 32 | 0 | 29 | 3 | 0 |
| davidteren/claude-server | 3 | 2 | 1 | 0 | 2 | 2 |
| meilisearch/meilisearch-mcp | 3 | 0 | 0 | 0 | 2 | 0 |
| vinayak-mehta/mcp-browser-use | 3 | 0 | 0 | 0 | 2 | 1 |
| aliyun/alibabacloud-dms-mcp-server | 1 | 0 | 0 | 0 | 1 | 0 |
| RegiByte/todo-list-mcp | 6 | 0 | 0 | 0 | 1 | 0 |
| WilliamCloudQi/matlab-mcp-server | 1 | 0 | 0 | 0 | 1 | 0 |
| Sheshiyer/framer-plugin-mcp | 1 | 1 | 1 | 0 | 1 | 0 |
| T1nker-1220/memories-with-lessons-mcp-server | 5 | 1 | 0 | 1 | 1 | 0 |
| revit-mcp/revit-mcp | 24 | 1 | 0 | 0 | 1 | 1 |
| Antonytm/mcp-sitecore-server | 1 | 0 | 0 | 0 | 0 | 0 |
| 34892002/bilibili-mcp-js | 1 | 0 | 0 | 0 | 0 | 0 |
| gdli6177/mcp-prompt-server | 9 | 0 | 0 | 0 | 0 | 2 |
| fireproof-storage/mcp-database-server | 3 | 0 | 0 | 0 | 0 | 3 |
| Jacck/mcp-reasoner | 1 | 1 | 0 | 0 | 0 | 1 |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | 6 | 3 | 0 | 0 | 0 | 1 |
| StevenStavrakis/mcp-starter-template | 1 | 0 | 0 | 0 | 0 | 1 |
| doggybee/mcp-server-ccxt | 8 | 0 | 0 | 0 | 0 | 0 |
| yokingma/time-mcp | 5 | 0 | 0 | 0 | 0 | 2 |

## ToolFuzz CRASH findings (for manual confirmation)

- `davidteren/claude-server::save_conversation_context` — <class 'langchain_core.tools.base.ToolException'>McpError: ENAMETOOLONG: name too long, open '/scratch/tofu/.tofu_scratch/toolfuzz/davidteren__claude-server/home/.claude/contexts/078 Andersen Parkways
- `newtype-01/obsidian-mcp::create_note` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: ENAMETOOLONG: name too long, open '/scratch/tofu/eval/targets_tf/newtype-01__obsidian-mcp/vault/2290 Johnny Valley Jennifer
- `newtype-01/obsidian-mcp::manage_folder` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: ENAMETOOLONG: name too long, mkdir '/scratch/tofu/eval/targets_tf/newtype-01__obsidian-mcp/vault/4019 Renee Streets Apt. 75
- `openags/paper-search-mcp::download_scihub` — <class 'langchain_core.tools.base.ToolException'>Error executing tool download_scihub: [Errno 36] File name too long: '5744 Jason Ranch Suite 115 East Lori, FM 36759 96970 Anthony Cape Apt. 434 Carolf
- `openags/paper-search-mcp::read_hal_paper` — <class 'langchain_core.tools.base.ToolException'>Error executing tool read_hal_paper: [Errno 36] File name too long: '87692 Brown Walks New Amber, MH 95225 58344 Angel View Suite 385 Josephburgh, AS 3
- `openags/paper-search-mcp::download_hal` — <class 'langchain_core.tools.base.ToolException'>Error executing tool download_hal: [Errno 36] File name too long: '95458 Jessica Plains Jeffreybury, MA 66066 999 Ryan Key Apt. 595 East Andrea, NJ 859
- `movibe/memory-bank-mcp::write_memory_bank_file` — <class 'langchain_core.tools.base.ToolException'>Error writing file 2735 Deborah Bypass Lake Chrischester, MT 37904 614 Ashley Walks North Brandonville, NE 51911 5430 Cody Path Suite 627 Michelleburgh
- `Sheshiyer/framer-plugin-mcp::create_plugin` — <class 'langchain_core.tools.base.ToolException'>McpError: MCP error -32603: Failed to create plugin: ENAMETOOLONG: name too long, mkdir '/scratch/tofu/eval/targets_tf/Sheshiyer__framer-plugin-mcp/624

## UNCLASS triggers (1, not counted) — sample

- `Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server::advanced_search` — <class 'langchain_core.tools.base.ToolException'>Error executing tool advanced_search: MCP error -32603: Failed to perform advanced search: Request failed with status code 400
