# Head-to-head shortlist (2026-09-20) -- ToFu-dominant, all classes, bug-count stratified

ToFu bug-count per repo vs CodeQL+Cisco on the same repo. beast = tofu - (codeql+cisco).
Selected 45: Viper-runnable (node) 35, Cisco all 45.

| repo | lang | tofu | codeql | cisco | beast | bucket | classes |
|---|---|---|---|---|---|---|---|
| Antonytm/mcp-sitecore-server | node | 86 | 4 | 7 | 75 | hi(10+) |  |
| antvis/mcp-server-chart | node | 25 | 3 | 0 | 22 | hi(10+) |  |
| maoxiaoke/mcp-media-processor | node | 10 | 0 | 0 | 10 | hi(10+) | path:10 |
| prathammanocha/wordpress-mcp-server | node | 10 | 0 | 0 | 10 | hi(10+) | ssrf:10 |
| Tisik79/MCP-Facebook | node | 18 | 28 | 0 | -10 | hi(10+) | log:2,path:2 |
| graphlit/graphlit-mcp-server | node | 9 | 0 | 0 | 9 | mid(3-9) |  |
| sworddut/mcp-ffmpeg-helper | node | 8 | 0 | 0 | 8 | mid(3-9) | path:8 |
| pixelsock/directus-mcp | node | 9 | 1 | 0 | 8 | mid(3-9) | ssrf:7 |
| bradrisse/kanban-mcp | node | 6 | 0 | 0 | 6 | mid(3-9) |  |
| jinzcdev/leetcode-mcp-server | node | 5 | 0 | 0 | 5 | mid(3-9) | log:3 |
| ProgramComputer/NASA-MCP-server | node | 5 | 1 | 0 | 4 | mid(3-9) |  |
| alioshr/memory-bank-mcp | node | 4 | 0 | 0 | 4 | mid(3-9) |  |
| dazeb/Cline-Memory-Bank | node | 4 | 0 | 0 | 4 | mid(3-9) | path:4 |
| dazeb/cline-mcp-memory-bank | node | 4 | 0 | 0 | 4 | mid(3-9) | path:4 |
| joshrutkowski/applescript-mcp | node | 6 | 2 | 0 | 4 | mid(3-9) | cmd:1,path:2 |
| movibe/memory-bank-mcp | node | 5 | 1 | 0 | 4 | mid(3-9) | log:1,path:4 |
| newtype-01/obsidian-mcp | node | 5 | 1 | 0 | 4 | mid(3-9) | path:5 |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | node | 4 | 0 | 0 | 4 | mid(3-9) | creds:1 |
| fireproof-storage/mcp-database-server | node | 4 | 0 | 0 | 4 | mid(3-9) |  |
| doggybee/mcp-server-ccxt | node | 3 | 0 | 0 | 3 | mid(3-9) |  |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | 2 | 0 | 0 | 2 | lo(1-2) | path:2 |
| PhialsBasement/CMD-MCP-Server | node | 2 | 0 | 0 | 2 | lo(1-2) | cmd:1 |
| davidteren/claude-server | node | 2 | 0 | 0 | 2 | lo(1-2) | log:2 |
| gdli6177/mcp-prompt-server | node | 2 | 0 | 0 | 2 | lo(1-2) |  |
| revit-mcp/revit-mcp | node | 2 | 0 | 0 | 2 | lo(1-2) | log:1,path:1 |
| yokingma/time-mcp | node | 2 | 0 | 0 | 2 | lo(1-2) |  |
| AzDeltaQQ/Mcp-Reasoning-Server | node | 2 | 0 | 0 | 2 | lo(1-2) |  |
| 34892002/bilibili-mcp-js | node | 1 | 0 | 0 | 1 | lo(1-2) |  |
| Jacck/mcp-reasoner | node | 1 | 0 | 0 | 1 | lo(1-2) |  |
| RegiByte/todo-list-mcp | node | 1 | 0 | 0 | 1 | lo(1-2) | log:1 |
| Sheshiyer/framer-plugin-mcp | node | 1 | 0 | 0 | 1 | lo(1-2) | path:1 |
| StevenStavrakis/mcp-starter-template | node | 1 | 0 | 0 | 1 | lo(1-2) |  |
| T1nker-1220/memories-with-lessons-mcp-server | node | 1 | 0 | 0 | 1 | lo(1-2) | creds:1 |
| WilliamCloudQi/matlab-mcp-server | node | 1 | 0 | 0 | 1 | lo(1-2) | path:1 |
| aaronjmars/web3-research-mcp | node | 1 | 0 | 0 | 1 | lo(1-2) |  |
| ocean-zhc/dolphinscheduler-mcp | python | 72 | 2 | 0 | 70 | hi(10+) | log:1,ssrf:68,temp:26 |
| taylorwilsdon/google_workspace_mcp | python | 105 | 59 | 5 | 41 | hi(10+) |  |
| openags/paper-search-mcp | python | 35 | 9 | 0 | 26 | hi(10+) | path:17,ssrf:4,temp:19 |
| meilisearch/meilisearch-mcp | python | 24 | 0 | 0 | 24 | hi(10+) | ssrf:24 |
| alaturqua/mcp-trino-python | python | 19 | 0 | 0 | 19 | hi(10+) | ssrf:19,temp:14 |
| aliyun/alibabacloud-dms-mcp-server | python | 16 | 0 | 1 | 15 | hi(10+) | temp:11 |
| neka-nat/freecad-mcp | python | 15 | 0 | 0 | 15 | hi(10+) | path:1,ssrf:15,temp:1 |
| AminForou/mcp-gsc | python | 14 | 0 | 0 | 14 | hi(10+) | ssrf:13,temp:2 |
| vinayak-mehta/mcp-browser-use | python | 14 | 0 | 0 | 14 | hi(10+) | temp:7 |
| rishijatia/fantasy-pl-mcp | python | 13 | 0 | 0 | 13 | hi(10+) | temp:2 |
