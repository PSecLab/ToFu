# Head-to-head, per repo — 45 ToFu-flagged repos — 2026-09-22

Every tool run on the **same 45 repos** (the head-to-head shortlist, `Benchmarks/extraction/head2head_cisco.txt`). Rows sorted by ToFu candidate count. This is the repo-level detail behind RESULTS_SUMMARY.md §5.

> **Units differ — do NOT read across a row as a leaderboard.** Each column answers a different question; the table shows *where each tool fires*, not which is "better".

| column | meaning | axis |
|---|---|---|
| **ToFu** | triaged silent-bug candidates (distinct tool×class); `(hi)` = high-conf succ≥0.5 | runtime oracle |
| **CodeQL** | security-extended rule matches | static SAST |
| **Cisco** | MCP-Scanner YARA + LLM analyzer findings | static metadata + LLM |
| **Viper** | Phase-II oracle hit-markers; `n/a` = python (Viper is node-only, item 95) | static taint + LLM (3 classes) |
| **ToolFuzz** | description-conformance discrepancies; `–` = not in ToolFuzz's 59-repo set | correctness (different axis) |
| **vanilla** | Sonnet-5 code-audit flagged tools (unverified) | LLM code-read |

| repo | lang | ToFu | CodeQL | Cisco | Viper | ToolFuzz | vanilla |
|---|---|---|---|---|---|---|---|
| ocean-zhc/dolphinscheduler-mcp | py | **72** (9) | 2 | 0 | n/a | – | 2 |
| openags/paper-search-mcp | py | **29** (26) | 9 | 0 | n/a | 55 | 23 |
| meilisearch/meilisearch-mcp | py | **24** (2) | 0 | 0 | n/a | 49 | 1 |
| alaturqua/mcp-trino-python | py | **19** (0) | 0 | 0 | n/a | – | 18 |
| neka-nat/freecad-mcp | py | **15** (13) | 0 | 0 | n/a | – | 2 |
| AminForou/mcp-gsc | py | **13** (13) | 0 | 0 | n/a | – | 0 |
| aliyun/alibabacloud-dms-mcp-server | py | **11** (1) | 0 | 1 | n/a | – | 0 |
| maoxiaoke/mcp-media-processor | no | **10** (8) | 0 | 0 | 0 | – | 6 |
| prathammanocha/wordpress-mcp-server | no | **10** (0) | 0 | 0 | 0 | – | 3 |
| sworddut/mcp-ffmpeg-helper | no | **8** (8) | 0 | 0 | 1 | – | 7 |
| pixelsock/directus-mcp | no | **7** (7) | 1 | 0 | 2 | – | 18 |
| vinayak-mehta/mcp-browser-use | py | **7** (2) | 0 | 0 | n/a | – | 0 |
| Tisik79/MCP-Facebook | no | **6** (6) | 28 | 0 | 0 | – | 5 |
| movibe/memory-bank-mcp | no | **5** (2) | 1 | 0 | 6 | – | 3 |
| newtype-01/obsidian-mcp | no | **5** (1) | 1 | 0 | 1 | – | 8 |
| rishijatia/fantasy-pl-mcp | py | **5** (4) | 0 | 0 | n/a | – | 0 |
| dazeb/Cline-Memory-Bank | no | **4** (1) | 0 | 0 | 0 | – | 4 |
| dazeb/cline-mcp-memory-bank | no | **4** (1) | 0 | 0 | 0 | – | 4 |
| jinzcdev/leetcode-mcp-server | no | **3** (3) | 0 | 0 | 2 | – | 0 |
| joshrutkowski/applescript-mcp | no | **3** (3) | 2 | 0 | 4 | 32 | 21 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | no | **2** (0) | 0 | 0 | 1 | – | 2 |
| davidteren/claude-server | no | **2** (1) | 0 | 0 | 1 | – | 4 |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | no | **1** (0) | 0 | 0 | 1 | – | 12 |
| PhialsBasement/CMD-MCP-Server | no | **1** (1) | 0 | 0 | 2 | – | 0 |
| revit-mcp/revit-mcp | no | **1** (1) | 0 | 0 | 0 | – | 1 |
| RegiByte/todo-list-mcp | no | **1** (1) | 0 | 0 | 0 | – | 0 |
| Sheshiyer/framer-plugin-mcp | no | **1** (1) | 0 | 0 | 1 | – | 2 |
| T1nker-1220/memories-with-lessons-mcp-server | no | **1** (0) | 0 | – | 1 | – | 0 |
| WilliamCloudQi/matlab-mcp-server | no | **1** (1) | 0 | 0 | 5 | – | 2 |
| taylorwilsdon/google_workspace_mcp | py | **1** (0) | 59 | 5 | n/a | 115 | 0 |
| Antonytm/mcp-sitecore-server | no | 0 | 4 | 7 | 0 | 123 | 8 |
| antvis/mcp-server-chart | no | 0 | 3 | 0 | 1 | – | 0 |
| graphlit/graphlit-mcp-server | no | 0 | 0 | 0 | 0 | 5 | 2 |
| bradrisse/kanban-mcp | no | 0 | 0 | 0 | 2 | – | 8 |
| ProgramComputer/NASA-MCP-server | no | 0 | 1 | 0 | 1 | – | 1 |
| alioshr/memory-bank-mcp | no | 0 | 0 | 0 | 1 | – | 1 |
| fireproof-storage/mcp-database-server | no | 0 | 0 | 0 | 1 | – | 0 |
| doggybee/mcp-server-ccxt | no | 0 | 0 | 0 | 0 | – | 1 |
| gdli6177/mcp-prompt-server | no | 0 | 0 | 0 | 1 | – | 0 |
| yokingma/time-mcp | no | 0 | 0 | 0 | 0 | – | 0 |
| AzDeltaQQ/Mcp-Reasoning-Server | no | 0 | 0 | 0 | 1 | – | 0 |
| 34892002/bilibili-mcp-js | no | 0 | 0 | 0 | 3 | – | 0 |
| Jacck/mcp-reasoner | no | 0 | 0 | 0 | 3 | – | 0 |
| StevenStavrakis/mcp-starter-template | no | 0 | 0 | 0 | 0 | – | 0 |
| aaronjmars/web3-research-mcp | no | 0 | 0 | 0 | 3 | – | 1 |

## Tally over the 45-repo set (repos with ≥1 finding)
| tool | repos flagged | denom | note |
|---|---|---|---|
| **ToFu** | **30** | 45 | shortlist = 45 repos ToFu flagged on *raw* finding-hits; **30 survive security-class triage** (other 15 were robustness/mandatory-layer noise only) |
| CodeQL | 11 | 45 | full-corpus tool, ran all 45 |
| Cisco (YARA+LLM) | 3 | 45 | 1 repo LLM incomplete (`–`) |
| Viper | 23 | 35 | node-only; 10 python repos = n/a |
| ToolFuzz | 6 | 6 | only 6/45 in its 59-repo partial set; diff axis |
| vanilla-claude-s5 | 28 | 45 | full corpus; unverified LLM flags |

## ToFu-exclusive on this set: 12 repos (triaged measure)
Repos where a **triaged** ToFu candidate exists and **all three static comparators (CodeQL, Cisco, Viper) found nothing** (viper n/a on python counted as no-find). This is 12 on the strict triaged measure; RESULTS_SUMMARY §5 quotes 16 on the looser raw-finding-hits measure (before security-class triage).

- `meilisearch/meilisearch-mcp` (python) — ToFu 24 (2 hi), vanilla 1
- `alaturqua/mcp-trino-python` (python) — ToFu 19 (0 hi), vanilla 18
- `neka-nat/freecad-mcp` (python) — ToFu 15 (13 hi), vanilla 2
- `AminForou/mcp-gsc` (python) — ToFu 13 (13 hi), vanilla 0
- `maoxiaoke/mcp-media-processor` (node) — ToFu 10 (8 hi), vanilla 6
- `prathammanocha/wordpress-mcp-server` (node) — ToFu 10 (0 hi), vanilla 3
- `vinayak-mehta/mcp-browser-use` (python) — ToFu 7 (2 hi), vanilla 0
- `rishijatia/fantasy-pl-mcp` (python) — ToFu 5 (4 hi), vanilla 0
- `dazeb/Cline-Memory-Bank` (node) — ToFu 4 (1 hi), vanilla 4
- `dazeb/cline-mcp-memory-bank` (node) — ToFu 4 (1 hi), vanilla 4
- `revit-mcp/revit-mcp` (node) — ToFu 1 (1 hi), vanilla 1
- `RegiByte/todo-list-mcp` (node) — ToFu 1 (1 hi), vanilla 0

## Reading notes
- **CodeQL out-fires ToFu on 3 repos** (Tisik79/MCP-Facebook 28, taylorwilsdon/google_workspace_mcp 59, Antonytm/mcp-sitecore-server 4). These are static rule matches on code paths, not runtime-reachable silent bugs — CodeQL and ToFu are complementary, and google_workspace is exactly a repo ToFu barely reaches at runtime (1 candidate) while CodeQL scans all source.
- **Viper's non-zero column is node-only** and models 3 classes (cmd-inj/SSRF/path-trav). Where it fires (e.g. WilliamCloudQi/matlab-mcp-server 5, movibe/memory-bank-mcp 6) it overlaps ToFu's path/command families.
- **ToolFuzz numbers are large but off-axis** (correctness discrepancies, not security): google_workspace 115, sitecore 123, openags/paper-search 55. Not comparable to a vuln count.
- **vanilla-claude flags widely** (Augmented-Nature-ChEMBL 12, joshrutkowski/applescript 21, openags/paper-search 23) but these are unverified LLM reads; several land on repos ToFu also flags (agreement) and several on repos ToFu reaches 0 (candidate misses to re-check).

Source indices (committed): `findings/baselines/*_2026092{1,2}.jsonl`, `findings/vanilla-claude-sonnet-5/inventory.jsonl`. Regen: `/tmp/h2hdump.py` on the VM.
