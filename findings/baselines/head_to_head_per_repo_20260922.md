# Head-to-head, per repo — 45 ToFu-flagged repos — 2026-09-22

> **2026-09-26: the `viper` column below is withdrawn** — it counted `oracle.json` lines incl. the `hook_init`
> marker (hook loaded), not findings, and python was n/a (since fixed, item 95). Viper's real results on these
> 45 repos: static 11, runtime sink 9, confirmed 2 — `viper_h2h_corrected_20260926.md`. Current ToFu-vs-Viper
> table at the 648 headline: `h2h_tofu_vs_viper_20260926.md`.

> **2026-09-23: the `toolfuzz` column is withdrawn** — it counted ToolFuzz prompt-set *tests*, not failures (see toolfuzz_method_20260923.md). Replaced by the H2H-45 re-run.


Every tool run on the **same 45 repos** (the head-to-head shortlist, `Benchmarks/extraction/head2head_cisco.txt`). Rows sorted by ToFu candidate count. This is the repo-level detail behind RESULTS_SUMMARY.md §5.

> **Units differ — do NOT read across a row as a leaderboard.** Each column answers a different question; the table shows *where each tool fires*, not which is "better".

| column | meaning | axis |
|---|---|---|
| **ToFu** | triaged silent-bug candidates (distinct tool×class) | runtime oracle |
| **CodeQL** | security-extended rule matches | static SAST |
| **Cisco** | MCP-Scanner YARA + LLM analyzer findings | static metadata + LLM |
| **Viper** | Phase-II oracle hit-markers; `n/a` = python (Viper is node-only, item 95) | static taint + LLM (3 classes) |
| **ToolFuzz** | description-conformance discrepancies; `–` = not in ToolFuzz's 59-repo set | correctness (different axis) |
| **sonnet-5** | Sonnet-5 code-audit flagged tools (unverified) | LLM code-read |

`n/a` = viper is node-only (python repo). `–` = repo not in that tool's run set. ToFu cell = triaged security-class candidates.

| repo | tofu | viper | codeql | cisco | sonnet-5 | toolfuzz |
|---|---|---|---|---|---|---|
| ocean-zhc/dolphinscheduler-mcp | **72** | n/a | 2 | 0 | 2 | – |
| openags/paper-search-mcp | **29** | n/a | 9 | 0 | 23 | 55 |
| meilisearch/meilisearch-mcp | **24** | n/a | 0 | 0 | 1 | 49 |
| alaturqua/mcp-trino-python | **19** | n/a | 0 | 0 | 18 | – |
| neka-nat/freecad-mcp | **15** | n/a | 0 | 0 | 2 | – |
| AminForou/mcp-gsc | **13** | n/a | 0 | 0 | 0 | – |
| aliyun/alibabacloud-dms-mcp-server | **11** | n/a | 0 | 1 | 0 | – |
| maoxiaoke/mcp-media-processor | **10** | 0 | 0 | 0 | 6 | – |
| prathammanocha/wordpress-mcp-server | **10** | 0 | 0 | 0 | 3 | – |
| sworddut/mcp-ffmpeg-helper | **8** | 1 | 0 | 0 | 7 | – |
| pixelsock/directus-mcp | **7** | 2 | 1 | 0 | 18 | – |
| vinayak-mehta/mcp-browser-use | **7** | n/a | 0 | 0 | 0 | – |
| Tisik79/MCP-Facebook | **6** | 0 | 28 | 0 | 5 | – |
| movibe/memory-bank-mcp | **5** | 6 | 1 | 0 | 3 | – |
| newtype-01/obsidian-mcp | **5** | 1 | 1 | 0 | 8 | – |
| rishijatia/fantasy-pl-mcp | **5** | n/a | 0 | 0 | 0 | – |
| dazeb/Cline-Memory-Bank | **4** | 0 | 0 | 0 | 4 | – |
| dazeb/cline-mcp-memory-bank | **4** | 0 | 0 | 0 | 4 | – |
| jinzcdev/leetcode-mcp-server | **3** | 2 | 0 | 0 | 0 | – |
| joshrutkowski/applescript-mcp | **3** | 4 | 2 | 0 | 21 | 32 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | **2** | 1 | 0 | 0 | 2 | – |
| davidteren/claude-server | **2** | 1 | 0 | 0 | 4 | – |
| Augmented-Nature/Augmented-Nature-ChEMBL-MCP-Server | **1** | 1 | 0 | 0 | 12 | – |
| PhialsBasement/CMD-MCP-Server | **1** | 2 | 0 | 0 | 0 | – |
| revit-mcp/revit-mcp | **1** | 0 | 0 | 0 | 1 | – |
| RegiByte/todo-list-mcp | **1** | 0 | 0 | 0 | 0 | – |
| Sheshiyer/framer-plugin-mcp | **1** | 1 | 0 | 0 | 2 | – |
| T1nker-1220/memories-with-lessons-mcp-server | **1** | 1 | 0 | – | 0 | – |
| WilliamCloudQi/matlab-mcp-server | **1** | 5 | 0 | 0 | 2 | – |
| taylorwilsdon/google_workspace_mcp | **1** | n/a | 59 | 5 | 0 | 115 |
| Antonytm/mcp-sitecore-server | 0 | 0 | 4 | 7 | 8 | 123 |
| antvis/mcp-server-chart | 0 | 1 | 3 | 0 | 0 | – |
| graphlit/graphlit-mcp-server | 0 | 0 | 0 | 0 | 2 | 5 |
| bradrisse/kanban-mcp | 0 | 2 | 0 | 0 | 8 | – |
| ProgramComputer/NASA-MCP-server | 0 | 1 | 1 | 0 | 1 | – |
| alioshr/memory-bank-mcp | 0 | 1 | 0 | 0 | 1 | – |
| fireproof-storage/mcp-database-server | 0 | 1 | 0 | 0 | 0 | – |
| doggybee/mcp-server-ccxt | 0 | 0 | 0 | 0 | 1 | – |
| gdli6177/mcp-prompt-server | 0 | 1 | 0 | 0 | 0 | – |
| yokingma/time-mcp | 0 | 0 | 0 | 0 | 0 | – |
| AzDeltaQQ/Mcp-Reasoning-Server | 0 | 1 | 0 | 0 | 0 | – |
| 34892002/bilibili-mcp-js | 0 | 3 | 0 | 0 | 0 | – |
| Jacck/mcp-reasoner | 0 | 3 | 0 | 0 | 0 | – |
| StevenStavrakis/mcp-starter-template | 0 | 0 | 0 | 0 | 0 | – |
| aaronjmars/web3-research-mcp | 0 | 3 | 0 | 0 | 1 | – |

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

- `meilisearch/meilisearch-mcp` (python) — ToFu 24, vanilla 1
- `alaturqua/mcp-trino-python` (python) — ToFu 19, vanilla 18
- `neka-nat/freecad-mcp` (python) — ToFu 15, vanilla 2
- `AminForou/mcp-gsc` (python) — ToFu 13, vanilla 0
- `maoxiaoke/mcp-media-processor` (node) — ToFu 10, vanilla 6
- `prathammanocha/wordpress-mcp-server` (node) — ToFu 10, vanilla 3
- `vinayak-mehta/mcp-browser-use` (python) — ToFu 7, vanilla 0
- `rishijatia/fantasy-pl-mcp` (python) — ToFu 5, vanilla 0
- `dazeb/Cline-Memory-Bank` (node) — ToFu 4, vanilla 4
- `dazeb/cline-mcp-memory-bank` (node) — ToFu 4, vanilla 4
- `revit-mcp/revit-mcp` (node) — ToFu 1, vanilla 1
- `RegiByte/todo-list-mcp` (node) — ToFu 1, vanilla 0

## Reading notes
- **CodeQL out-fires ToFu on 3 repos** (Tisik79/MCP-Facebook 28, taylorwilsdon/google_workspace_mcp 59, Antonytm/mcp-sitecore-server 4). These are static rule matches on code paths, not runtime-reachable silent bugs — CodeQL and ToFu are complementary, and google_workspace is exactly a repo ToFu barely reaches at runtime (1 candidate) while CodeQL scans all source.
- **Viper's non-zero column is node-only** and models 3 classes (cmd-inj/SSRF/path-trav). Where it fires (e.g. WilliamCloudQi/matlab-mcp-server 5, movibe/memory-bank-mcp 6) it overlaps ToFu's path/command families.
- **ToolFuzz numbers are large but off-axis** (correctness discrepancies, not security): google_workspace 115, sitecore 123, openags/paper-search 55. Not comparable to a vuln count.
- **vanilla-claude flags widely** (Augmented-Nature-ChEMBL 12, joshrutkowski/applescript 21, openags/paper-search 23) but these are unverified LLM reads; several land on repos ToFu also flags (agreement) and several on repos ToFu reaches 0 (candidate misses to re-check).

Source indices (committed): `findings/baselines/*_2026092{1,2}.jsonl`, `findings/vanilla-claude-sonnet-5/inventory.jsonl`. Regen: `/tmp/h2hdump.py` on the VM.
