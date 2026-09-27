# Sandboxed corpus re-sweep (reachable set) — 2026-09-26

Arm `gpt41-corpus-sbx`. The **1,481 reachable configs** (250 repos, ≥1 successful
exec in the 2026-09-22 corpus run; unsafe repos skipped) re-fuzzed 60 s/tool under
the bubblewrap sandbox on the current oracles (reflected-xss + exfil tracers added
after the original run). Purpose: put the reachable corpus on current oracles +
sandbox, catch new-tracer bugs, and settle the 09-22 "corpus-only" candidates.
Candidates auto-triaged (`eval/triage_findings.py`), **unconfirmed**. No
confidence tier (item 17): counts are whole candidate counts; the success rate is
reachability only.

## Headline
- 1,481 configs, **1,403 executed successfully**, 0 sandbox aborts.
- **413 candidates across 123 repos.** By class: reflected-xss 189, path-traversal 94,
  log-injection 73, ssrf 48, os-command-injection 4, data-exfiltration 4, insecure-temp-file 1.

## Versus the 2026-09-22 run, same 1,481 configs (370 candidates then)
| | count | classes |
|---|---|---|
| in **both** runs | 230 | stable core |
| **new** in sandboxed sweep | **183** | reflected-xss 171, log-injection 5, data-exfiltration 4, ssrf 3 — **175 from the new tracers** |
| **gone** vs 09-22 | 140 | **insecure-temp-file 77**, ssrf 24, log-injection 18, path-traversal 17, reflected-xss 3, hardcoded-creds 1 |

**Two clean results for the paper:**
1. **New tracers dominate the gains.** 175 of 183 new candidates are reflected-xss/
   exfil — bugs the original run could not surface. reflected-xss rises 21→189.
2. **The shared-/tmp temp-file false positives are confirmed and removed.** The
   insecure-temp-file class collapses **78→1** under the sandbox's private /tmp: the
   09-22 run fuzzed 5 configs against one shared /tmp, so a config saw temp files
   other configs left and flagged them as its own leak. 77 of the 78 vanish when each
   config gets an isolated /tmp — they were harness artefacts, not target bugs. The
   remaining "gone" (ssrf/log/path 59) need per-case check but are a minority.

## Status / next
- Candidates unconfirmed (mandatory layer not subtracted; hand-verification owed).
- Companion runs: `findings/repo24_20260926/` (24h deep budget, RQ4) and
  `findings/recover_pc_20260926/` (231 previously-dead repos: 21 recovered, 56 net-new).
- Slice logs (480 MB) on the VM (`~/toolfuzzer/eval/runs/gpt41-corpus-sbx`) and the
  laptop (`~/pseclab/ToFu_repo24_results/corpus-sbx/`); gitignored. Per-candidate
  new/lost diff: `diff.json`.

## Per-repo candidates
| repo | candidates | classes |
|---|---|---|
| kukapay/crypto-indicators-mcp | 60 | reflected-xss 60 |
| openags/paper-search-mcp | 21 | path-traversal 13, log-injection 3, data-exfiltration 3, reflected-xss 2 |
| neka-nat/freecad-mcp | 14 | ssrf 13, path-traversal 1 |
| CheMiguel23/MemoryMesh | 13 | reflected-xss 13 |
| aviveldan/datagov-mcp | 13 | log-injection 13 |
| maoxiaoke/mcp-media-processor | 10 | path-traversal 10 |
| ocean-zhc/dolphinscheduler-mcp | 8 | ssrf 5, reflected-xss 2, log-injection 1 |
| sworddut/mcp-ffmpeg-helper | 8 | path-traversal 8 |
| gdli6177/mcp-prompt-server | 7 | reflected-xss 7 |
| pixelsock/directus-mcp | 7 | ssrf 7 |
| qiniu/qiniu-mcp-server | 7 | reflected-xss 4, ssrf 3 |
| Nayshins/mcp-server-ccxt | 6 | log-injection 6 |
| StarRocks/mcp-server-starrocks | 6 | reflected-xss 5, path-traversal 1 |
| Tisik79/MCP-Facebook | 6 | log-injection 2, path-traversal 2, ssrf 1, reflected-xss 1 |
| bnb-chain/bnbchain-mcp | 6 | reflected-xss 4, path-traversal 2 |
| yzfly/mcp-python-interpreter | 6 | path-traversal 3, reflected-xss 2, log-injection 1 |
| antoinebou12/uml-mcp | 5 | log-injection 4, path-traversal 1 |
| dragon1086/kospi-kosdaq-stock-server | 5 | reflected-xss 5 |
| hanweg/mcp-pdf-tools | 5 | path-traversal 5 |
| jinzcdev/leetcode-mcp-server | 5 | log-injection 3, reflected-xss 2 |
| movibe/memory-bank-mcp | 5 | path-traversal 4, log-injection 1 |
| rishijatia/fantasy-pl-mcp | 5 | reflected-xss 4, data-exfiltration 1 |
| AzDeltaQQ/Mcp-Reasoning-Server | 4 | reflected-xss 4 |
| dazeb/Cline-Memory-Bank | 4 | path-traversal 4 |
| dazeb/cline-mcp-memory-bank | 4 | path-traversal 4 |
| hijaz/postmancer | 4 | reflected-xss 4 |
| krzko/google-cloud-mcp | 4 | reflected-xss 4 |
| tuanle96/mcp-odoo | 4 | reflected-xss 4 |
| yctimlin/mcp_excalidraw | 4 | reflected-xss 2, path-traversal 1, log-injection 1 |
| AppiumTestDistribution/mcp-appium-gestures | 3 | reflected-xss 3 |
| AustinKelsay/nostr-mcp-server | 3 | reflected-xss 3 |
| GoogleCloudPlatform/cloud-run-mcp | 3 | ssrf 1, path-traversal 1, log-injection 1 |
| QuantGeekDev/docker-mcp | 3 | reflected-xss 3 |
| Xuanwo/mcp-server-opendal | 3 | log-injection 2, path-traversal 1 |
| aaronjmars/web3-research-mcp | 3 | reflected-xss 3 |
| aaronsb/google-workspace-mcp | 3 | path-traversal 2, reflected-xss 1 |
| aws-samples/sample-mcp-server-s3 | 3 | ssrf 2, log-injection 1 |
| bsmi021/mcp-file-context-server | 3 | path-traversal 3 |
| coinpaprika/dexpaprika-mcp | 3 | log-injection 3 |
| designcomputer/mysql_mcp_server | 3 | reflected-xss 2, log-injection 1 |
| joshrutkowski/applescript-mcp | 3 | path-traversal 2, os-command-injection 1 |
| pmmvr/obsidian-api-mcp-server | 3 | path-traversal 2, ssrf 1 |
| puravparab/Gitingest-MCP | 3 | reflected-xss 2, log-injection 1 |
| renyumeng1/mcp_scholar | 3 | reflected-xss 1, log-injection 1, ssrf 1 |
| roadwy/cve-search_mcp | 3 | log-injection 3 |
| sonnylazuardi/cursor-talk-to-figma-mcp | 3 | log-injection 2, path-traversal 1 |
| takashiishida/arxiv-latex-mcp | 3 | log-injection 3 |
| terryso/mcp-pinterest | 3 | reflected-xss 2, ssrf 1 |
| AudienseCo/mcp-audiense-insights | 2 | reflected-xss 2 |
| DMontgomery40/pentest-mcp | 2 | ssrf 1, path-traversal 1 |
| Dakkshin/after-effects-mcp | 2 | path-traversal 1, reflected-xss 1 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | 2 | path-traversal 2 |
| PuroDelphi/mcpFirebird | 2 | reflected-xss 2 |
| RegiByte/todo-list-mcp | 2 | reflected-xss 1, log-injection 1 |
| VxASI/blender-mcp-vxai | 2 | ssrf 2 |
| aakarsh-sasi/memory-bank-mcp | 2 | path-traversal 2 |
| adhikasp/mcp-git-ingest | 2 | ssrf 1, path-traversal 1 |
| apvlv/davinci-resolve-mcp | 2 | log-injection 1, os-command-injection 1 |
| aurda012/cursor10x-mcp | 2 | reflected-xss 1, log-injection 1 |
| bigcodegen/mcp-neovim-server | 2 | os-command-injection 1, log-injection 1 |
| blazickjp/arxiv-mcp-server | 2 | log-injection 1, reflected-xss 1 |
| bmorphism/anti-bullshit-mcp-server | 2 | reflected-xss 2 |
| davidteren/claude-server | 2 | log-injection 2 |
| dschuler36/reaper-mcp-server | 2 | path-traversal 2 |
| gerred/mcp-server-replicate | 2 | reflected-xss 1, log-injection 1 |
| gregkop/sketchfab-mcp-server | 2 | reflected-xss 1, path-traversal 1 |
| horw/esp-mcp | 2 | log-injection 1, path-traversal 1 |
| meilisearch/meilisearch-mcp | 2 | ssrf 1, reflected-xss 1 |
| narumiruna/yfinance-mcp | 2 | log-injection 1, reflected-xss 1 |
| nickclyde/duckduckgo-mcp-server | 2 | reflected-xss 1, ssrf 1 |
| qpd-v/mcp-guide | 2 | reflected-xss 2 |
| ryaker/outlook-mcp | 2 | log-injection 1, path-traversal 1 |
| zhixiaoqiang/antd-components-mcp | 2 | reflected-xss 2 |
| CodeLogicIncEngineering/codelogic-mcp-server | 1 | reflected-xss 1 |
| DMontgomery40/meta-mcp-server | 1 | path-traversal 1 |
| FradSer/mcp-server-mas-sequential-thinking | 1 | log-injection 1 |
| Joooook/12306-mcp | 1 | reflected-xss 1 |
| Jpisnice/shadcn-ui-mcp-unofficial | 1 | reflected-xss 1 |
| MushroomFleet/DeepLucid3D-MCP | 1 | reflected-xss 1 |
| MushroomFleet/TranscriptionTools-MCP | 1 | reflected-xss 1 |
| Promptly-Technologies-LLC/mcp-structured-thinking | 1 | log-injection 1 |
| SecretiveShell/MCP-searxng | 1 | ssrf 1 |
| Sheshiyer/framer-plugin-mcp | 1 | path-traversal 1 |
| Vortiago/mcp-azure-devops | 1 | reflected-xss 1 |
| Vortiago/mcp-outline | 1 | log-injection 1 |
| WilliamCloudQi/matlab-mcp-server | 1 | path-traversal 1 |
| YuChenSSR/mindmap-mcp-server | 1 | insecure-temp-file 1 |
| adityak74/mcp-scholarly | 1 | reflected-xss 1 |
| ananddtyagi/webpage-screenshot-mcp | 1 | ssrf 1 |
| annenpolka/roo-logger | 1 | log-injection 1 |
| andybrandt/mcp-simple-arxiv | 1 | log-injection 1 |
| armorwallet/armor-crypto-mcp | 1 | reflected-xss 1 |
| blazickjp/web-browser-mcp-server | 1 | ssrf 1 |
| bradrisse/kanban-mcp | 1 | log-injection 1 |
| containerelic/github-enterprise-mcp | 1 | log-injection 1 |
| crazyrabbitLTC/mcp-vibecoder | 1 | log-injection 1 |
| d-zero-dev/mcp-server | 1 | path-traversal 1 |
| dazeb/markdown-downloader | 1 | reflected-xss 1 |
| executeautomation/mcp-playwright | 1 | reflected-xss 1 |
| fengin/image-gen-server | 1 | path-traversal 1 |
| fireproof-storage/mcp-database-server | 1 | reflected-xss 1 |
| g0t4/mcp-server-commands | 1 | os-command-injection 1 |
| hyperb1iss/lucidity-mcp | 1 | path-traversal 1 |
| ihrpr/mcp-server-jupyter | 1 | path-traversal 1 |
| jatinsandilya/mcp-server-template | 1 | reflected-xss 1 |
| kbsooo/MCP_Atom_of_Thoughts | 1 | reflected-xss 1 |
| klara-research/MCP-Analyzer | 1 | path-traversal 1 |
| lucasmontano/mcp-montano-server | 1 | reflected-xss 1 |
| m2rads/v0-mcp | 1 | ssrf 1 |
| makafeli/n8n-workflow-builder | 1 | reflected-xss 1 |
| nahmanmate/postgresql-mcp-server | 1 | reflected-xss 1 |
| noahgsolomon/pumpfun-mcp-server | 1 | ssrf 1 |
| openSVM/zig-mcp-server | 1 | reflected-xss 1 |
| pinkpixel-dev/MCPollinations | 1 | reflected-xss 1 |
| puremd/puremd-mcp | 1 | ssrf 1 |
| qhdrl12/mcp-server-gemini-image-generator | 1 | path-traversal 1 |
| ravinahp/surf-mcp | 1 | log-injection 1 |
| revit-mcp/revit-mcp | 1 | path-traversal 1 |
| ruan11223344/McpDocServer | 1 | reflected-xss 1 |
| tavily-ai/tavily-mcp | 1 | ssrf 1 |
| vinayak-mehta/mcp-browser-use | 1 | reflected-xss 1 |
| yokingma/time-mcp | 1 | reflected-xss 1 |
| zhiwei5576/excel-mcp-server | 1 | path-traversal 1 |
