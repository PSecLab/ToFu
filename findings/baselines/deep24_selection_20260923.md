# 24h deep-fuzz selection (20260923)

Source arm `gpt41-corpus`; scored 6153 configs, **1073 eligible**, **78 picked across 47 repos** (cap 78 = 5 workers x 24.0h / (5400+120)s; per-repo <= 4). Estimated wall: **23.9 h**.

Score = late_gain x recency, where late_gain = cov(T_end) - cov(T_end/2) and recency = time of last new edge / T_end. Saturated curves score 0.

Languages picked: {'python': 15, 'node': 63}

Excluded: unreachable (0 successful execs) 3736, unsafe 675, not ok 487, cov < 20 182

## Picked (baseline recorded for the before/after comparison)

| repo | lang | tool | score | cov@60s | cov_final (prior) | prior t_end | recency | succ | prior hits |
|---|---|---|---|---|---|---|---|---|---|
| CodeLogicIncEngineering/codelogic-mcp-server | python | `lineai-graph-validate-change-scope` | 336.97 | 0 | 525 | 140.5s | 0.642 | 0.97 | 237 |
| openags/paper-search-mcp | python | `search_dblp` | 197.87 | 325 | 325 | 60.0s | 0.609 | 1.0 | 2 |
| openags/paper-search-mcp | python | `search_papers` | 86.82 | 180 | 180 | 60.0s | 0.819 | 1.0 | 3 |
| openags/paper-search-mcp | python | `search_iacr` | 55.06 | 588 | 588 | 60.0s | 0.765 | 1.0 | 0 |
| Vortiago/mcp-outline | python | `batch_create_documents` | 140.78 | 270 | 270 | 76.0s | 0.521 | 0.291 | 1 |
| blazickjp/arxiv-mcp-server | python | `check_alerts` | 131.96 | 233 | 233 | 87.0s | 0.566 | 0.446 | 0 |
| blazickjp/arxiv-mcp-server | python | `list_paper_latex_sections` | 39.0 | 976 | 979 | 62.2s | 1.0 | 0.004 | 49 |
| T1nker-1220/memories-with-lessons-mcp-server | node | `add_observations` | 99.63 | 328 | 328 | 60.0s | 0.923 | 0.371 | 0 |
| T1nker-1220/memories-with-lessons-mcp-server | node | `create_lesson` | 22.13 | 301 | 301 | 62.8s | 0.738 | 0.013 | 5 |
| T1nker-1220/memories-with-lessons-mcp-server | node | `create_relations` | 20.37 | 299 | 299 | 61.6s | 0.886 | 0.981 | 0 |
| newtype-01/obsidian-mcp | node | `auto_backlink_vault` | 98.35 | 256 | 256 | 61.3s | 0.964 | 0.878 | 0 |
| newtype-01/obsidian-mcp | node | `manage_folder` | 10.72 | 113 | 117 | 74.4s | 0.893 | 0.03 | 6 |
| newtype-01/obsidian-mcp | node | `list_notes` | 9.24 | 100 | 100 | 60.0s | 0.66 | 1.0 | 0 |
| bsmi021/mcp-file-context-server | node | `read_context` | 87.0 | 208 | 291 | 63.5s | 1.0 | 0.12 | 146 |
| bsmi021/mcp-file-context-server | node | `get_chunk_count` | 66.97 | 349 | 349 | 60.0s | 0.797 | 0.182 | 153 |
| Alec2435/python_mcp | python | `python_repl` | 65.12 | 116 | 116 | 60.0s | 0.561 | 1.0 | 98 |
| revit-mcp/revit-mcp | node | `create_line_based_element` | 62.99 | 174 | 174 | 60.0s | 0.9 | 0.951 | 0 |
| revit-mcp/revit-mcp | node | `store_room_data` | 38.0 | 200 | 222 | 78.6s | 1.0 | 0.169 | 0 |
| revit-mcp/revit-mcp | node | `store_project_data` | 18.54 | 152 | 158 | 73.6s | 0.927 | 0.998 | 33 |
| ProgramComputer/NASA-MCP-server | node | `jpl_fireball` | 59.14 | 174 | 174 | 60.0s | 0.939 | 0.998 | 0 |
| ProgramComputer/NASA-MCP-server | node | `jpl_scout` | 55.98 | 188 | 188 | 60.0s | 0.889 | 0.999 | 0 |
| ProgramComputer/NASA-MCP-server | node | `nasa_mars_rover` | 46.62 | 170 | 170 | 60.0s | 0.729 | 0.999 | 114 |
| ProgramComputer/NASA-MCP-server | node | `jpl_sentry` | 41.75 | 170 | 170 | 61.0s | 0.663 | 0.999 | 125 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | `append_memory_bank_entry` | 54.07 | 0 | 82 | 123.9s | 0.659 | 0.104 | 44 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | `initialize_memory_bank` | 20.11 | 32 | 32 | 83.0s | 0.628 | 1.0 | 0 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | node | `read_memory_bank_file` | 17.33 | 0 | 28 | 120.0s | 0.619 | 0.015 | 2 |
| antoinebou12/uml-mcp | python | `generate_uml` | 44.89 | 1116 | 1116 | 60.0s | 0.935 | 0.057 | 20 |
| Pimzino/agentic-tools-mcp | node | `search_memories` | 41.35 | 77 | 135 | 300.0s | 0.713 | 0.004 | 13 |
| Pimzino/agentic-tools-mcp | node | `list_memories` | 27.52 | 77 | 117 | 300.0s | 0.688 | 0.005 | 16 |
| jinzcdev/markmap-mcp-server | node | `cleanup_mindmaps` | 33.9 | 122 | 122 | 60.0s | 0.721 | 0.602 | 0 |
| aurda012/cursor10x-mcp | node | `getActiveFiles` | 29.62 | 314 | 314 | 60.0s | 0.705 | 0.005 | 0 |
| aurda012/cursor10x-mcp | node | `storeDecision` | 22.25 | 294 | 294 | 60.0s | 0.927 | 0.761 | 666 |
| aurda012/cursor10x-mcp | node | `getRecentMessages` | 21.11 | 336 | 336 | 60.0s | 0.879 | 0.733 | 0 |
| aurda012/cursor10x-mcp | node | `recordEpisode` | 15.94 | 290 | 290 | 60.0s | 0.664 | 0.946 | 18 |
| baranwang/mcp-trends-hub | node | `get_bilibili_rank` | 29.22 | 242 | 242 | 60.0s | 0.974 | 0.031 | 0 |
| aviveldan/datagov-mcp | python | `package_list` | 24.23 | 665 | 665 | 60.0s | 0.897 | 1.0 | 16 |
| aviveldan/datagov-mcp | python | `license_list` | 22.86 | 666 | 666 | 60.0s | 0.847 | 1.0 | 23 |
| aviveldan/datagov-mcp | python | `organization_list` | 21.71 | 665 | 665 | 60.0s | 0.804 | 1.0 | 25 |
| kukapay/crypto-indicators-mcp | node | `calculate_williams_r_strategy` | 21.22 | 50 | 50 | 60.0s | 0.965 | 1.0 | 0 |
| kukapay/crypto-indicators-mcp | node | `calculate_awesome_oscillator` | 16.87 | 50 | 50 | 60.0s | 0.733 | 1.0 | 0 |
| kukapay/crypto-indicators-mcp | node | `calculate_kdj_strategy` | 13.28 | 50 | 50 | 60.8s | 0.531 | 0.982 | 0 |
| kukapay/crypto-indicators-mcp | node | `calculate_triangular_moving_average` | 12.9 | 50 | 50 | 60.0s | 0.538 | 1.0 | 0 |
| cdugo/package-documentation-mcp | node | `fetch-multilingual-docs` | 20.0 | 460 | 462 | 61.6s | 1.0 | 0.27 | 92 |
| openSVM/zig-mcp-server | node | `get_recommendations` | 19.76 | 810 | 814 | 63.6s | 0.988 | 1.0 | 0 |
| openSVM/zig-mcp-server | node | `generate_code` | 8.0 | 118 | 118 | 61.4s | 0.8 | 1.0 | 0 |
| hijaz/postmancer | node | `get_environment_variables` | 18.0 | 116 | 134 | 91.6s | 1.0 | 1.0 | 0 |
| Coding-Solo/godot-mcp | node | `list_projects` | 17.18 | 190 | 190 | 84.0s | 0.537 | 0.039 | 0 |
| baranwang/mcp-tung-shing | node | `get-tung-shing` | 17.11 | 60 | 60 | 60.0s | 0.535 | 0.035 | 0 |
| obra/private-journal-mcp | node | `search_journal` | 16.55 | 204 | 226 | 300.0s | 0.919 | 1.0 | 0 |
| arabold/docs-mcp-server | node | `find_version` | 14.77 | 707 | 727 | 300.0s | 0.738 | 0.029 | 0 |
| CheMiguel23/MemoryMesh | node | `add_npc` | 14.13 | 492 | 514 | 300.0s | 0.642 | 0.46 | 5 |
| CheMiguel23/MemoryMesh | node | `add_artifact` | 10.6 | 512 | 556 | 300.0s | 0.883 | 0.661 | 1 |
| CheMiguel23/MemoryMesh | node | `add_location` | 10.01 | 500 | 518 | 300.0s | 0.715 | 0.733 | 9 |
| CheMiguel23/MemoryMesh | node | `add_nodes` | 9.49 | 319 | 333 | 300.0s | 0.949 | 0.129 | 1 |
| PuroDelphi/mcpFirebird | node | `get-execution-plan` | 13.39 | 283 | 311 | 300.0s | 0.837 | 0.068 | 0 |
| coinpaprika/dexpaprika-mcp | node | `getTokenMultiPrices` | 13.16 | 155 | 159 | 85.5s | 0.822 | 0.012 | 0 |
| joshrutkowski/applescript-mcp | node | `notes_create` | 11.75 | 119 | 125 | 69.6s | 0.979 | 1.0 | 0 |
| bradrisse/kanban-mcp | node | `mcp_kanban_label_manager` | 11.7 | 166 | 168 | 63.0s | 0.975 | 0.018 | 1 |
| bradrisse/kanban-mcp | node | `mcp_kanban_card_manager` | 9.16 | 230 | 230 | 65.1s | 0.916 | 0.092 | 43 |
| dazeb/cline-mcp-memory-bank | node | `record_decision` | 11.69 | 86 | 90 | 96.0s | 0.974 | 0.19 | 267 |
| aaronjmars/web3-research-mcp | node | `defillama-search` | 11.66 | 108 | 110 | 84.2s | 0.728 | 0.998 | 0 |
| MushroomFleet/TranscriptionTools-MCP | node | `format_transcript` | 10.76 | 82 | 82 | 66.0s | 0.897 | 0.89 | 0 |
| Selenium39/mcp-server-weibo | node | `get_profile` | 9.77 | 20 | 20 | 60.0s | 0.888 | 1.0 | 0 |
| Selenium39/mcp-server-weibo | node | `search_users` | 8.69 | 24 | 24 | 60.0s | 0.966 | 1.0 | 0 |
| api7/apisix-mcp | node | `send_request_to_gateway` | 9.65 | 126 | 136 | 300.0s | 0.965 | 0.977 | 0 |
| marcelmarais/spotify-mcp-server | node | `addTracksToPlaylist` | 9.6 | 80 | 80 | 60.0s | 0.8 | 0.988 | 0 |
| nickclyde/duckduckgo-mcp-server | python | `search` | 9.0 | 41 | 50 | 62.8s | 1.0 | 1.0 | 2 |
| nickclyde/duckduckgo-mcp-server | python | `fetch_content` | 8.91 | 109 | 118 | 63.8s | 0.99 | 1.0 | 126 |
| ocean-zhc/dolphinscheduler-mcp | python | `delete_worker_groups` | 8.82 | 34 | 34 | 61.7s | 0.588 | 1.0 | 40 |
| AudienseCo/mcp-audiense-insights | node | `compare-audience-influencers` | 8.81 | 53 | 62 | 63.0s | 0.979 | 1.0 | 0 |
| doggybee/mcp-server-leetcode | node | `get-problem` | 8.6 | 54 | 54 | 71.3s | 0.537 | 1.0 | 0 |
| jae-jae/fetcher-mcp | node | `fetch_urls` | 8.58 | 222 | 298 | 300.7s | 0.858 | 0.005 | 1 |
| davidteren/claude-server | node | `list_contexts` | 8.46 | 69 | 69 | 60.0s | 0.846 | 0.117 | 0 |
| Jpisnice/shadcn-ui-mcp-unofficial | node | `list_blocks` | 8.2 | 340 | 359 | 300.0s | 0.631 | 0.036 | 1 |
| MushroomFleet/DeepLucid3D-MCP | node | `analyze_problem` | 8.0 | 157 | 159 | 93.8s | 1.0 | 0.984 | 0 |
| Jacck/mcp-reasoner | node | `mcp-reasoner` | 7.94 | 653 | 653 | 65.4s | 0.882 | 0.114 | 33 |
| gannonh/memento-mcp | node | `add_observations` | 7.86 | 285 | 285 | 66.2s | 0.786 | 0.066 | 0 |
| ddukbg/github-enterprise-mcp | node | `trigger-workflow` | 7.76 | 138 | 146 | 300.0s | 0.97 | 0.138 | 0 |
