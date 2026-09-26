# ToFu real-vulnerability candidates from set_e2 (2026-09-18)

> **NOTE 2026-09-26:** the "high-confidence (succ≥0.5)" tier used below is withdrawn — tool-level exec-success rate is reachability, not evidence about a given alert (the oracle already requires per-input success), so it is no longer used to tier or filter candidates. Candidate totals below are unaffected; see findings/RESULTS_SUMMARY.md.


**257 distinct repo::tool::class candidates across 81 repos** (of 450 oracle hits;
robustness/mandatory-layer noise excluded). Each is a ToFu silent-bug: an adversarial
input in an *exploitable* class tripped a sanitizer AND the tool returned success.
**succ** = fraction of execs the tool swallowed it (>=0.5 = high-confidence, 134 of these).
POTENTIAL/unconfirmed: hand-verify + subtract mandatory layer before any published FP rate.


## hardcoded-creds (CWE-798) -- 1

| repo | tool | succ | commit |
|---|---|---|---|
| T1nker-1220/memories-with-lessons-mcp-server | `create_lesson` | 0.013 | 7c6a33e635 |

## insecure-temp-file (CWE-377) -- 75

| repo | tool | succ | commit |
|---|---|---|---|
| Alec2435/python_mcp | `python_repl` | 1.000 | 9aee64bcca |
| CodeLogicIncEngineering/codelogic-mcp-server | `lineai-graph-capabilities` | 1.000 | 6fdff87b42 |
| ScrapeGraphAI/scrapegraph-mcp | `credits` | 1.000 | 8372895aa6 |
| ScrapeGraphAI/scrapegraph-mcp | `monitor_pause` | 1.000 | 8372895aa6 |
| ScrapeGraphAI/scrapegraph-mcp | `monitor_resume` | 1.000 | 8372895aa6 |
| Skywork-ai/Skywork-Super-Agents | `generate_sheet` | 1.000 | 38a10c36a5 |
| Skywork-ai/Skywork-Super-Agents | `generate_webpage` | 1.000 | 38a10c36a5 |
| Vortiago/mcp-azure-devops | `list_processes` | 1.000 | 1ce53765c7 |
| Vortiago/mcp-outline | `archive_document` | 1.000 | 1e80cc98a7 |
| Vortiago/mcp-outline | `delete_collection` | 1.000 | 1e80cc98a7 |
| Vortiago/mcp-outline | `get_attachment_url` | 1.000 | 1e80cc98a7 |
| Vortiago/mcp-outline | `restore_document` | 1.000 | 1e80cc98a7 |
| YuChenSSR/mindmap-mcp-server | `convert_markdown_to_mindmap` | 1.000 | f61f76fd60 |
| adhikasp/mcp-twikit | `delete_tweet` | 1.000 | d5c0e24183 |
| adhikasp/mcp-twikit | `delete_dm` | 1.000 | d5c0e24183 |
| adhikasp/mcp-twikit | `get_latest_timeline` | 1.000 | d5c0e24183 |
| adhikasp/mcp-twikit | `get_timeline` | 1.000 | d5c0e24183 |
| adhikasp/mcp-twikit | `get_user_tweets` | 1.000 | d5c0e24183 |
| adhikasp/mcp-twikit | `search_twitter` | 1.000 | d5c0e24183 |
| am0y/mcp-fal | `search` | 1.000 | 9c57d9970d |
| am0y/mcp-fal | `schema` | 1.000 | 9c57d9970d |
| armorwallet/armor-mcp | `list_groups` | 1.000 | c026c00b2f |
| blazickjp/arxiv-mcp-server | `list_watches` | 1.000 | 42419c1837 |
| apvlv/davinci-resolve-mcp | `load_project` | 1.000 | d025e4ecaf |
| dnakov/frida-mcp | `get_local_device` | 1.000 | f8003c7de6 |
| fengin/image-gen-server | `use_description` | 1.000 | 4ec89fefef |
| dschuler36/reaper-mcp-server | `list_installed_fx` | 0.973 | 96be16df70 |
| CodeLogicIncEngineering/codelogic-mcp-server | `lineai-database-impact` | 0.971 | 6fdff87b42 |
| StarRocks/mcp-server-starrocks | `db_summary` | 0.966 | 88e782b0f3 |
| Vortiago/mcp-outline | `add_comment` | 0.954 | 1e80cc98a7 |
| aliyun/alibabacloud-dms-mcp-server | `executeScript` | 0.932 | f8e1ae32a5 |
| Vortiago/mcp-outline | `delete_document` | 0.928 | 1e80cc98a7 |
| Vortiago/mcp-outline | `list_collections` | 0.914 | 1e80cc98a7 |
| blazickjp/arxiv-mcp-server | `watch_topic` | 0.789 | 42419c1837 |
| Vortiago/mcp-outline | `batch_create_documents` | 0.291 | 1e80cc98a7 |
| StarRocks/mcp-server-starrocks | `analyze_query` | 0.148 | 88e782b0f3 |
| adhikasp/mcp-twikit | `post_tweet` | 0.080 | d5c0e24183 |
| Vortiago/mcp-outline | `create_document` | 0.074 | 1e80cc98a7 |
| am0y/mcp-fal | `models` | 0.068 | 9c57d9970d |
| blazickjp/arxiv-mcp-server | `download_paper` | 0.033 | 42419c1837 |
| ScrapeGraphAI/scrapegraph-mcp | `history` | 0.028 | 8372895aa6 |
| armorwallet/armor-mcp | `create_dca_order` | 0.023 | c026c00b2f |
| armorwallet/armor-crypto-mcp | `search_token_details` | 0.022 | c026c00b2f |
| blazickjp/arxiv-mcp-server | `unwatch_topic` | 0.020 | 42419c1837 |
| armorwallet/armor-crypto-mcp | `cancel_dca_order` | 0.018 | c026c00b2f |
| armorwallet/armor-crypto-mcp | `get_all_orders` | 0.017 | c026c00b2f |
| armorwallet/armor-mcp | `unarchive_wallet_group` | 0.017 | c026c00b2f |
| armorwallet/armor-mcp | `add_wallets_to_group` | 0.010 | c026c00b2f |
| armorwallet/armor-mcp | `unstake_transaction` | 0.008 | c026c00b2f |
| armorwallet/armor-mcp | `unstake_quote` | 0.007 | c026c00b2f |
| armorwallet/armor-crypto-mcp | `unstake_transaction` | 0.005 | c026c00b2f |
| ShenghaiWang/xcodebuild | `build` | 0.000 | 543536b2e4 |
| aliyun/alibabacloud-dms-mcp-server | `createDataChangeOrder` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `fixSql` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `getDatabase` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `getInstance` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `getOrderInfo` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `getTableDetailInfo` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `listInstances` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `listTables` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `optimizeSql` | 0.000 | f8e1ae32a5 |
| aliyun/alibabacloud-dms-mcp-server | `submitOrderApproval` | 0.000 | f8e1ae32a5 |
| blazickjp/arxiv-mcp-server | `read_paper` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `semantic_search` | 0.000 | 42419c1837 |
| briandconnelly/mcp-server-ipinfo | `ipinfo_lookup_ips` | 0.000 | fb4af66dd6 |
| caiyunapp/mcp-caiyun-weather | `get_realtime_weather` | 0.000 | cbbdd7c29f |
| caiyunapp/mcp-caiyun-weather | `get_weekly_forecast` | 0.000 | cbbdd7c29f |
| caiyunapp/mcp-caiyun-weather | `get_weather_alerts` | 0.000 | cbbdd7c29f |
| dnakov/frida-mcp | `get_session_messages` | 0.000 | f8003c7de6 |
| dnakov/frida-mcp | `kill_process` | 0.000 | f8003c7de6 |
| horw/esp-mcp | `flash_esp_project` | 0.000 | 28afddf9ff |
| ihrpr/mcp-server-jupyter | `execute_cell` | 0.000 | fb4427030f |
| kagisearch/kagimcp | `kagi_extract` | 0.000 | 55b38d20c6 |
| kagisearch/kagimcp | `kagi_search_fetch` | 0.000 | 55b38d20c6 |
| kujenga/zotero-mcp | `zotero_item_metadata` | 0.000 | 8461cc42d9 |

## log-injection (CWE-117) -- 77

| repo | tool | succ | commit |
|---|---|---|---|
| Nayshins/mcp-server-ccxt | `get-historical-ohlcv` | 1.000 | f7ddee5eb4 |
| Nayshins/mcp-server-ccxt | `get-market-summary` | 1.000 | f7ddee5eb4 |
| Nayshins/mcp-server-ccxt | `get-price-change` | 1.000 | f7ddee5eb4 |
| Nayshins/mcp-server-ccxt | `get-price` | 1.000 | f7ddee5eb4 |
| Nayshins/mcp-server-ccxt | `get-top-volumes` | 1.000 | f7ddee5eb4 |
| Nayshins/mcp-server-ccxt | `get-volume-history` | 1.000 | f7ddee5eb4 |
| QuantGeekDev/docker-mcp | `get-logs` | 1.000 | 6dada7feb3 |
| andybrandt/mcp-simple-arxiv | `search_papers` | 1.000 | fc9262eaa4 |
| antoinebou12/uml-mcp | `validate_uml` | 1.000 | e3c007de86 |
| apvlv/davinci-resolve-mcp | `create_project` | 1.000 | d025e4ecaf |
| aviveldan/datagov-mcp | `chart_generator` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `dataset_profile` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `datastore_search` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `fetch_data` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `license_list` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `organization_list` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `map_generator` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `package_list` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `organization_show` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `package_search` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `resource_search` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `package_show` | 1.000 | 31143d3077 |
| aviveldan/datagov-mcp | `status_show` | 1.000 | 31143d3077 |
| aws-samples/sample-mcp-server-s3 | `GetObject` | 1.000 | b215bedef4 |
| Tisik79/MCP-Facebook | `create_pixel` | 1.000 | 2ebfbc931b |
| Tisik79/MCP-Facebook | `update_adcreative` | 1.000 | 2ebfbc931b |
| designcomputer/mysql_mcp_server | `get_schema_info` | 1.000 | d88c510f60 |
| gerred/mcp-server-replicate | `create_prediction` | 1.000 | 568024cbab |
| horw/esp-mcp | `list_esp_serial_ports` | 1.000 | 28afddf9ff |
| jinzcdev/leetcode-mcp-server | `get_recent_submissions` | 1.000 | 126115fc6e |
| jinzcdev/leetcode-mcp-server | `get_user_contest_ranking` | 1.000 | 126115fc6e |
| jinzcdev/leetcode-mcp-server | `list_problem_solutions` | 1.000 | 126115fc6e |
| GoogleCloudPlatform/cloud-run-mcp | `get_service_log` | 0.995 | 560558a78b |
| containerelic/github-enterprise-mcp | `create-repository` | 0.994 | 86c87521d7 |
| Xuanwo/mcp-server-opendal | `get_info` | 0.990 | f49ee92cae |
| dragon1086/kospi-kosdaq-stock-server | `get_stock_market_cap` | 0.990 | 8455054a04 |
| designcomputer/mysql_mcp_server | `get_table_sample` | 0.978 | d88c510f60 |
| Xuanwo/mcp-server-opendal | `list` | 0.976 | f49ee92cae |
| dragon1086/kospi-kosdaq-stock-server | `get_index_ohlcv` | 0.973 | 8455054a04 |
| dragon1086/kospi-kosdaq-stock-server | `get_stock_trading_volume` | 0.967 | 8455054a04 |
| Vortiago/mcp-outline | `update_collection` | 0.965 | 1e80cc98a7 |
| designcomputer/mysql_mcp_server | `execute_sql` | 0.962 | d88c510f60 |
| RegiByte/todo-list-mcp | `search-todos-by-title` | 0.920 | a04a79204f |
| coinpaprika/dexpaprika-mcp | `getCapabilities` | 0.788 | 9ef4a9f6f9 |
| crazyrabbitLTC/mcp-vibecoder | `start_feature_clarification` | 0.739 | 5e218b01c9 |
| bigcodegen/mcp-neovim-server | `vim_grep` | 0.705 | 9076bbb34a |
| davidteren/claude-server | `save_conversation_context` | 0.589 | 0b8568630d |
| davidteren/claude-server | `save_project_context` | 0.481 | 0b8568630d |
| annenpolka/roo-logger | `log_activity` | 0.140 | 6ebede5ebd |
| antoinebou12/uml-mcp | `list_diagram_types` | 0.133 | e3c007de86 |
| coinpaprika/dexpaprika-mcp | `getNetworks` | 0.094 | 9ef4a9f6f9 |
| antoinebou12/uml-mcp | `generate_uml` | 0.057 | e3c007de86 |
| FradSer/mcp-server-mas-sequential-thinking | `sequentialthinking` | 0.013 | f1a20b349e |
| antoinebou12/uml-mcp | `generate_uml_image` | 0.004 | e3c007de86 |
| blazickjp/arxiv-mcp-server | `list_paper_latex_sections` | 0.004 | 42419c1837 |
| ZeparHyfar/mcp-datetime | `get_datetime` | 0.000 | d517593caa |
| andybrandt/mcp-simple-arxiv | `get_full_paper_text` | 0.000 | fc9262eaa4 |
| andybrandt/mcp-simple-arxiv | `get_paper_data` | 0.000 | fc9262eaa4 |
| blazickjp/arxiv-mcp-server | `get_paper_latex_section` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `get_paper_latex` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `export_citations` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `get_paper_outline` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `read_paper_section` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `reindex` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `search_paper_text` | 0.000 | 42419c1837 |
| blazickjp/arxiv-mcp-server | `search_papers` | 0.000 | 42419c1837 |
| chatmcp/mcp-server-collector | `extract-mcp-servers-from-url` | 0.000 | 24dfe077da |
| gerred/mcp-server-replicate | `generate_image` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `get_collection_details` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `get_webhook_secret` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `list_collections` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `list_hardware` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `list_models` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `search_available_models` | 0.000 | 568024cbab |
| gerred/mcp-server-replicate | `search_models` | 0.000 | 568024cbab |
| horw/esp-mcp | `setup_project_esp_target` | 0.000 | 28afddf9ff |
| laptou/rust-docs-mcp-server | `search_crates` | 0.000 | b05dedd551 |

## os-command-injection (CWE-78) -- 5

| repo | tool | succ | commit |
|---|---|---|---|
| PhialsBasement/CMD-MCP-Server | `execute_command` | 1.000 | 08a3492dd9 |
| bigcodegen/mcp-neovim-server | `vim_command` | 1.000 | 9076bbb34a |
| joshrutkowski/applescript-mcp | `iterm_run` | 1.000 | e6f4c2ee7d |
| apvlv/davinci-resolve-mcp | `execute_lua` | 0.963 | d025e4ecaf |
| g0t4/mcp-server-commands | `run_process` | 0.009 | bc62283f43 |

## path-traversal (CWE-22) -- 48

| repo | tool | succ | commit |
|---|---|---|---|
| GoogleCloudPlatform/cloud-run-mcp | `deploy_local_folder` | 1.000 | 560558a78b |
| aakarsh-sasi/memory-bank-mcp | `set_memory_bank_path` | 1.000 | 0813435550 |
| ihrpr/mcp-server-jupyter | `add_cell` | 1.000 | fb4427030f |
| joshrutkowski/applescript-mcp | `finder_quick_look_file` | 1.000 | e6f4c2ee7d |
| joshrutkowski/applescript-mcp | `finder_search_files` | 1.000 | e6f4c2ee7d |
| Tisik79/MCP-Facebook | `upload_ad_media` | 0.999 | 2ebfbc931b |
| Tisik79/MCP-Facebook | `create_video_post` | 0.995 | 2ebfbc931b |
| gregkop/sketchfab-mcp-server | `sketchfab-download` | 0.994 | e5969ef858 |
| horw/esp-mcp | `run_esp_idf_install` | 0.992 | 28afddf9ff |
| klara-research/MCP-Analyzer | `read_mcp_logs` | 0.988 | 5b011cd17f |
| antoinebou12/uml-mcp | `generate_uml_batch` | 0.980 | e3c007de86 |
| StarRocks/mcp-server-starrocks | `read_query` | 0.975 | 88e782b0f3 |
| aakarsh-sasi/memory-bank-mcp | `initialize_memory_bank` | 0.973 | 0813435550 |
| hanweg/mcp-pdf-tools | `search-pdfs` | 0.968 | 388ba1fcb8 |
| fengin/image-gen-server | `generate_image` | 0.965 | 4ec89fefef |
| bsmi021/mcp-file-context-server | `generate_outline` | 0.964 | 85a0681d89 |
| Xuanwo/mcp-server-opendal | `read` | 0.963 | f49ee92cae |
| hyperb1iss/lucidity-mcp | `analyze_changes` | 0.955 | cdcb184bf1 |
| Sheshiyer/framer-plugin-mcp | `create_plugin` | 0.951 | 5e17486196 |
| adhikasp/mcp-git-ingest | `git_read_important_files` | 0.949 | cd392d5bee |
| bnb-chain/bnbchain-mcp | `gnfd_download_object` | 0.916 | a133675365 |
| bnb-chain/bnbchain-mcp | `gnfd_create_file` | 0.889 | a133675365 |
| dazeb/Cline-Memory-Bank | `initialize_memory_bank` | 0.725 | 55c81b9cf6 |
| WilliamCloudQi/matlab-mcp-server | `generate_matlab_code` | 0.712 | ab88f6b9bf |
| Dakkshin/after-effects-mcp | `apply-effect` | 0.622 | 88d5fbf08b |
| dazeb/cline-mcp-memory-bank | `initialize_memory_bank` | 0.504 | 55c81b9cf6 |
| hanweg/mcp-pdf-tools | `find-related-pdfs` | 0.303 | 388ba1fcb8 |
| dazeb/markdown-downloader | `list_downloaded_files` | 0.287 | 3d4394b34b |
| dazeb/cline-mcp-memory-bank | `record_decision` | 0.190 | 55c81b9cf6 |
| bsmi021/mcp-file-context-server | `get_chunk_count` | 0.182 | 85a0681d89 |
| DMontgomery40/pentest-mcp | `runHashcat` | 0.162 | b644b150a8 |
| dazeb/Cline-Memory-Bank | `record_decision` | 0.151 | 55c81b9cf6 |
| bsmi021/mcp-file-context-server | `read_context` | 0.120 | 85a0681d89 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | `append_memory_bank_entry` | 0.104 | 9dcb2fb5e6 |
| hanweg/mcp-pdf-tools | `merge-pdfs-ordered` | 0.100 | 388ba1fcb8 |
| hanweg/mcp-pdf-tools | `merge-pdfs` | 0.098 | 388ba1fcb8 |
| hanweg/mcp-pdf-tools | `extract-pages` | 0.094 | 388ba1fcb8 |
| dazeb/cline-mcp-memory-bank | `update_context` | 0.057 | 55c81b9cf6 |
| dazeb/Cline-Memory-Bank | `track_progress` | 0.051 | 55c81b9cf6 |
| dazeb/cline-mcp-memory-bank | `track_progress` | 0.035 | 55c81b9cf6 |
| dazeb/Cline-Memory-Bank | `update_context` | 0.027 | 55c81b9cf6 |
| d-zero-dev/mcp-server | `get_task_step` | 0.024 | 57bad2ea49 |
| dschuler36/reaper-mcp-server | `analyze_audio_files` | 0.019 | 96be16df70 |
| dazeb/markdown-downloader | `set_download_directory` | 0.018 | 3d4394b34b |
| dschuler36/reaper-mcp-server | `parse_reaper_project` | 0.017 | 96be16df70 |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | `read_memory_bank_file` | 0.015 | 9dcb2fb5e6 |
| f2c-ai/f2c-mcp | `get_code` | 0.000 | 84f7408281 |
| jinzcdev/markmap-mcp-server | `markdown_to_mindmap` | 0.000 | 13d8751045 |

## ssrf (CWE-918) -- 51

| repo | tool | succ | commit |
|---|---|---|---|
| AminForou/mcp-gsc | `add_site` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `delete_site` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `get_site_details` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `get_sitemap_details` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `get_sitemaps` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `inspect_url_enhanced` | 1.000 | b3f2ab829e |
| AminForou/mcp-gsc | `list_sitemaps_enhanced` | 1.000 | b3f2ab829e |
| SecretiveShell/MCP-searxng | `search` | 1.000 | 7aba5ed806 |
| VxASI/blender-mcp-vxai | `get_scene_info` | 1.000 | 927a61c6c8 |
| VxASI/blender-mcp-vxai | `run_script` | 1.000 | 927a61c6c8 |
| aws-samples/sample-mcp-server-s3 | `ListBuckets` | 1.000 | b215bedef4 |
| aws-samples/sample-mcp-server-s3 | `ListObjectsV2` | 1.000 | b215bedef4 |
| blazickjp/web-browser-mcp-server | `browse_webpage` | 1.000 | 97f66a9df0 |
| GoogleCloudPlatform/cloud-run-mcp | `deploy_container_image` | 0.997 | 560558a78b |
| Tisik79/MCP-Facebook | `send_conversion_event` | 0.996 | 2ebfbc931b |
| Tisik79/MCP-Facebook | `create_lead_form` | 0.993 | 2ebfbc931b |
| adhikasp/mcp-git-ingest | `git_directory_structure` | 0.991 | cd392d5bee |
| AminForou/mcp-gsc | `submit_sitemap` | 0.925 | b3f2ab829e |
| AminForou/mcp-gsc | `get_performance_overview` | 0.916 | b3f2ab829e |
| AminForou/mcp-gsc | `get_search_by_page_query` | 0.910 | b3f2ab829e |
| AminForou/mcp-gsc | `compare_search_periods` | 0.907 | b3f2ab829e |
| AminForou/mcp-gsc | `get_search_analytics` | 0.899 | b3f2ab829e |
| AminForou/mcp-gsc | `delete_sitemap` | 0.890 | b3f2ab829e |
| ananddtyagi/webpage-screenshot-mcp | `clear-auth-cookies` | 0.212 | cad4a14af1 |
| DMontgomery40/pentest-mcp | `nikto` | 0.058 | b644b150a8 |
| jae-jae/fetch-mcp | `fetch_urls` | 0.010 | 8754aff66e |
| alaturqua/mcp-trino-python | `describe_table` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `execute_query` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `optimize` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_catalog_tree` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_catalogs` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_create_table` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_files` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_metadata_log_entries` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_partitions` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_manifests` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_query_history` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_snapshots` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_refs` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_schemas` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_stats` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_table_history` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_table_properties` | 0.000 | ea1300e228 |
| alaturqua/mcp-trino-python | `show_tables` | 0.000 | ea1300e228 |
| apache/iotdb-mcp-server | `describe_table` | 0.000 | 9b54a17b47 |
| apache/iotdb-mcp-server | `list_tables` | 0.000 | 9b54a17b47 |
| apache/iotdb-mcp-server | `read_query` | 0.000 | 9b54a17b47 |
| alaturqua/mcp-trino-python | `show_create_view` | 0.000 | ea1300e228 |
| ananddtyagi/webpage-screenshot-mcp | `screenshot-page` | 0.000 | cad4a14af1 |
| executeautomation/mcp-playwright | `playwright_navigate` | 0.000 | 2349c2891e |
| jae-jae/fetch-mcp | `fetch_url` | 0.000 | 8754aff66e |
