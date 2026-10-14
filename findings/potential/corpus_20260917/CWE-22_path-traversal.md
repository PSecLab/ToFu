# CWE-22 — Path Traversal / arbitrary file access (47 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `path-traversal` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| GoogleCloudPlatform/cloud-run-mcp | `deploy_local_folder` | node | 1.000 | 560558a78b | check_path_traversal | GoogleCloudPlatform__cloud-run-mcp__deploy_local_folder.log |
| aakarsh-sasi/memory-bank-mcp | `set_memory_bank_path` | node | 1.000 | 0813435550 | check_path_traversal | aakarsh-sasi__memory-bank-mcp__set_memory_bank_path.log |
| ihrpr/mcp-server-jupyter | `add_cell` | python | 1.000 | fb4427030f | check_file_access,check_introspection_incomplete_cleanup,check_introspection_sensitive_file_access,check_introspection_temp_file_leak,check_path_traversal | ihrpr__mcp-server-jupyter__add_cell.log |
| joshrutkowski/applescript-mcp | `finder_quick_look_file` | node | 1.000 | e6f4c2ee7d | check_path_traversal,check_process_and_fd_leaks | joshrutkowski__applescript-mcp__finder_quick_look_file.log |
| joshrutkowski/applescript-mcp | `finder_search_files` | node | 1.000 | e6f4c2ee7d | check_path_traversal | joshrutkowski__applescript-mcp__finder_search_files.log |
| Tisik79/MCP-Facebook | `upload_ad_media` | node | 0.999 | 2ebfbc931b | check_path_traversal | Tisik79__MCP-Facebook__upload_ad_media.log |
| Tisik79/MCP-Facebook | `create_video_post` | node | 0.995 | 2ebfbc931b | check_path_traversal | Tisik79__MCP-Facebook__create_video_post.log |
| gregkop/sketchfab-mcp-server | `sketchfab-download` | node | 0.994 | e5969ef858 | check_path_traversal | gregkop__sketchfab-mcp-server__sketchfab-download.log |
| horw/esp-mcp | `run_esp_idf_install` | python | 0.992 | 28afddf9ff | check_introspection_incomplete_cleanup,check_introspection_log_injection,check_introspection_temp_file_leak,check_path_traversal | horw__esp-mcp__run_esp_idf_install.log |
| antoinebou12/uml-mcp | `generate_uml_batch` | python | 0.980 | e3c007de86 | check_path_traversal | antoinebou12__uml-mcp__generate_uml_batch.log |
| StarRocks/mcp-server-starrocks | `read_query` | python | 0.975 | 88e782b0f3 | check_path_traversal | StarRocks__mcp-server-starrocks__read_query.log |
| aakarsh-sasi/memory-bank-mcp | `initialize_memory_bank` | node | 0.973 | 0813435550 | check_path_traversal | aakarsh-sasi__memory-bank-mcp__initialize_memory_bank.log |
| hanweg/mcp-pdf-tools | `search-pdfs` | python | 0.968 | 388ba1fcb8 | check_path_traversal | hanweg__mcp-pdf-tools__search-pdfs.log |
| fengin/image-gen-server | `generate_image` | python | 0.965 | 4ec89fefef | check_introspection_log_injection,check_introspection_weak_hash,check_path_traversal,check_resource_exhaustion | fengin__image-gen-server__generate_image.log |
| bsmi021/mcp-file-context-server | `generate_outline` | node | 0.964 | 85a0681d89 | check_path_traversal | bsmi021__mcp-file-context-server__generate_outline.log |
| Xuanwo/mcp-server-opendal | `read` | python | 0.963 | f49ee92cae | check_introspection_log_injection,check_path_traversal | Xuanwo__mcp-server-opendal__read.log |
| hyperb1iss/lucidity-mcp | `analyze_changes` | python | 0.955 | cdcb184bf1 | check_introspection_log_injection,check_path_traversal | hyperb1iss__lucidity-mcp__analyze_changes.log |
| Sheshiyer/framer-plugin-mcp | `create_plugin` | node | 0.951 | 5e17486196 | check_path_traversal | Sheshiyer__framer-plugin-mcp__create_plugin.log |
| adhikasp/mcp-git-ingest | `git_read_important_files` | python | 0.949 | cd392d5bee | check_introspection_incomplete_cleanup,check_introspection_temp_file_leak,check_path_traversal,check_resource_exhaustion | adhikasp__mcp-git-ingest__git_read_important_files.log |
| bnb-chain/bnbchain-mcp | `gnfd_download_object` | node | 0.916 | a133675365 | check_path_traversal | bnb-chain__bnbchain-mcp__gnfd_download_object.log |
| bnb-chain/bnbchain-mcp | `gnfd_create_file` | node | 0.889 | a133675365 | check_path_traversal | bnb-chain__bnbchain-mcp__gnfd_create_file.log |
| dazeb/Cline-Memory-Bank | `initialize_memory_bank` | node | 0.725 | 55c81b9cf6 | check_path_traversal | dazeb__Cline-Memory-Bank__initialize_memory_bank.log |
| WilliamCloudQi/matlab-mcp-server | `generate_matlab_code` | node | 0.712 | ab88f6b9bf | check_path_traversal | WilliamCloudQi__matlab-mcp-server__generate_matlab_code.log |
| Dakkshin/after-effects-mcp | `apply-effect` | node | 0.622 | 88d5fbf08b | check_path_traversal | Dakkshin__after-effects-mcp__apply-effect.log |
| dazeb/cline-mcp-memory-bank | `initialize_memory_bank` | node | 0.504 | 55c81b9cf6 | check_path_traversal | dazeb__cline-mcp-memory-bank__initialize_memory_bank.log |
| hanweg/mcp-pdf-tools | `find-related-pdfs` | python | 0.303 | 388ba1fcb8 | check_path_traversal | hanweg__mcp-pdf-tools__find-related-pdfs.log |
| dazeb/markdown-downloader | `list_downloaded_files` | node | 0.287 | 3d4394b34b | check_path_traversal | dazeb__markdown-downloader__list_downloaded_files.log |
| dazeb/cline-mcp-memory-bank | `record_decision` | node | 0.190 | 55c81b9cf6 | check_path_traversal | dazeb__cline-mcp-memory-bank__record_decision.log |
| bsmi021/mcp-file-context-server | `get_chunk_count` | node | 0.182 | 85a0681d89 | check_path_traversal | bsmi021__mcp-file-context-server__get_chunk_count.log |
| DMontgomery40/pentest-mcp | `runHashcat` | node | 0.162 | b644b150a8 | check_path_traversal | DMontgomery40__pentest-mcp__runHashcat.log |
| dazeb/Cline-Memory-Bank | `record_decision` | node | 0.151 | 55c81b9cf6 | check_path_traversal | dazeb__Cline-Memory-Bank__record_decision.log |
| bsmi021/mcp-file-context-server | `read_context` | node | 0.120 | 85a0681d89 | check_path_traversal | bsmi021__mcp-file-context-server__read_context.log |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | `append_memory_bank_entry` | node | 0.104 | 9dcb2fb5e6 | check_path_traversal | IncomeStreamSurfer__roo-code-memory-bank-mcp-server__append_memory_bank_entry.log |
| hanweg/mcp-pdf-tools | `merge-pdfs-ordered` | python | 0.100 | 388ba1fcb8 | check_path_traversal | hanweg__mcp-pdf-tools__merge-pdfs-ordered.log |
| hanweg/mcp-pdf-tools | `merge-pdfs` | python | 0.098 | 388ba1fcb8 | check_file_access,check_introspection_path_traversal,check_introspection_sensitive_file_access,check_path_traversal | hanweg__mcp-pdf-tools__merge-pdfs.log |
| hanweg/mcp-pdf-tools | `extract-pages` | python | 0.094 | 388ba1fcb8 | check_file_access,check_introspection_path_traversal,check_introspection_sensitive_file_access,check_path_traversal | hanweg__mcp-pdf-tools__extract-pages.log |
| dazeb/cline-mcp-memory-bank | `update_context` | node | 0.057 | 55c81b9cf6 | check_invalid_json,check_path_traversal | dazeb__cline-mcp-memory-bank__update_context.log |
| dazeb/Cline-Memory-Bank | `track_progress` | node | 0.051 | 55c81b9cf6 | check_invalid_json,check_path_traversal | dazeb__Cline-Memory-Bank__track_progress.log |
| dazeb/cline-mcp-memory-bank | `track_progress` | node | 0.035 | 55c81b9cf6 | check_invalid_json,check_path_traversal | dazeb__cline-mcp-memory-bank__track_progress.log |
| dazeb/Cline-Memory-Bank | `update_context` | node | 0.027 | 55c81b9cf6 | check_path_traversal | dazeb__Cline-Memory-Bank__update_context.log |
| d-zero-dev/mcp-server | `get_task_step` | node | 0.024 | 57bad2ea49 | check_path_traversal | d-zero-dev__mcp-server__get_task_step.log |
| dschuler36/reaper-mcp-server | `analyze_audio_files` | python | 0.019 | 96be16df70 | check_file_access,check_introspection_sensitive_file_access,check_path_traversal | dschuler36__reaper-mcp-server__analyze_audio_files.log |
| dazeb/markdown-downloader | `set_download_directory` | node | 0.018 | 3d4394b34b | check_path_traversal | dazeb__markdown-downloader__set_download_directory.log |
| dschuler36/reaper-mcp-server | `parse_reaper_project` | python | 0.017 | 96be16df70 | check_file_access,check_introspection_sensitive_file_access,check_path_traversal | dschuler36__reaper-mcp-server__parse_reaper_project.log |
| IncomeStreamSurfer/roo-code-memory-bank-mcp-server | `read_memory_bank_file` | node | 0.015 | 9dcb2fb5e6 | check_path_traversal | IncomeStreamSurfer__roo-code-memory-bank-mcp-server__read_memory_bank_file.log |
| f2c-ai/f2c-mcp | `get_code` | node | 0.000 | 84f7408281 | check_path_traversal | f2c-ai__f2c-mcp__get_code.log |
| jinzcdev/markmap-mcp-server | `markdown_to_mindmap` | node | 0.000 | 13d8751045 | check_path_traversal | jinzcdev__markmap-mcp-server__markdown_to_mindmap.log |
