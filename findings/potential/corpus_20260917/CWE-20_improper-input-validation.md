# CWE-20 — Improper Input Validation (37 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `improper-input-validation` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| Vortiago/mcp-outline | `export_all_collections` | python | 1.000 | 1e80cc98a7 | check_invalid_json | Vortiago__mcp-outline__export_all_collections.log |
| Vortiago/mcp-outline | `get_collection_structure` | python | 1.000 | 1e80cc98a7 | check_invalid_json | Vortiago__mcp-outline__get_collection_structure.log |
| ProgramComputer/NASA-MCP-server | `nasa_cmr` | node | 1.000 | 8d66b2b7fa | check_invalid_json | ProgramComputer__NASA-MCP-server__nasa_cmr.log |
| ProgramComputer/NASA-MCP-server | `nasa_donki` | node | 1.000 | 8d66b2b7fa | check_invalid_json | ProgramComputer__NASA-MCP-server__nasa_donki.log |
| ProgramComputer/NASA-MCP-server | `nasa_power` | node | 1.000 | 8d66b2b7fa | check_invalid_json | ProgramComputer__NASA-MCP-server__nasa_power.log |
| StevenStavrakis/mcp-starter-template | `some_function` | node | 1.000 | 57f51ff262 | check_invalid_json | StevenStavrakis__mcp-starter-template__some_function.log |
| Tisik79/MCP-Facebook | `create_adcreative` | node | 1.000 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__create_adcreative.log |
| Tisik79/MCP-Facebook | `get_ad` | node | 1.000 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__get_ad.log |
| Tisik79/MCP-Facebook | `get_lead_forms` | node | 1.000 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__get_lead_forms.log |
| aaronjmars/web3-research-mcp | `research-with-keywords` | node | 1.000 | e454995982 | check_invalid_json | aaronjmars__web3-research-mcp__research-with-keywords.log |
| bnb-chain/bnbchain-mcp | `register_erc8004_agent` | node | 1.000 | a133675365 | check_invalid_json | bnb-chain__bnbchain-mcp__register_erc8004_agent.log |
| gdli6177/mcp-prompt-server | `prompt_template_generator` | node | 1.000 | a27941f53b | check_invalid_json | gdli6177__mcp-prompt-server__prompt_template_generator.log |
| gdli6177/mcp-prompt-server | `project_architecture` | node | 1.000 | a27941f53b | check_invalid_json | gdli6177__mcp-prompt-server__project_architecture.log |
| jinzcdev/leetcode-mcp-server | `get_problem_solution` | node | 1.000 | 126115fc6e | check_invalid_json | jinzcdev__leetcode-mcp-server__get_problem_solution.log |
| jinzcdev/leetcode-mcp-server | `search_problems` | node | 1.000 | 126115fc6e | check_invalid_json | jinzcdev__leetcode-mcp-server__search_problems.log |
| ProgramComputer/NASA-MCP-server | `jpl_sentry` | node | 0.999 | 8d66b2b7fa | check_invalid_json | ProgramComputer__NASA-MCP-server__jpl_sentry.log |
| ProgramComputer/NASA-MCP-server | `nasa_mars_rover` | node | 0.999 | 8d66b2b7fa | check_invalid_json | ProgramComputer__NASA-MCP-server__nasa_mars_rover.log |
| Tisik79/MCP-Facebook | `create_custom_conversion` | node | 0.999 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__create_custom_conversion.log |
| Tisik79/MCP-Facebook | `estimate_audience_size` | node | 0.999 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__estimate_audience_size.log |
| Tisik79/MCP-Facebook | `send_conversion_events_batch` | node | 0.997 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__send_conversion_events_batch.log |
| Tisik79/MCP-Facebook | `upload_offline_conversions` | node | 0.997 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__upload_offline_conversions.log |
| gregkop/sketchfab-mcp-server | `sketchfab-search` | node | 0.994 | e5969ef858 | check_invalid_json | gregkop__sketchfab-mcp-server__sketchfab-search.log |
| Vortiago/mcp-azure-devops | `get_work_item_templates` | python | 0.981 | 1ce53765c7 | check_invalid_json | Vortiago__mcp-azure-devops__get_work_item_templates.log |
| Tisik79/MCP-Facebook | `create_custom_audience` | node | 0.973 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__create_custom_audience.log |
| CodeLogicIncEngineering/codelogic-mcp-server | `lineai-graph-search` | python | 0.971 | 6fdff87b42 | check_invalid_json | CodeLogicIncEngineering__codelogic-mcp-server__lineai-graph-search.log |
| CodeLogicIncEngineering/codelogic-mcp-server | `lineai-graph-validate-change-scope` | python | 0.970 | 6fdff87b42 | check_invalid_json | CodeLogicIncEngineering__codelogic-mcp-server__lineai-graph-validate-change-scope.log |
| Tisik79/MCP-Facebook | `update_custom_conversion` | node | 0.969 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__update_custom_conversion.log |
| CodeLogicIncEngineering/codelogic-mcp-server | `lineai-graph-impact` | python | 0.965 | 6fdff87b42 | check_invalid_json | CodeLogicIncEngineering__codelogic-mcp-server__lineai-graph-impact.log |
| Vortiago/mcp-azure-devops | `get_work_item_template` | python | 0.955 | 1ce53765c7 | check_invalid_json | Vortiago__mcp-azure-devops__get_work_item_template.log |
| ScrapeGraphAI/scrapegraph-mcp | `schema` | python | 0.928 | 8372895aa6 | check_invalid_json | ScrapeGraphAI__scrapegraph-mcp__schema.log |
| AminForou/mcp-gsc | `get_advanced_search_analytics` | python | 0.831 | b3f2ab829e | check_invalid_json | AminForou__mcp-gsc__get_advanced_search_analytics.log |
| cdugo/package-documentation-mcp | `fetch-multilingual-docs` | node | 0.270 | 9f8ac082cd | check_invalid_json | cdugo__package-documentation-mcp__fetch-multilingual-docs.log |
| Tisik79/MCP-Facebook | `search_geo_locations` | node | 0.223 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__search_geo_locations.log |
| Tisik79/MCP-Facebook | `create_campaign` | node | 0.120 | 2ebfbc931b | check_invalid_json | Tisik79__MCP-Facebook__create_campaign.log |
| Jacck/mcp-reasoner | `mcp-reasoner` | node | 0.114 | ee93c70d31 | check_invalid_json | Jacck__mcp-reasoner__mcp-reasoner.log |
| bnb-chain/bnbchain-mcp | `get_block_by_hash` | node | 0.107 | a133675365 | check_invalid_json | bnb-chain__bnbchain-mcp__get_block_by_hash.log |
| bnb-chain/bnbchain-mcp | `read_contract` | node | 0.072 | a133675365 | check_invalid_json | bnb-chain__bnbchain-mcp__read_contract.log |
