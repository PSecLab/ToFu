# CWE-400 — Uncontrolled Resource Consumption (DoS) (21 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `resource-exhaustion` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| DMontgomery40/pentest-mcp | `createClientReport` | node | 1.000 | b644b150a8 | check_resource_exhaustion | DMontgomery40__pentest-mcp__createClientReport.log |
| Skywork-ai/Skywork-Super-Agents | `generate_broadcast` | python | 1.000 | 38a10c36a5 | check_resource_exhaustion | Skywork-ai__Skywork-Super-Agents__generate_broadcast.log |
| Skywork-ai/Skywork-Super-Agents | `generate_ppt` | python | 1.000 | 38a10c36a5 | check_resource_exhaustion | Skywork-ai__Skywork-Super-Agents__generate_ppt.log |
| cdugo/package-documentation-mcp | `fetch-package-docs` | node | 1.000 | 9f8ac082cd | check_resource_exhaustion | cdugo__package-documentation-mcp__fetch-package-docs.log |
| bnb-chain/bnbchain-mcp | `write_contract` | node | 0.998 | a133675365 | check_invalid_json,check_resource_exhaustion | bnb-chain__bnbchain-mcp__write_contract.log |
| gannonh/memento-mcp | `get_graph_at_time` | node | 0.988 | be6dc36978 | check_resource_exhaustion | gannonh__memento-mcp__get_graph_at_time.log |
| 34892002/bilibili-mcp-js | `bilibili-search-summary` | node | 0.000 | 3537650dc1 | check_resource_exhaustion | 34892002__bilibili-mcp-js__bilibili-search-summary.log |
| Flux159/mcp-server-kubernetes | `node_management` | node | 0.000 | daf01de72a | check_resource_exhaustion | Flux159__mcp-server-kubernetes__node_management.log |
| aliyun/mcp-server-esa | `create_site_txt_record` | node | 0.000 | 2fc9e46e73 | check_resource_exhaustion | aliyun__mcp-server-esa__create_site_txt_record.log |
| aliyun/mcp-server-esa | `list_certificates` | node | 0.000 | 2fc9e46e73 | check_resource_exhaustion | aliyun__mcp-server-esa__list_certificates.log |
| aliyun/mcp-server-esa | `site_record_list` | node | 0.000 | 2fc9e46e73 | check_resource_exhaustion | aliyun__mcp-server-esa__site_record_list.log |
| antvis/mcp-server-chart | `generate_path_map` | node | 0.000 | e2a8fb7c18 | check_resource_exhaustion | antvis__mcp-server-chart__generate_path_map.log |
| antvis/mcp-server-chart | `generate_radar_chart` | node | 0.000 | e2a8fb7c18 | check_introspection_type_confusion,check_resource_exhaustion,check_unexpected_crash | antvis__mcp-server-chart__generate_radar_chart.log |
| baranwang/mcp-trends-hub | `get_douyin_trending` | node | 0.000 | 5a3a9942a5 | check_resource_exhaustion | baranwang__mcp-trends-hub__get_douyin_trending.log |
| baranwang/mcp-trends-hub | `get_ifanr_news` | node | 0.000 | 5a3a9942a5 | check_resource_exhaustion | baranwang__mcp-trends-hub__get_ifanr_news.log |
| baranwang/mcp-trends-hub | `get_infoq_news` | node | 0.000 | 5a3a9942a5 | check_resource_exhaustion | baranwang__mcp-trends-hub__get_infoq_news.log |
| baranwang/mcp-trends-hub | `get_tencent_news_trending` | node | 0.000 | 5a3a9942a5 | check_resource_exhaustion | baranwang__mcp-trends-hub__get_tencent_news_trending.log |
| bnb-chain/bnbchain-mcp | `gnfd_list_buckets` | node | 0.000 | a133675365 | check_resource_exhaustion | bnb-chain__bnbchain-mcp__gnfd_list_buckets.log |
| doggybee/mcp-server-ccxt | `batch-get-tickers` | node | 0.000 | b0b532334a | check_resource_exhaustion | doggybee__mcp-server-ccxt__batch-get-tickers.log |
| doggybee/mcp-server-ccxt | `get-ohlcv` | node | 0.000 | b0b532334a | check_resource_exhaustion | doggybee__mcp-server-ccxt__get-ohlcv.log |
| doggybee/mcp-server-ccxt | `get-orderbook` | node | 0.000 | b0b532334a | check_resource_exhaustion | doggybee__mcp-server-ccxt__get-orderbook.log |
