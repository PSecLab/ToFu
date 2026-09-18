# CWE-noclass — unclassified (11 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `unclassified` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| QuantGeekDev/docker-mcp | `deploy-compose` | python | 1.000 | 6dada7feb3 | check_introspection_path_traversal | QuantGeekDev__docker-mcp__deploy-compose.log |
| andybrandt/mcp-simple-arxiv | `update_categories` | python | 1.000 | fc9262eaa4 | check_introspection_insecure_file_permissions | andybrandt__mcp-simple-arxiv__update_categories.log |
| StarRocks/mcp-server-starrocks | `query_and_plotly_chart` | python | 0.969 | 88e782b0f3 | check_introspection_code_injection | StarRocks__mcp-server-starrocks__query_and_plotly_chart.log |
| aliyun/alibabacloud-dms-mcp-server | `addInstance` | python | 0.000 | f8e1ae32a5 | check_introspection_weak_hash | aliyun__alibabacloud-dms-mcp-server__addInstance.log |
| aliyun/alibabacloud-dms-mcp-server | `answerSqlSyntax` | python | 0.000 | f8e1ae32a5 | check_introspection_weak_hash | aliyun__alibabacloud-dms-mcp-server__answerSqlSyntax.log |
| aliyun/alibabacloud-dms-mcp-server | `approveOrder` | python | 0.000 | f8e1ae32a5 | check_introspection_weak_hash | aliyun__alibabacloud-dms-mcp-server__approveOrder.log |
| aliyun/alibabacloud-dms-mcp-server | `generateSql` | python | 0.000 | f8e1ae32a5 | check_introspection_weak_hash | aliyun__alibabacloud-dms-mcp-server__generateSql.log |
| aliyun/alibabacloud-dms-mcp-server | `searchDatabase` | python | 0.000 | f8e1ae32a5 | check_introspection_weak_hash | aliyun__alibabacloud-dms-mcp-server__searchDatabase.log |
| am0y/mcp-fal | `upload` | python | 0.000 | 9c57d9970d | check_introspection_path_traversal | am0y__mcp-fal__upload.log |
| ihrpr/mcp-server-jupyter | `edit_cell` | python | 0.000 | fb4427030f | check_file_access,check_introspection_sensitive_file_access | ihrpr__mcp-server-jupyter__edit_cell.log |
| ihrpr/mcp-server-jupyter | `read_output_of_cell` | python | 0.000 | fb4427030f | check_file_access,check_introspection_path_traversal,check_introspection_sensitive_file_access | ihrpr__mcp-server-jupyter__read_output_of_cell.log |
