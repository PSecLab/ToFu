# Recovery probe — previously-dead corpus repos, re-prepared + fuzzed on the PSU PC — 2026-09-26

Arm `gpt41-recover-pc`. Target: the **231 repos with 0 reachable tools** in the
2026-09-22 corpus run (`corpus_unsuccessful_repos.txt`). Re-prepared with the
correct env (harness Python 3.13 + node 22) and fuzzed 60 s/tool under the
bubblewrap sandbox, on the PC's open egress (no proxy). Purpose: (1) measure how
much of the 482→249 executability drop was environment vs genuinely creds/backends,
and (2) catch bugs the **new tracers** (reflected-xss, exfil) surface on repos that
never executed before. Candidates are auto-triaged, **unconfirmed**.

> A first probe (quarantined, `quarantine-2026-09-26-recover-pc-badenv`) ran in a
> tmux that never sourced `.tofu_env.sh`: target venvs built on system Python 3.12
> (harness 3.13) + node v18; 0/2356 executed. Guards added (`0d05c93`) to fail fast
> on both. This report is the corrected re-run.

## Executability recovered (vs the VM's 0 on these repos)
| metric | value |
|---|---|
| repos probed | 218 of 231 (13 had no fuzzable config) |
| configs | 2,787 |
| repos with ≥1 tool that **executed** (n_exec>0) | **155** |
| repos with ≥1 tool that **returned success** | **21** |
| configs executed / succeeded / with alerts | 1,458 / 58 / 246 |

The 21 repos (58 tools) are genuine executability gains from correct env + open
egress — e.g. `prathammanocha/wordpress-mcp-server` recovered all 29 tools;
also sql-analyzer, datagov, uber-eats, bing-cn, and 1/123 in google_workspace.

Why the other ~197 still return 0 (from the run's error grouping):
- **(a) real environment exclusions** — live creds/backends required (Discord "not
  logged in", Ableton "not connected", InvalidCredentials, Graphlit org id). Stay excluded.
- **(b) seed-quality misses** — tool rejects OUR input for a missing required id
  ("Board ID required", "organization identifier required"). A ToFu seed defect;
  these STAY in the denominator, not an exclusion. Worth schema-aware seeds later.

## New candidates (all net-new: these repos produced 0 in the corpus run)
**56 candidates across 16 repos.**
By class: ssrf 28, log-injection 12, reflected-xss 9, insecure-temp-file 5, path-traversal 2.
**9 come from the new tracers** (reflected-xss) — impossible to find before they were added.
Examples: korean-spell `fix_korean_spell` (reflected-xss, 1.00),
sql-analyzer `lint_sql` (reflected-xss, 0.58) + `get_all_column_references` (0.56),
office `write_docx` (path-traversal, 0.68).

## Status / next
- Candidates unconfirmed (mandatory layer not subtracted; hand-verification owed).
- The VM sandboxed sweep (`gpt41-corpus-sbx`, the 250 reachable repos on current
  oracles) is still running; its new-tracer catches will be triaged the same way
  and merged into one report when it finishes.
- Slice logs (534 MB) on the PC (`/scratch/tofu/eval/runs/gpt41-recover-pc`) and
  Ananto's laptop (`~/pseclab/ToFu_repo24_results/recover-pc/`); gitignored.

## Candidates (full)
| repo | tool | class | tool exec-success rate (reachability, not a filter) | new-tracer |
|---|---|---|---|---|
| winterjung/mcp-korean-spell | `fix_korean_spell` | reflected-xss | 1.00 | yes |
| famano/mcp-server-office | `write_docx` | path-traversal | 0.68 |  |
| j4c0bs/mcp-server-sql-analyzer | `lint_sql` | reflected-xss | 0.58 | yes |
| j4c0bs/mcp-server-sql-analyzer | `get_all_column_references` | reflected-xss | 0.56 | yes |
| j4c0bs/mcp-server-sql-analyzer | `transpile_sql` | reflected-xss | 0.38 | yes |
| j4c0bs/mcp-server-sql-analyzer | `get_all_table_references` | reflected-xss | 0.35 | yes |
| thomasgazzoni/vsc-mcp | `write_file` | path-traversal | 0.32 |  |
| prathammanocha/wordpress-mcp-server | `get-stats-summary` | ssrf | 0.24 |  |
| cline/linear-mcp | `linear_auth` | ssrf | 0.24 |  |
| taylorwilsdon/google_workspace_mcp | `start_google_auth` | log-injection | 0.16 |  |
| prathammanocha/wordpress-mcp-server | `create-user` | ssrf | 0.15 |  |
| sunriseapps/imagesorcery-mcp | `config` | log-injection | 0.10 |  |
| prathammanocha/wordpress-mcp-server | `get-clicks` | ssrf | 0.07 |  |
| ZeparHyfar/mcp-datetime | `get_datetime` | log-injection | 0.00 |  |
| alaturqua/mcp-trino-python | `execute_query` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `expire_snapshots` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `optimize` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_catalog_tree` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_catalogs` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_create_view` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_manifests` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_partitions` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_query_history` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_schemas` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_snapshots` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_stats` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_table_history` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_table_properties` | ssrf | 0.00 |  |
| alaturqua/mcp-trino-python | `show_tables` | ssrf | 0.00 |  |
| antvis/mcp-server-chart | `generate_area_chart` | reflected-xss | 0.00 | yes |
| antvis/mcp-server-chart | `generate_column_chart` | reflected-xss | 0.00 | yes |
| antvis/mcp-server-chart | `generate_funnel_chart` | reflected-xss | 0.00 | yes |
| antvis/mcp-server-chart | `generate_radar_chart` | reflected-xss | 0.00 | yes |
| apache/iotdb-mcp-server | `describe_table` | ssrf | 0.00 |  |
| apache/iotdb-mcp-server | `list_tables` | ssrf | 0.00 |  |
| apache/iotdb-mcp-server | `read_query` | ssrf | 0.00 |  |
| chatmcp/mcp-server-collector | `extract-mcp-servers-from-url` | log-injection | 0.00 |  |
| nicknochnack/BuildMCPServer | `PredictChurn` | ssrf | 0.00 |  |
| nkapila6/mcp-local-rag | `deep_research` | insecure-temp-file | 0.00 |  |
| nkapila6/mcp-local-rag | `deep_research_ddgs` | insecure-temp-file | 0.00 |  |
| nkapila6/mcp-local-rag | `deep_research_google` | insecure-temp-file | 0.00 |  |
| nkapila6/mcp-local-rag | `rag_search_ddgs` | insecure-temp-file | 0.00 |  |
| nkapila6/mcp-local-rag | `rag_search_google` | insecure-temp-file | 0.00 |  |
| ryft-io/iceberg-mcp | `get_iceberg_tables` | ssrf | 0.00 |  |
| ryft-io/iceberg-mcp | `get_namespaces` | ssrf | 0.00 |  |
| ryft-io/iceberg-mcp | `get_table_partitions` | ssrf | 0.00 |  |
| ryft-io/iceberg-mcp | `get_table_properties` | ssrf | 0.00 |  |
| ryft-io/iceberg-mcp | `get_table_schema` | ssrf | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `crop` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `draw_arrows` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `draw_lines` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `draw_rectangles` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `draw_texts` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `fill` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `ocr` | log-injection | 0.00 |  |
| sunriseapps/imagesorcery-mcp | `rotate` | log-injection | 0.00 |  |
