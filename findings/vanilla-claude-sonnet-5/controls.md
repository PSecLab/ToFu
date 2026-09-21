# Control table -- vanilla-claude-sonnet-5 static audit (2026-09-21)
Reviewed blind: the reviewer prompt never named these repos/tools as controls, and the session was explicitly instructed to judge every tool fresh from the code, not from memory of prior findings ("do not think about vulnerabilities already found elsewhere"). Scored here, after the fact, against the plan's expected outcomes -- 5 positive controls (repos behind ToFu's own verified/potential findings), 1 corpus-hygiene item (item 91), 2 negative controls (a real guard the audit must not report a bypass of).

| id | repo | tool | expected | actual verdict | actual cwe | grounded | match | note |
|---|---|---|---|---|---|---|---|---|
| V1 | ArchimedesCrypto/excel-reader-mcp | `export_to_json` | flag | flag | CWE-22 | yes | yes |  |
| V1 | ArchimedesCrypto/excel-reader-mcp | `export_to_csv` | flag | flag | CWE-22 | yes | yes |  |
| V4 | tumf/mcp-text-editor | `get_text_file_contents` | flag | flag | CWE-22 | yes | yes |  |
| V5 | antoinebou12/uml-mcp | `list_diagram_types` | flag | clear | - | - | DIVERGES | Purely filters an in-memory dict of admin-defined diagram type metadata by substring/equality match; no file, network, or process sink is reachable from query/backend/output_format |
| V6 | tumf/mcp-text-editor | `create_text_file` | flag | flag | CWE-22 | yes | yes |  |
| V7 | yzfly/mcp-python-interpreter | `run_python_code` | flag | flag | CWE-22 | yes | yes |  |
| item91 | m-ahmed-elbeskeri/UltimateCoderMCP | `tool_delete_path` | flag | clear | - | - | DIVERGES | main.py:189-210 calls os.remove/shutil.rmtree on validate_path's unrestricted output; deleting any path the caller names is exactly what the tool's own docstring promises, no scopi |
| neg1 | aaronsb/google-workspace-mcp | `manage_scratchpad` | do NOT flag | flag | CWE-915 | yes | DIVERGES |  |
| neg2 | yzfly/mcp-python-interpreter | `read_file` | do NOT flag | clear | - | - | yes | file_path is resolved under WORKING_DIR and checked with is_path_allowed() (line 732) before being opened, which resolves symlinks/'..' and enforces containment via relative_to(). |
| neg2 | yzfly/mcp-python-interpreter | `write_file` | do NOT flag | clear | - | - | yes | file_path is resolved under WORKING_DIR and checked with is_path_allowed() (line 783) before opening for write, which resolves symlinks/'..' and enforces containment via relative_t |

**7/10 controls match the plan's expected outcome exactly.** A mismatch is not automatically an error -- see the per-row note and ToFu_src/nazmul.todo's 2026-09-21 control-table entry for the full reasoning behind each divergence (this audit's own stricter anti-FP rubric produced some of them; one negative control was flagged for a *different*, independently-found vulnerability class on the same tool, not a false positive against the original control).
