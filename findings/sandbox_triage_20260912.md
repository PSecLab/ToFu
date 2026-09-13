# ToFu sandbox run (gpt41-sandbox) — triage, 2026-09-12

Full run inside the container: 506 runs, 10.76 h. 72 executable, 330 zero-success,
104 llm=unknown (API tail). 48,414 raw alerts but heavily duplicated -> 65 distinct
signatures; only **28 runs were EXECUTABLE AND alerted** (the only findings pool).

## Verdict: NO new vulnerabilities beyond the two already confirmed.
Every executable+alerted candidate triaged to false positive, documented behavior,
or environment. Sink read + reasoning for each family below.

| tool(s) | sanitizer | verdict | why |
|---|---|---|---|
| DesktopCommander create_directory, list_directory | check_path_traversal | FP (documented) | createDirectory DOES call validatePath, but default `allowedDirectories: []` = "full access" per server.ts:346. Traversal is the intended default for an OS-control tool, not a bug. |
| bsv-mcp app_ordinals_data / app_sweep_scan / bsv_explore | check_resource_exhaustion | not a vuln | 3.4–4.3s single completions; these tools fetch external blockchain APIs. Network latency, not input-driven DoS. |
| DesktopCommander get_recent_tool_calls, list_directory | check_process_and_fd_leaks | not a vuln | leaked PIDs are sh/python3 children this terminal-control tool spawns by design. |
| cursor10x endConversation, storeDecision | check_log_injection / invalid_json | FP | storage via better-sqlite3 `db.prepare(?)` (parameterized); newlines/`__proto__` stored as data. |
| mcpFirebird list-available-tools, pluggedin clipboard_set | check_invalid_json | FP | type-confusion (`[object Object]`) echoed in output text; no sink. |
| google-workspace manage_scratchpad / manage_workspace | check_path_traversal | FP (positive control) | resolveWorkspacePath()+verifyPathSafety() reject escapes (established host-side). |

## Important: the two confirmed findings did NOT reproduce in the sandbox
- `excel-reader::export_to_json` / `export_to_csv`: **executable=no** in the Linux
  container (native build differs from macOS). V1 (arbitrary file write) NOT
  re-confirmed in-sandbox.
- locallama-mcp: native better-sqlite3 `ERR_DLOPEN_FAILED` on Linux -> tools did
  not execute. V2 (log injection) / V3 (update_server) NOT re-confirmed in-sandbox.
- CONSEQUENCE: V1/V2 stand on their HOST reproductions + directed tests
  (findings/confirmed/). The sandbox corpus loses exactly the repos where bugs were
  found -- a real macOS-vs-Linux corpus difference to state in the methodology, not
  a retraction of the findings.

## Borderline note (NOT filed as a finding)
DesktopCommander ships `allowedDirectories: []` = full filesystem access by default.
Documented, intended, and not ToFu's semantic-bug class -- so not a finding -- but a
legitimate "dangerous default" observation for the paper's discussion of MCP
deployment posture.

## Method
Only EXECUTABLE tools considered (330 zero-success excluded; their "0 findings" is
not evidence). Raw alert count ignored (48k, FP-dominated by bug-22 url/contract
sanitizers + silent-bug on tools that ignore input). Each candidate: read the sink,
reason from the tool's documented contract. Evidence logs +
index in findings/evidence/sandbox_triage_20260912/.
