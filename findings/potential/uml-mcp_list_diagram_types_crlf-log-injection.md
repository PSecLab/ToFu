# V5 (potential) — antoinebou12/uml-mcp `list_diagram_types`: caller-controlled CR/LF written unneutralized into the server log (CWE-117)

**Status: POTENTIAL.** Second Python-arm finding (item 86/89 fix, 2026-09-15).
Same weakness class as V2 (locallama, CONFIRMED) but a weaker sink: Python
`logging` (stderr / whatever handler the deployment attaches), not a file the
server itself owns.

| | |
|---|---|
| repo | antoinebou12/uml-mcp (13 stars; FastMCP 4 / mcp 2.1.1) |
| commit | `e3c007de860f0e4cdc9ed98e18e0fe84bba8d532` |
| tool | `list_diagram_types` (all-optional params: query, backend, output_format, limit) |
| sink | `mcp_core/tools/diagram_tools.py:80` — `logger.info("Called list_diagram_types: query=%s backend=%s format=%s limit=%s", ...)` with the raw caller strings |
| weakness | CWE-117 improper output neutralization for logs; CWE-93 CRLF |
| oracle | `check_introspection_log_injection` (LogInjectionTracer) — **not** in the LLM's selection for this run; fired through the evidence path (see attribution) |
| run | sandbox (Linux, py3.13), gpt-4.1 temp 0 seed 20260910, 30 s, `eval/sandbox/runs/smoke86/antoinebou12__uml-mcp__list_diagram_types.fuzz30c.log` |

## What ToFu observed (traceable to the log above)
```
target packages added to the atheris include set: ['app', 'mcp_core', 'server', 'tools']
EXEC_SUMMARY tool=list_diagram_types n_exec=14336 n_success=1532 success_rate=0.107
libFuzzer: cov 55 ft 109 corp 13, ~470 exec/s
alerts: 9, all check_introspection_log_injection; 5 distinct inputs, e.g.
  {'query': '"\x10\nery": null, "backend"', 'backend': None, 'output_format': '', 'limit': '0'}
  {'query': '"que\r\x06": null, "vvvvvvvv', 'backend': '癶癶癶癶癶癶扶', 'output_format': 'ckput_f', 'limit': None}
Tool Output : 'Returned 0 supported diagram type(s).'          <- SUCCESS, not an error
Analysis    : Unneutralized CRLF newline character detected in log output
              (logger:mcp_core.tools.diagram_tools)! Logged content:
              'Called list_diagram_types: query="\nery": null, "backend" backend=None format= limit=0'
```
The tool accepts the input, logs it verbatim (a `\n` inside `query` starts a
new, caller-authored log line), and returns success — the silent-bug shape.

## Why potential, not confirmed
- The sink is a `logging` call. Impact depends on where the deployment sends
  logs: with stderr on a developer laptop it is cosmetic; with the HTTP
  transport the project documents for Vercel / Cloud Run (`mcp_core/core/
  server.py` docstring) logs are aggregated and line-oriented, where forged
  records are the classic CWE-117 harm.
- No file is written by the server itself (contrast V2: locallama wrote a
  602 KB `subtask_results.log`).
- Fix is one line: `%r` / `repr()` on the four fields, or strip `\r\n`.

## Attribution (paper, RQ2/RQ3 — read this before citing)
`check_introspection_log_injection` was **not** among the sanitizers the LLM
selected for this tool (`['check_introspection_type_confusion',
'check_introspection_prototype_pollution', 'check_introspection_redos']`) and
is **not** in `BASE_MANDATORY_SANITIZERS`. It fired because
`fuzzer._run_sanitizers` gates every introspection check as
`if "<check>" in selected **or <tracer evidence present>**` — the
LogInjectionTracer recorded a logged message, so the check ran. On the Python
arm the introspection layer is therefore effectively always-on whenever a
tracer captures anything; an introspection alert is **not** evidence for the
LLM-selection design (HANDOFF §2 attribution trap). Recorded in nazmul.todo
2026-09-15; the same caveat now applies to V4's
`check_introspection_sensitive_file_access` (selected there, but would have
fired unselected).
