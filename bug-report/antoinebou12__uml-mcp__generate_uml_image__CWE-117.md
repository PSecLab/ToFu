# Log injection in `generate_uml_image`: CR/LF in `diagram_type` or `output_format` forges log lines

**Repository:** `antoinebou12/uml-mcp` · **Tool:** `generate_uml_image` · **Tested commit:** `e3c007d`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`generate_uml_image` logs `diagram_type` and `output_format` at INFO level as soon as it is called, before either value is validated. A `\r` or `\n` inside them starts a new line in the server's log file and on stderr. A caller who can steer the tool arguments can insert fake log entries.

## Details
`mcp_core/tools/diagram_tools.py:314-319` (tested commit):

```python
logger.info(
    "Called generate_uml_image tool: type=%s, format=%s, code length=%s",
    diagram_type,
    output_format,
    len(code),
)
```

Both arguments are free strings here. The allow-list checks in `GenerateUMLInput` (`mcp_core/tools/schemas.py:74-124`) only run afterwards, in `generate_from_request`. Logging is configured in `mcp_core/core/cli.py:44-77`: a file handler on `logs/uml_mcp_server_<date>.log` with the plain format `%(asctime)s - %(name)s - %(levelname)s - %(message)s`, plus `RichHandler` on stderr. No handler escapes control characters.

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`. No network is needed; the call fails validation after the log line is written.
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
               result = await session.call_tool("generate_uml_image", {
                   "diagram_type": "class\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY",
                   "code": "@startuml\nclass A\n@enduml",
               })
               print(result)

   asyncio.run(main())
   ```
4. Run `grep -n FAKE-LOG-ENTRY /path/to/uml-mcp/logs/uml_mcp_server_*.log`. The forged entry appears on its own line. The same works with the payload in `output_format`.

## Expected behavior
Control characters in arguments are escaped before logging; one call gives one log line.

## Actual behavior
The value is logged raw. ToFu's log hook captured this from logger `mcp_core.tools.diagram_tools` (CR shown escaped; fuzzed bytes, not a forged entry):

```
Called generate_uml_image tool: type="diagram_type": "class", "code": "%_%_%_%_%_%_%_%", ... "outp\x0b\x0b \x19\x10\r\x12\x1et": "jpeg", ..., format=, code length=0
```

## Impact
The LLM chooses the arguments, and prompt injection can steer it. The attacker can add fake lines to the operator's log file and stderr, which makes the logs less trustworthy. The tool output is not affected. Low severity.

## Suggested fix
Log the values with `%r`, or add a `logging.Filter` that replaces `\r` and `\n` in the message for all handlers. Alternatively, log only after `GenerateUMLInput` has accepted `diagram_type` and `output_format`.

## Status on the default branch
Still present at `c598429` (2026-09-29): the same call is at `mcp_core/tools/diagram_tools.py:318-323`. Logging moved to `mcp_core/observability/logging_setup.py`. The default `text` format still writes the raw message. Only `logging.format: json` escapes newlines.

## Prior reports
- #335 "feat: uml-mcp.yaml config, MXCP-style audit trail, rate limits, lint, local install, admin dashboard (includes #333, #334)" (PR, closed 2026-09-25; merged, its `docs/configuration/uml-mcp-yaml.md` is on the default branch): added the `logging.format: text | json` setting. Only the opt-in `json` format escapes newlines; the default `text` format still writes the raw message. Partial mitigation, not a fix.
- Documentation: docs/configuration/uml-mcp-yaml.md: "format: json  # text | json (one JSON object per line)" and docs/enterprise/operations.md: "`logging.format: json` (one object per line ...)" (document the JSON log format as an option; nothing says text logs are unsafe for untrusted input). SECURITY.md: "Validate all input coming from external sources" (general advice to operators).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. Also fired: `check_introspection_code_injection`, `check_resource_exhaustion` (not covered here).
- Campaigns and executions: corpus-sbx 1024 exec / 27 ok (60 s); repo24-b 68608 / 1744, 55808 / 898, 54784 / 700 (4200 s each); e2-0922 512 / 2 (60 s).
- Evidence (verbatim, trimmed):
  - `{'diagram_type': 'mermaid', 'code': 'http://localhost:8080', 'output_format': 'png', ...}` -> logger `mcp_core.core.diagram_rendering`: `Fallback also failed for mermaid: Client error '400 Bad Request' for url 'https://mermaid.ink/img/pako:...?type=png'\nFor more information check: ...`. This newline is httpx's own fixed text in `HTTPStatusError`, not caller input; the code is pako-encoded in the URL. Not evidence of injection.
  - `{'diagram_type': '"diagram_type": "class", "code": "%_%_%_%_%_%_%_%", \x00...\x01"outp\x0b\x0b \x19\x10\r\x12\x1et": "jpeg", ...', 'code': '', 'output_format': '', ...}` -> output `None`, logged `Called generate_uml_image tool: type=... \r ..., format=, code length=0`. This one is real.
  - A third input of the same shape, same result.
- Hand-check hints: real but low severity, based on evidence 2 and 3 (caller CR reaches `logger.info` with `%s`, confirmed at `diagram_tools.py:314-319`). Discard evidence 1. The forged-entry payload is my substitution and was not run. Same pattern as `generate_uml`, `validate_uml`, `list_diagram_types`; consider one combined issue.
</details>
