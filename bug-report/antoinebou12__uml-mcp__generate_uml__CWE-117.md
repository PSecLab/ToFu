# Log injection in `generate_uml`: CR/LF in `diagram_type` forges lines in the server log

**Repository:** `antoinebou12/uml-mcp` · **Tool:** `generate_uml` · **Tested commit:** `e3c007d`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`generate_uml` logs the caller's `diagram_type` at INFO level before it validates it. The value goes into the log record as is, so a `\r` or `\n` inside it starts a new line in the daily log file and on stderr. Anyone who can influence the tool arguments can add fake entries that look like real server log lines.

## Details
`mcp_core/tools/diagram_tools.py:267-271` (tested commit), the first statement of the tool:

```python
logger.info(
    "Called generate_uml tool: type=%s, code length=%s",
    diagram_type,
    len(code),
)
```

`diagram_type` is a free string at this point. The allow-list check in `GenerateUMLInput.validate_diagram_type` (`mcp_core/tools/schemas.py:74-86`) only runs later, inside `generate_from_request`. So the log line is written even for values that are rejected afterwards.

The server's logging is set up in `mcp_core/core/cli.py:44-77`. It writes to `logs/uml_mcp_server_<date>.log` with the plain-text format `%(asctime)s - %(name)s - %(levelname)s - %(message)s` and to stderr through `RichHandler`. Neither handler escapes control characters.

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`. No network access is needed, because the call fails validation after the log line is written.
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
               result = await session.call_tool("generate_uml", {
                   "diagram_type": "class\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY",
                   "code": "@startuml\nclass A\n@enduml",
               })
               print(result)

   asyncio.run(main())
   ```
4. Run `grep -n FAKE-LOG-ENTRY /path/to/uml-mcp/logs/uml_mcp_server_*.log`. The forged entry sits on its own line, in the same format as a real one.

## Expected behavior
Control characters in tool arguments are escaped or removed before logging, so one call produces exactly one log line.

## Actual behavior
The raw value is logged. ToFu's log hook recorded this message from logger `mcp_core.tools.diagram_tools` (CR shown escaped, the run used fuzzed bytes rather than a forged entry):

```
Called generate_uml tool: type="diagram_type": "class", ... "theme": "../../../../etc/passwd", "\r..., code length=0
```

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in a document or web page it reads can steer them. An attacker can then write fake lines into the operator's log file and stderr, for example fake errors or fake request records, which makes logs less reliable for debugging or incident review. The tool output itself is not affected. Low severity.

## Suggested fix
Neutralize CR/LF before logging, for example log `diagram_type!r` (`%r`) instead of `%s`, or add a `logging.Filter` / formatter that replaces `\r` and `\n` in `record.getMessage()`. Logging only after `validate_diagram_type` has accepted the value also works for this field.

## Status on the default branch
Still present at `c598429` (2026-09-29). The log call is unchanged at `mcp_core/tools/diagram_tools.py:271-275`. Logging is now configured in `mcp_core/observability/logging_setup.py`. The default `text` format still writes the raw message. Only the optional `logging.format: json` setting escapes newlines, because it uses `json.dumps`.

## Prior reports
- #335 "feat: uml-mcp.yaml config, MXCP-style audit trail, rate limits, lint, local install, admin dashboard (includes #333, #334)" (PR, closed 2026-09-25; merged, its `docs/configuration/uml-mcp-yaml.md` is on the default branch): added the `logging.format: text | json` setting. Only the opt-in `json` format escapes newlines; the default `text` format still writes the raw message. Partial mitigation, not a fix.
- Documentation: docs/configuration/uml-mcp-yaml.md: "format: json  # text | json (one JSON object per line)" and docs/enterprise/operations.md: "`logging.format: json` (one object per line ...)" (document the JSON log format as an option; nothing says text logs are unsafe for untrusted input). SECURITY.md: "Validate all input coming from external sources" (general advice to operators).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. `check_resource_exhaustion` also fired for this tool (not covered here).
- Campaigns and executions: corpus-sbx 1536 exec / 59 ok (60 s); repo24-b 72192 / 1295 and 63488 / 1186 (4200 s each); e2-0922 512 / 29 (60 s).
- Evidence (verbatim, trimmed):
  - input `{'diagram_type': '"diagram_type": "class", "code": "class Example { }", "output_dir": null, "output_format": "svg", "theme": "../../../../etc/passwd", "\r\x1c\x1e\x13\x1aS]B', 'code': '', 'output_dir': '', 'output_format': '', 'theme': '', 'scale': 0.0}`, output `None`, logged `Called generate_uml tool: type=... "\r\x1c\x1e\x13\x1aS]B, code length=0` (logger `mcp_core.tools.diagram_tools`).
  - Two more inputs of the same shape, same logger and line.
- Hand-check hints: real but low severity. The CR came from the caller-controlled `diagram_type` and reached `logger.info` with `%s` (confirmed at `diagram_tools.py:267-271`); the file handler with plain-text format is set in `cli.py:53-59`. The forged-entry payload in the repro is my substitution and was not run. The same pattern exists in `generate_uml_image`, `validate_uml`, `list_diagram_types` and `generate_uml_batch` (`output_dir`); consider filing one combined issue for all five.
</details>
