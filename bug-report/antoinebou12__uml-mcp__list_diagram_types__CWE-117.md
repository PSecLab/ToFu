# Log injection in `list_diagram_types`: CR/LF in `query`, `backend` or `output_format` forges log lines

**Repository:** `antoinebou12/uml-mcp` · **Tool:** `list_diagram_types` · **Tested commit:** `e3c007d`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list_diagram_types` takes optional filter strings and logs all of them at INFO level on every call. The values are logged raw, so a `\r` or `\n` in a filter starts a new line in the server log file and on stderr. A caller who can steer the arguments can add fake log entries. No network or backend is involved.

## Details
`mcp_core/tools/diagram_tools.py:79-85` (tested commit), the first statement of the tool:

```python
logger.info(
    "Called list_diagram_types: query=%s backend=%s format=%s limit=%s",
    query,
    backend,
    output_format,
    limit,
)
```

`query`, `backend` and `output_format` are free strings (`str | None`) and are never validated; they are only used as filters afterwards. Logging is configured in `mcp_core/core/cli.py:44-77`: a file handler on `logs/uml_mcp_server_<date>.log` with the plain format `%(asctime)s - %(name)s - %(levelname)s - %(message)s`, and `RichHandler` on stderr. No handler escapes control characters.

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`.
2. Install and start the server as the README describes:
   `git clone https://github.com/antoinebou12/uml-mcp.git && cd uml-mcp && git checkout e3c007d && uv sync`
3. Call the tool with:

   ```json
   {"backend": "x\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY"}
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
               result = await session.call_tool("list_diagram_types", {
                   "backend": "x\r\n2026-01-01 00:00:00,000 - mcp_core.tools.diagram_tools - INFO - FAKE-LOG-ENTRY",
               })
               print(result)

   asyncio.run(main())
   ```
4. Run `grep -n FAKE-LOG-ENTRY /path/to/uml-mcp/logs/uml_mcp_server_*.log`. The forged entry is on its own line.

## Expected behavior
Filter values are escaped before logging; one call gives one log line.

## Actual behavior
The values are logged raw. ToFu's log hook captured these messages from logger `mcp_core.tools.diagram_tools` (CR/LF shown escaped):

```
Called list_diagram_types: query=None backend=\rll,"ou format=None limit=None
Called list_diagram_types: query="\x0f\n\x1a\x14y": "test", "bt": " backend=vg", "limit": "0 format= limit=0
```

The tool itself returned `Returned 0 supported diagram type(s).`

## Impact
The LLM picks the filter values, and prompt injection can steer it. The attacker can write fake lines into the operator's log file and stderr. This tool is read-only and is often the first call a client makes, so it is easy to reach. Low severity.

## Suggested fix
Log the filters with `%r`, or install a `logging.Filter` / formatter that replaces `\r` and `\n` in log messages for every handler.

## Status on the default branch
Still present at `c598429` (2026-09-29): the same call is at `mcp_core/tools/diagram_tools.py:83-89`. Logging is now configured in `mcp_core/observability/logging_setup.py`. The default `text` format still writes the raw message. Only `logging.format: json` escapes newlines.

## Prior reports
- #316 "feat(mcp): harden result contracts, rendering, validation, and HTTP security" (PR, closed 2026-08-24): added the optional `query`, `backend`, `output_format` and `limit` filters to `list_diagram_types`, which are the values this log call writes. It does not mention logging. Origin of the arguments, not a fix.
- #335 "feat: uml-mcp.yaml config, MXCP-style audit trail, rate limits, lint, local install, admin dashboard (includes #333, #334)" (PR, closed 2026-09-25; merged, its `docs/configuration/uml-mcp-yaml.md` is on the default branch): added the `logging.format: text | json` setting. Only the opt-in `json` format escapes newlines; the default `text` format still writes the raw message. Partial mitigation, not a fix.
- Documentation: docs/configuration/uml-mcp-yaml.md: "format: json  # text | json (one JSON object per line)" and docs/enterprise/operations.md: "`logging.format: json` (one object per line ...)" (document the JSON log format as an option; nothing says text logs are unsafe for untrusted input). SECURITY.md: "Validate all input coming from external sources" (general advice to operators).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection` only.
- Campaigns and executions: corpus-sbx 3072 exec / 356 ok (60 s); repo24-b 254976 / 28932 (4200 s); e2-0922 1024 / 136 (60 s).
- Evidence (verbatim, trimmed):
  - `{'query': '"q\x14\x1a\r\x06]M_\x11at": null, "li', 'backend': 'it": "-1', 'output_format': '', 'limit': '-1'}` -> `'Returned 0 supported diagram type(s).'`, logged `Called list_diagram_types: query="q\x14\x1a\r\x06]M_\x11at": null, "li backend=it": "-1 format= limit=-1`.
  - `{'query': None, 'backend': '\rll,"ou', 'output_format': None, 'limit': None}` -> logged `... backend=\rll,"ou ...`.
  - `{'query': '"\x0f\n\x1a\x14y": "test", "bt": "', 'backend': 'vg", "limit": "0', 'output_format': '', 'limit': '0'}` -> logged with a raw LF.
- Hand-check hints: real but low severity. Caller CR/LF reaches `logger.info` with `%s` (confirmed at `diagram_tools.py:79-85`); file handler with plain format at `cli.py:53-59`. The forged-entry payload is my substitution and was not run. Same pattern as the other uml-mcp tools; consider one combined issue.
</details>
