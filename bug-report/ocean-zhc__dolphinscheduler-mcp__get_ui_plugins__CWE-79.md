# Missing output encoding in `get_ui_plugins`: an invalid `id` is echoed back verbatim in the error text

**Repository:** `ocean-zhc/dolphinscheduler-mcp` · **Tool:** `get_ui_plugins` · **Tested commit:** `d44f0bd`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_ui_plugins` looks up a DolphinScheduler UI plugin by ID. When `id` is not an integer, the tool returns `Invalid ID format: <id>` with the caller's string copied in unchanged. The result is plain text, so this only matters for MCP clients that render tool output as Markdown or HTML. We report it as low-severity missing output encoding.

## Details
The handler interpolates the raw `id` into the error (`src/dolphinscheduler_mcp/tools_generated/ui_plugin_tools.py:42` and `:54-58`):

```python
plugin_id = int(id) if id is not None else None
...
except ValueError:
    return {
        "success": False,
        "error": f"Invalid ID format: {id}"
    }
```

The generated wrapper returns `str(result)` as the tool's text (`src/dolphinscheduler_mcp/fastmcp_compat.py:71-73`), which leaves `<`, `>` and `{` as they are. The class `schema` declares `id` as `integer`, but `FastMCPTool._register` registers an untyped generated function instead (`fastmcp_compat.py:62-85`), so FastMCP passes any string through.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and the `mcp` Python package for the client script. No DolphinScheduler backend is needed, because a non-integer `id` fails before any request.
2. Install and start the server from a checkout (the README's `ds-mcp` entry point; `mcp.run()` defaults to stdio):

   ```bash
   git clone https://github.com/ocean-zhc/dolphinscheduler-mcp && cd dolphinscheduler-mcp
   git checkout d44f0bd
   pip install -e .
   ```
   The server writes its own log lines to stdout, so the client may print JSON parse warnings for them; they did not break our fuzzing sessions.
3. Call the tool with a non-integer `id`:

   ```json
   {"id": "<b>tofu-poc</b>{{x}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="ds-mcp", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_ui_plugins", {"id": "<b>tofu-poc</b>{{x}}"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the result text `{'success': False, 'error': 'Invalid ID format: <b>tofu-poc</b>{{x}}'}`, with the markup unchanged.

## Expected behavior
Non-integer IDs are rejected by schema validation, or the error does not echo the raw value (or encodes it for the output context).

## Actual behavior
The value is echoed back, markup characters included. From our run, this `id` (raw string value):

```
"id":`"{{\"$ne\":nu
```

returned this tool text (`repr` doubles the backslashes, the rest is unchanged):

```
{'success': False, 'error': 'Invalid ID format: "id":`"{{\\"$ne\\":nu'}
```

## Impact
The LLM picks `id`, and prompt injection from untrusted content can steer it. The echoed string goes back to the model and to the user's client. A client that renders tool results as HTML or Markdown could display injected markup; a plain-text client shows it as text. Low severity.

## Suggested fix
Return a fixed message such as `Invalid ID format: expected an integer`, or HTML-escape the value (`html.escape`) before including it. Better, register the tool with typed parameters (`id: int`) so FastMCP rejects non-integers before the handler runs. The same `f"Invalid ID format: {id}"` pattern appears in other generated tools.

## Status on the default branch
The tested commit `d44f0bd` (2025-05-14) is the current head of the default branch, so the code above is unchanged.

## Prior reports
- #1 "Add MseeP.ai badge to README" (PR, open 2025-05-03): a third-party badge PR whose automated scan flags `exec()` in `src/dolphinscheduler_mcp/fastmcp_compat.py:81`, the code that builds the untyped `tool_fn` wrapper mentioned above. It says nothing about echoed input or output encoding, so it is not a report of this bug and fixes nothing.
- No other issue or PR exists (0 issues, 2 PRs fetched 2026-10-01).
- Documentation: `src/dolphinscheduler_mcp/tools_generated/README.md`: the error-handling template returns the fixed text `"Invalid parameter format"` on `ValueError` (the project's own template does not echo the value; this tool departs from it). Nothing in the README or `docs/` about escaping.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` on all three evidence calls; `check_introspection_ssrf` also fired for this tool (not covered here).
- Campaigns and executions: `corpus-sbx` 3584/3584, 60 s budget.
- Evidence (decoded from the log's Python reprs, trimmed): input ``{'id': '"id":`"{{\\"$ne\\":nu'}`` -> tool text ``{'success': False, 'error': 'Invalid ID format: "id":`"{{\\"$ne\\":nu'}``. The other two calls add a trailing `{` or a leading `d`.
- Hand-check hints: weak. The only flagged token is `{{`, echoed into a plain-text `TextContent` built from `str(dict)`. No rendering context is known. The `<b>` payload in the reproduction is derived from the code, not observed. The backslashes in the evidence output are doubled because `str(dict)` uses `repr`, so the echo is not byte-for-byte; the `{{` is. The `check_introspection_ssrf` hit is probably the GET to the configured `DOLPHINSCHEDULER_API_URL` for integer IDs, not a caller-controlled URL.
</details>
