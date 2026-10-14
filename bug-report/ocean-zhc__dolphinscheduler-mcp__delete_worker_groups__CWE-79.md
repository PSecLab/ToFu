# Missing output encoding in `delete_worker_groups`: an invalid `id` is echoed back verbatim in the error text

**Repository:** `ocean-zhc/dolphinscheduler-mcp` · **Tool:** `delete_worker_groups` · **Tested commit:** `d44f0bd`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`delete_worker_groups` deletes a DolphinScheduler worker group by ID. When `id` is not an integer, the tool returns `Invalid ID format: <id>` with the caller's string copied in unchanged. The tool result is plain text, so this is only a problem if an MCP client renders tool output as Markdown or HTML. We report it as missing output encoding of low severity.

## Details
The handler interpolates the raw `id` into the error (`src/dolphinscheduler_mcp/tools_generated/worker_group_tools.py:187` and `:199-203`):

```python
worker_group_id = int(id) if id is not None else None
...
except ValueError:
    return {
        "success": False,
        "error": f"Invalid ID format: {id}"
    }
```

The generated wrapper turns the dict into the tool's text result with `str(result)` (`src/dolphinscheduler_mcp/fastmcp_compat.py:71-73`). Python's `repr` of the string leaves markup characters such as `<`, `>` and `{` untouched. The `integer` type declared in the class `schema` is not applied, because `FastMCPTool._register` registers an untyped generated function instead (`fastmcp_compat.py:62-85`), so any string reaches the handler.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and the `mcp` Python package for the client script. No DolphinScheduler backend is needed: a non-integer `id` fails before any request, so nothing is deleted.
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
               result = await session.call_tool("delete_worker_groups", {"id": "<b>tofu-poc</b>{{x}}"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the result text `{'success': False, 'error': 'Invalid ID format: <b>tofu-poc</b>{{x}}'}`, with the markup unchanged.

## Expected behavior
Non-integer IDs are rejected by schema validation, or the error message does not echo the raw value (or encodes it for the output context).

## Actual behavior
The value is echoed verbatim. From our run, input `{'id': '{{'}` returned:

```
{'success': False, 'error': 'Invalid ID format: {{'}
```

## Impact
The LLM chooses `id`, and prompt injection from untrusted content can steer it. The echoed text goes back to the same model and to the user's client. If that client renders tool results as HTML or Markdown, injected markup could display there; with a plain-text client nothing happens. This is a low-severity hardening issue.

## Suggested fix
Return a fixed message such as `Invalid ID format: expected an integer` without the raw value, or HTML-escape it (`html.escape`) before including it. Better, register the tool with typed parameters (`id: int`) so FastMCP rejects non-integers before the handler runs; the same applies to the other generated tools that use this pattern.

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
- Evidence (verbatim, trimmed): input `{'id': '{{"d'}` -> `{'success': False, 'error': 'Invalid ID format: {{"d'}`; input `{'id': '{{'}` -> `{'success': False, 'error': 'Invalid ID format: {{'}`.
- Hand-check hints: weak. Only template braces `{{` were observed echoed, into a plain-text tool result (`TextContent` built from `str(dict)`). No HTML rendering context is known. The `<b>` payload in the reproduction is derived from the code (`f"Invalid ID format: {id}"`), not from a run. Do not use an integer `id` when testing: that would send a real DELETE to the backend. The `check_introspection_ssrf` hit is probably the call to the configured `DOLPHINSCHEDULER_API_URL` (default `http://localhost:12345/dolphinscheduler`), not a caller-controlled URL.
</details>
