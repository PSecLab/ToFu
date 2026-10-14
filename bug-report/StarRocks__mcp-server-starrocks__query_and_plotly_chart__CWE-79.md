# Missing output encoding in `query_and_plotly_chart`: the SQL text is echoed raw in error messages

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `query_and_plotly_chart` · **Tested commit:** `88e782b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`query_and_plotly_chart` runs a SQL query and turns the result into a Plotly chart. When the query fails, the tool returns `Error: Error executing statement '<query>': <driver error>` with the caller's SQL inserted unchanged. Markup and control characters in the query come back as-is, in both the text content and `structured_content.error_message`. This only matters if a client renders tool output as HTML or HTML-enabled Markdown, so the impact is low.

## Details
The message is built in the shared DB client, `src/mcp_server_starrocks/db_client.py:617-623` (the same format is used again at `:701-711`):

```python
        except (MySQLError, adbcError) as e:
            self._handle_db_error(e)
            return ResultSet(
                success=False,
                error_message=f"Error executing statement '{statement}': {str(e)}",
                execution_time=time.time() - start_time
            )
```

`query_and_plotly_chart` returns it unchanged, `src/mcp_server_starrocks/server.py:617-622`:

```python
        if errmsg:
            logger.warning(f"Query or data issue: {errmsg}")
            return ToolResult(
                content=[TextContent(type='text', text=f'Error: {errmsg}')],
                structured_content={'success': False, 'error_message': errmsg},
            )
```

Nothing escapes, truncates or strips control characters from `statement` on this path. The generic exception handler at `server.py:684-688` returns `str(err)` the same way.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is not needed: with nothing listening on the configured FE port (default `localhost:9030`), every query takes the error path above. With a reachable StarRocks, any statement it rejects takes the same path.
2. Start the server as the README describes: `uv run --with mcp-server-starrocks mcp-server-starrocks`. To test the tested commit, run `uv run --directory /path/to/mcp-server-starrocks mcp-server-starrocks` in a checkout at `88e782b`.
3. Call the tool:

   ```json
   {"query": "<b>tofu-poc</b>", "plotly_expr": "px.bar(df)"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["run", "--with", "mcp-server-starrocks", "mcp-server-starrocks"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("query_and_plotly_chart", {"query": "<b>tofu-poc</b>", "plotly_expr": "px.bar(df)"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `Error: Error executing statement '<b>tofu-poc</b>': ...` with the markup unchanged. The same string is in `structuredContent.error_message`.

## Expected behavior
Error messages do not repeat caller input verbatim. If the statement is useful for debugging, it is truncated and encoded (for example with `repr()` or JSON) and control characters are removed.

## Actual behavior
The SQL text is echoed verbatim. From the fuzzing run (StarRocks unreachable):

```
input:  {'query': '{{{{{{{{...{{{{', 'plotly_expr': '', 'format': '', 'db': ''}
output: Error: Error executing statement '{{{{{{{{...{{{{': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)
```

## Impact
The model chooses `query`, and prompt injection in untrusted content can steer it. This server exists to run model-chosen SQL, so whoever controls the argument already has more power than the echo gives them. The echo matters only for a client that renders tool output as HTML. Low severity, mostly a hardening item.

## Suggested fix
- In `db_client.py:621`, `:627`, `:705` and `:710`, stop embedding the full statement in `error_message`, or embed a short, encoded form such as `f"... statement {statement[:200]!r}: {e}"`.
- This one change also covers `read_query`, `write_query`, `table_overview`, `top_bad_tables` and `set_session_db`, which return the same message.
- Clients that render tool output should still escape it; the server cannot know the rendering context.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
No issue or pull request reports the SQL text being echoed in error messages. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "fix: reject non-read-only SQL in read_query and query_and_plotly_chart" (PR, open 2026-09-08): adds a SELECT/SHOW/DESCRIBE/EXPLAIN/WITH keyword check before `execute()` in this tool. It does not change the error text, so it does not fix this; if merged, the reproduction query must start with `SELECT` to reach the same error path.
- #43 "add HTML output for plotly, fix PNG output" (PR, closed 2026-06-17; the `format="html"` code is on the default branch): adds HTML chart files for this tool; unrelated to the error-message echo.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `${` and `{{`. `check_introspection_code_injection` also triggered for this tool; I did not review it here. It presumably relates to `eval(plotly_expr, {"px": px}, local_vars)` at `server.py:626`, guarded by `validate_plotly_expr` (`server.py:511-568`: single `px.<attr>(...)` call, no nested calls). In the evidence the DB was unreachable, so `eval` was never reached. Worth a separate look.
- Campaigns and executions: `corpus-sbx`, 2048 executions, 2042 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'query': '"qu${b\x0eu\x00\x00\x01\x00 \x00\x00{"qu;{\x00\x00\x00\x00\x00', 'plotly_expr': '', 'format': '', 'db': ''}`, output `Error: Error executing statement '"qu${b\x0eu\x00...': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)`
  - input `{'query': '{{{{...{{{{' (88 braces), ...}`, output `Error: Error executing statement '{{{{...': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)`
- Hand-check hints: **weak**. Only `{{` and `${` were echoed, into a plain-text error message; no rendering context. Same root cause as the `write_query`/`table_overview`/`top_bad_tables`/`set_session_db` CWE-79 drafts (`db_client.py:621`); `read_query` returns the same message too. File at most one combined issue for the repo. Driver text differs by OS (errno 111 on Linux). Steps not executed (read-only review).
</details>
