# Missing output encoding in `write_query`: the SQL text is echoed raw in error messages

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `write_query` · **Tested commit:** `88e782b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`write_query` runs a DDL/DML statement. When the statement fails, the tool returns `Error: Error executing statement '<query>': <driver error>` with the caller's SQL inserted unchanged, in the text content and in `structured_content.error_message`. Markup and control characters in the query come back as-is. This only matters if a client renders tool output as HTML or HTML-enabled Markdown, so the impact is low.

## Details
`src/mcp_server_starrocks/server.py:390-403`:

```python
@mcp.tool(description="Execute a DDL/DML or other StarRocks command that do not have a ResultSet" + description_suffix)
def write_query(query: Annotated[str, Field(description="SQL to execute")],
                db: Annotated[str|None, Field(description="database")] = None,
                ctx: Context = None) -> ToolResult:
    logger.info(f"Executing write query: {query[:100]}{'...' if len(query) > 100 else ''}")
    result = db_client.execute(query, db=db, session_id=_safe_session_id(ctx))
    if not result.success:
        logger.error(f"Write query failed: {result.error_message}")
    ...
    return ToolResult(content=[TextContent(type='text', text=result.to_string(limit=2000))],
                      structured_content=result.to_dict())
```

For a failed result, `ResultSet.to_string` returns `f"Error: {self.error_message}"` (`db_client.py:106-107`). The `limit` only applies to rows, not to the error. `error_message` embeds the statement unchanged (`db_client.py:621`, `:627`, `:705`, `:710`).

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is not needed: with nothing listening on the configured FE port (default `localhost:9030`), every statement takes the error path. With a reachable StarRocks, any statement it rejects does too.
2. Start the server as the README describes: `uv run --with mcp-server-starrocks mcp-server-starrocks`. To test the tested commit, use `uv run --directory /path/to/mcp-server-starrocks mcp-server-starrocks` in a checkout at `88e782b`.
3. Call the tool:

   ```json
   {"query": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("write_query", {"query": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `Error: Error executing statement '<b>tofu-poc</b>': ...` with the markup unchanged.

## Expected behavior
Error messages do not repeat the statement verbatim, or include a truncated, encoded form with control characters removed.

## Actual behavior
The SQL text is echoed verbatim. From the fuzzing run (StarRocks unreachable):

```
input:  {'query': '{{1', 'db': ''}
output: Error: Error executing statement '{{1': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)
```

## Impact
The model chooses `query`, and prompt injection in untrusted content can steer it. The tool already executes the model's SQL, so the echo gives a caller nothing new. It only matters for a client that renders tool output as HTML. Low severity, hardening only.

## Suggested fix
- In `db_client.py:621`, `:627`, `:705` and `:710`, drop the statement from `error_message` or include a short encoded form such as `{statement[:200]!r}`.
- This one change also covers `read_query`, `query_and_plotly_chart`, `table_overview`, `top_bad_tables` and `set_session_db`.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #27 (issue, open) and #56 (PR, open) mention `write_query` only as the intended mutation path; no issue reports the SQL text being echoed in error messages.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `${` and `{{`.
- Campaigns and executions: `corpus-sbx`, 2048 executions, 2040 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'query': '"quer="yi"  :${', 'db': ''}` -> `Error: Error executing statement '"quer="yi"  :${': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)`
  - `{'query': '{{""ququery": "\'', 'db': ''}` -> `Error: Error executing statement '{{""ququery": "'': 2003 (HY000): ...`
  - `{'query': '{{1', 'db': ''}` -> `Error: Error executing statement '{{1': 2003 (HY000): ...`
- Hand-check hints: **weak**. Only `{{`/`${` echoed, into a plain-text error; the tool's purpose is to run caller SQL. Same root cause as the other StarRocks CWE-79 drafts (`db_client.py:621`); file at most one combined issue, or drop. Steps not executed (read-only review).
</details>
