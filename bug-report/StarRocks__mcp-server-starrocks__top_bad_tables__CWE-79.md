# Missing output encoding in `top_bad_tables`: the `db` filter is echoed raw inside the failed SQL in the error message

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `top_bad_tables` · **Tested commit:** `88e782b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`top_bad_tables` ranks tables by a health score, optionally filtered by `db` and `table`. The filters are correctly quoted as SQL literals. When the query fails, though, the tool returns `Error getting top bad tables: Error executing statement '<full SQL>': ...`, which contains the filter values unchanged inside the roughly 100-line generated SQL. The impact is low.

## Details
The filters are quoted with `_sql_literal` (`src/mcp_server_starrocks/table_management_tools.py:23-24`, `:218-221`), so there is no SQL injection here. The echo comes from the error path, `table_management_tools.py:121-128`:

```python
        result = self.db_client.execute(sql)
        if not result.success:
            return {
                "success": False,
                "error": result.error_message or "Failed to get top bad tables.",
                "analysis_timestamp": now.isoformat(),
                "top_bad_tables": [],
            }
```

`result.error_message` embeds the whole statement (`db_client.py:621`, `:705`), and `format_top_bad_tables_analysis` returns it as text (`table_management_tools.py:366-367`):

```python
    if not result.get("success"):
        return f"Error getting top bad tables: {result.get('error', 'unknown error')}"
```

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is not needed: with nothing listening on the configured FE port (default `localhost:9030`), the query fails and the error is returned. Any other database error on this query takes the same path.
2. Start the server as the README describes: `uv run --with mcp-server-starrocks mcp-server-starrocks`. To test the tested commit, use `uv run --directory /path/to/mcp-server-starrocks mcp-server-starrocks` in a checkout at `88e782b`.
3. Call the tool:

   ```json
   {"db": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("top_bad_tables", {"db": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text starts with `Error getting top bad tables: Error executing statement '` and, near the end of the SQL, contains `db_name = '<b>tofu-poc</b>'` with the markup unchanged.

## Expected behavior
The error message names the failure without repeating the generated SQL and the caller's filter values verbatim.

## Actual behavior
The full SQL, including the filter, is echoed. From the fuzzing run (StarRocks unreachable), trimmed:

```
input:  {'db': '" *{"tab{{"ld', 'table': '', 'top_n': 0}
output: Error getting top bad tables: Error executing statement '
            SELECT *
            FROM (
            WITH tablet_base AS (
        ...
```

The full output contains the `db` value inside the `WHERE` clause.

## Impact
The model chooses `db`, and prompt injection in untrusted content can steer it. The output is plain text, so the echo matters only for a client that renders tool output as HTML. The long SQL in every error also wastes model context. Low severity.

## Suggested fix
- In `get_top_bad_tables` (and `get_top_hot_tables`, which has the same shape), return a short error such as `"Failed to get top bad tables: <driver error>"` without the statement.
- More generally, shorten and encode the statement in `db_client.py:621`/`:705`. That fixes the echo for every tool.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #46 "Add top bad tables health analysis tool" (PR, closed 2026-07-28) introduced the tool and says nothing about error output. No issue reports the SQL text being echoed in error messages.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{` and `${`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2554 successful, 60 s budget.
- Evidence (verbatim, trimmed): each output is the same ~100-line SQL, cut off in the evidence file before the `WHERE` clause.
  - `{'db': '" *{"tab{{"ld', 'table': '', 'top_n': 0}` -> `Error getting top bad tables: Error executing statement '\n            SELECT *\n            FROM (\n ...`
  - `{'db': 'y{{b""$"/db": "t_', 'table': '', 'top_n': 0}` -> same
  - `{'db': 'y"/dby": "t_db"${', 'table': '', 'top_n': 0}` -> same
- Hand-check hints: **weak**. Only `{{`/`${` echoed, inside a plain-text error, and the value is correctly SQL-quoted (single quotes doubled), so no SQL injection. The evidence output is truncated before the filter value; that the value appears in the message follows from `_build_top_bad_tables_sql` + `db_client.py:621` (code reading). `top_n: 0` is clamped to 1 by `_bounded_limit`. Same root cause as the other StarRocks CWE-79 drafts; file at most one combined issue. Steps not executed (read-only review).
</details>
