# Missing output encoding in `table_overview`: the table argument is echoed raw in the overview header and errors

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `table_overview` · **Tested commit:** `88e782b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`table_overview` takes `table` (optionally `db.table`) and returns a text overview with columns, sample rows and a row count. The database and table names are inserted unchanged into the overview header, into the SQL statements, and into the error messages that echo those statements. Markup and control characters come back as-is. The result is also cached and returned again on later calls. The impact is low.

## Details
`src/mcp_server_starrocks/server.py:277-298` (inside `_get_table_details`, called from `table_overview` at `server.py:732`):

```python
    full_table_name = f"`{table_name}`"
    if db_name:
        full_table_name = f"`{db_name}`.`{table_name}`"
    ...
    output_lines.append(f"--- Overview for {full_table_name} ---")

    # 1. Get Row Count
    query = f"SELECT COUNT(*) FROM {full_table_name}"
    count_result = db_client.execute(query, db=db_name)
    ...
            output_lines.append(f"Error: {count_result.error_message}")
```

`table` is only split on the first `.` (`server.py:706-712`). Neither part is validated or has its backticks doubled. `count_result.error_message` repeats the full statement (`db_client.py:621`, `:705`). The string is stored in `global_table_overview_cache` (`server.py:325-328`), a process-wide cache keyed only by `(db_name, table_name)`. The error branches at `server.py:718` and `:721` echo `table` too.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is not needed: with nothing listening on the configured FE port (default `localhost:9030`), the row count query fails and the error is included. With a reachable StarRocks, an unknown table gives the same message shape.
2. Start the server as the README describes: `uv run --with mcp-server-starrocks mcp-server-starrocks`. To test the tested commit, use `uv run --directory /path/to/mcp-server-starrocks mcp-server-starrocks` in a checkout at `88e782b`.
3. Call the tool:

   ```json
   {"table": "tofu_db.<b>tofu-poc</b>", "refresh": true}
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
               result = await session.call_tool("table_overview", {"table": "tofu_db.<b>tofu-poc</b>", "refresh": True})
               print(result)

   asyncio.run(main())
   ```
4. The returned text starts with ``--- Overview for `tofu_db`.`<b>tofu-poc</b>` ---`` and ends with ``Error: Error executing statement 'SELECT COUNT(*) FROM `tofu_db`.`<b>tofu-poc</b>`': ...``, with the markup unchanged.

## Expected behavior
Names are checked against StarRocks identifier rules (or at least have backticks doubled) before they go into SQL, and the text output does not repeat raw caller input.

## Actual behavior
The names are echoed verbatim. From the fuzzing run (StarRocks unreachable):

```
input:  {'table': '"ta{{"mee.table"e\x00me.', 'refresh': False}
output: --- Overview for `"ta{{"mee`.`table"e\x00me.` ---

        Could not determine total row count.
        Error: Error executing statement 'SELECT COUNT(*) FROM `"ta{{"mee`.`table"e\x00me.`': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)
```

## Impact
The model chooses `table`, and prompt injection in untrusted content can steer it. The output is plain text, so the echo matters only for a client that renders tool output as HTML. A backtick in either name changes the SQL, but `read_query` and `write_query` already run arbitrary SQL, so that adds little. Because the cache is shared by all sessions of a server process, a cached overview with injected text is served to later callers who request the same `(db, table)` pair. That matters mainly for shared `http` deployments. Low severity.

## Suggested fix
- Validate `db_name` and `table_name` with `validate_sql_identifier` (`db_client.py:44-48`), as `get_table_schema` already does, or double backticks in each part before quoting.
- Encode names in the header (for example `{name!r}`), and shorten and encode the statement in `db_client.py:621`/`:705` so error messages do not repeat raw input. That change covers all tools.
- Consider not caching results that contain an error.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
- #58 "fix: validate db/table identifiers in table_overview before SQL interpolation" (PR, open 2026-09-28): adds `validate_sql_identifier` for `db_name` and `table_name` in this tool, the validation half of this draft. Not merged; the default branch still lacks the check. Invalid names would then raise `ValueError` before any SQL is built, but that message still contains the name via `repr()`, which leaves `<` and `>` intact, so the echo is reduced rather than removed.
- #33 "Validate identifiers and proc paths before interpolating them into SQL" (issue, closed 2026-08-21) / #49 "Validate identifiers and proc paths before interpolating into SQL" (PR, closed 2026-08-21, "Fixes #33"; its validators are on the default branch): same class, fixed at other call sites, not in `table_overview`.
- #28 "Bug: table_overview: description says "up to 5" but implementation uses LIMIT 3" (issue, closed 2026-02-23): same tool, unrelated.
- No issue or pull request reports the raw echo of the name in the overview text or error messages. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: missing identifier validation is addressed by open PR #58 (not merged at 88e782b). The echo/encoding part is not reported. If filed, reference #58.
- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2556 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'table': '"ta{{"mee.table"e\x00me.', 'refresh': False}` -> ``--- Overview for `"ta{{"mee`.`table"e\x00me.` ---\n\nCould not determine total row count.\nError: Error executing statement 'SELECT COUNT(*) FROM `"ta{{"mee`.`table"e\x00me.`': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)``
  - `{'table': '\x00\x00\x00\x00{{&."e\x00&.\x00\x00"e\x00t', 'refresh': False}` -> same shape
  - `{'table': '\x00\x00\x00\x00{{%."e\x00&.\x00\x00"e\x00t', 'refresh': False}` -> same shape
- Hand-check hints: **weak**. Only `{{` was echoed, into plain text. The cross-session cache point is from code reading; whether a cached error overview is served to another session depends on deployment (single-user stdio makes it moot). Same root cause as the other StarRocks CWE-79 drafts (`db_client.py:621`); file at most one combined issue. Steps not executed (read-only review).
</details>
