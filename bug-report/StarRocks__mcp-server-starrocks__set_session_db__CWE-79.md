# Missing output encoding in `set_session_db`: the database name is echoed raw and is not validated before `USE`

**Repository:** `StarRocks/mcp-server-starrocks` · **Tool:** `set_session_db` · **Tested commit:** `88e782b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`set_session_db` sets the default database for the current MCP session. It probes the name with ``USE `<db>` `` and returns either a success or a failure message that contains `db` twice, unchanged. Markup and control characters in the name are echoed as-is. The name is also not validated, although the repo already has `validate_sql_identifier` for this. The impact is low.

## Details
`src/mcp_server_starrocks/server.py:848-853`:

```python
    # Validate by issuing USE on a real connection.
    probe = db_client.execute(f"USE `{db}`")
    if not probe.success:
        return f"Failed to switch session to `{db}`: {probe.error_message}"
    db_client.set_session_default_db(session_id, db)
    return f"Per-session default database set to `{db}`."
```

`probe.error_message` embeds the full statement again (`db_client.py:621` and `:705`, ``Error executing statement 'USE `<db>`': ...``). A backtick inside `db` is not doubled, so it also ends the quoted identifier early. Other entry points validate names first: the `starrocks:///{db}/...` resources (`server.py:244-245`, `:253`) and `analyze_query` (`server.py:433-434`) call `validate_sql_identifier` (`db_client.py:44-48`). `set_session_db` does not.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. A StarRocks instance is not needed: with nothing listening on the configured FE port (default `localhost:9030`), the probe fails and the failure message is returned. With a reachable StarRocks, an unknown database name gives the same message shape.
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
               result = await session.call_tool("set_session_db", {"db": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is ``Failed to switch session to `<b>tofu-poc</b>`: Error executing statement 'USE `<b>tofu-poc</b>`': ...`` with the markup unchanged.

## Expected behavior
The name is checked against StarRocks identifier rules before use, and messages do not repeat raw caller input.

## Actual behavior
The name is echoed twice, verbatim. From the fuzzing run (StarRocks unreachable):

```
input:  {'db': '\x1d\x1d@{{{{{'}
output: Failed to switch session to `\x1d\x1d@{{{{{`: Error executing statement 'USE `\x1d\x1d@{{{{{`': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)
```

## Impact
The model chooses `db`, and prompt injection in untrusted content can steer it. The echoed text is a plain-text tool result, so it matters only for a client that renders tool output as HTML. The unescaped backtick lets a caller change the `USE` statement. That gains little here, because `read_query` and `write_query` already run arbitrary SQL. Low severity, mostly hardening.

## Suggested fix
- Call `validate_sql_identifier(db, "database")` at the top of `set_session_db`, as the resources and `analyze_query` already do. If StarRocks allows database names outside `^[A-Za-z_][A-Za-z0-9_]*$` that you want to support, at least double every backtick in `db` before building ``USE `...` ``.
- Return the name encoded (for example `{db!r}`) or leave it out of the failure message.
- The duplicate echo comes from `db_client.py:621`/`:705`. Shortening and encoding the statement there fixes this for every tool.

## Status on the default branch
Still present at `88e782b` (2026-09-08). The tested commit is the current head of the default branch.

## Prior reports
- #57 "set_session_db does not validate the db identifier before interpolating it into `USE `{db}``" (issue, open 2026-09-15): reports the missing `validate_sql_identifier` call in this tool, the second half of this draft. Not fixed on the default branch. It does not mention the raw echo in the reply.
- #56 "fix: reject non-read-only SQL in read_query and query_and_plotly_chart" (PR, open 2026-09-08): its body notes that `set_session_db` "interpolates db without validate_sql_identifier" and leaves it out of scope; no fix.
- #33 "Validate identifiers and proc paths before interpolating them into SQL" (issue, closed 2026-08-21) / #49 "Validate identifiers and proc paths before interpolating into SQL" (PR, closed 2026-08-21, "Fixes #33"; its validators are on the default branch): added identifier checks at five other call sites; `set_session_db` was not among them.
- No issue or pull request reports the raw echo of `db` in the reply text. Searched all 27 issues and 30 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: missing identifier validation already reported in open issue #57 (also noted in open PR #56); not fixed at 88e782b. The echo/encoding part is not reported. If filed, reference #57 and limit this to the echo.
- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2553 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'db': '\x1d\x1d@{{{{{'}` -> ``Failed to switch session to `\x1d\x1d@{{{{{`: Error executing statement 'USE `\x1d\x1d@{{{{{`': 2003 (HY000): Can't connect to MySQL server on 'localhost:9030' (111)``
  - `{'db': '\x1d\x1d@{{{\x01\x00'}` -> same shape
  - `{'db': '\x1d\x1d@\x00\x00\x00\x00\x00\x00{{{\x01\x00'}` -> same shape
- Hand-check hints: **weak**. Only `{{` was echoed, into plain text. The missing `validate_sql_identifier` call is the more useful observation, but it is low impact because the server exposes arbitrary SQL anyway. The fuzz run did get past the `session_id` check (`server.py:839-841`), so fastmcp supplied a session id over stdio. Same root cause as the other StarRocks CWE-79 drafts (`db_client.py:621`); file at most one combined issue. Steps not executed (read-only review).
</details>
