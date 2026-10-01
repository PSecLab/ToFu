# Missing output encoding in `transpile_sql`: `sql` and dialect names are echoed raw in error messages

**Repository:** `j4c0bs/mcp-server-sql-analyzer` · **Tool:** `transpile_sql` · **Tested commit:** `d6d69c0`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`transpile_sql` converts SQL from one dialect to another with sqlglot. When the SQL does not parse, or `read_dialect` / `write_dialect` is unknown, the reply's `message` contains the caller's input verbatim: a slice of the SQL (with raw control characters and sqlglot's ANSI underline codes) or the dialect string. Nothing is escaped or stripped, so a client that renders tool output as HTML or Markdown would render caller-supplied markup.

## Details
`transpile_sql` first runs the shared `_parse` helper with `read_dialect` and returns its error unchanged (`src/mcp_server_sql_analyzer/server.py:120-122`). `_parse` interpolates raw input (`server.py:62-83`): `f"Unsupported dialect: {dialect}"` and `message=str(e)` for a sqlglot `ParseError`. The write dialect gets the same treatment (`server.py:124-129`):

```python
if not _valid_dialect(write_dialect):
    return ParseResult(
        is_valid=False,
        message=f"Unsupported write dialect: {write_dialect}",
        position=None,
    )
```

`str(e)` from sqlglot contains the SQL around the error and wraps the failing token in `\x1b[4m ... \x1b[0m`. The same `_parse` serves `lint_sql`, `get_all_table_references` and `get_all_column_references`.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/j4c0bs/mcp-server-sql-analyzer.git mcp-server-sql-analyzer` (append `@d6d69c0c55826d6baa5033820078d1c72453ee33` to the URL to match the tested commit).
3. Call the tool with `{"sql": "SELECT 1", "read_dialect": "sqlite", "write_dialect": "<b>tofu-poc</b>"}`, and with the logged input `{"sql": "%s %n %x {{{{{{{{{%p", "read_dialect": "sqlite", "write_dialect": ""}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/j4c0bs/mcp-server-sql-analyzer.git@d6d69c0c55826d6baa5033820078d1c72453ee33",
                 "mcp-server-sql-analyzer"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("transpile_sql", {
                   "sql": "SELECT 1", "read_dialect": "sqlite", "write_dialect": "<b>tofu-poc</b>"}))
               print(await session.call_tool("transpile_sql", {
                   "sql": "%s %n %x {{{{{{{{{%p", "read_dialect": "sqlite", "write_dialect": ""}))

   asyncio.run(main())
   ```
4. Observe: the first `message` is `Unsupported write dialect: <b>tofu-poc</b>`. The second echoes the SQL with `\u001b[4m` / `\u001b[0m` around the failing `%`.

## Expected behavior
Error messages do not carry caller input verbatim, or they neutralise it: control characters (including ESC) removed, and unknown dialect names omitted or quoted with `repr()` and length-limited.

## Actual behavior
The input is returned unchanged inside `message`. Logged output from fuzzing:

```
{"is_valid": false, "message": "Required keyword: 'this' missing for <class 'sqlglot.expressions.Mod'>. Line 1, Col: 4.\n  %s \u001b[4m%\u001b[0mn %x {{{{{{{{{%p", "position": {"line": 1, "column": 4}}
```

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection, and the reflected text returns to the client. The output is JSON text, so most MCP clients show it as plain text. The risk is limited to clients or UIs that render tool output as HTML or Markdown without escaping, or terminals that interpret the echoed escape sequences. Severity is low; this is a hardening issue.

## Suggested fix
- For unknown read or write dialects, return a fixed message (optionally with `repr(value)[:64]`) and point to `dialects://all`.
- For parse errors, build the message from the line and column already read from `e.errors[0]`, or strip control characters from `str(e)` (for example `re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(e))`). Apply the same to the `UnsupportedError` message at `server.py:141-143`.

## Status on the default branch
Still present at `d6d69c0` (2025-07-01). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only (token `{{`).
- Campaigns and executions: recover-pc 4608 exec / 1754 success.
- Evidence (verbatim, trimmed):
  - `{'sql': '%s %n %x {{{{{{{{{%p', 'read_dialect': 'sqlite', 'write_dialect': ''}` -> `{"is_valid": false, "message": "Required keyword: 'this' missing for <class 'sqlglot.expressions.Mod'>. Line 1, Col: 4.\\n  %s \\u001b[4m%\\u001b[0mn %x {{{{{{{{{%p", "position": {"line": 1, "column": 4}}`
  - `{'sql': '"sql": "%{"s %n %x {{{{{{{{{%p",q* "read_dia', 'read_dialect': '', 'write_dialect': ''}` -> `Invalid expression / Unexpected token. Line 1, Col: 12. ...` with the SQL echoed.
- Hand-check hints: weak. Only `{{` template braces were echoed, into a JSON error string; the server has no rendering context, and showing the failing SQL is normal for a transpiler. The `write_dialect` markup call is derived from `server.py:127`, not from a log. Same root cause as the other three sql-analyzer drafts; consider one combined issue. Not run.
</details>
