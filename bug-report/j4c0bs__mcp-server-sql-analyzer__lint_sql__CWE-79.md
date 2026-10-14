# Missing output encoding in `lint_sql`: `dialect` and `sql` are echoed raw in error messages

**Repository:** `j4c0bs/mcp-server-sql-analyzer` · **Tool:** `lint_sql` · **Tested commit:** `d6d69c0`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`lint_sql` parses SQL with sqlglot and returns either "No syntax errors" or the parse error. For an unknown dialect the reply is `Unsupported dialect: <dialect>` with the caller's string inserted verbatim, and for a parse error it is sqlglot's error text, which includes the input SQL, raw control characters and ANSI underline codes. Nothing is escaped or stripped. A client that renders tool output as HTML or Markdown would render caller-supplied markup.

## Details
`lint_sql` returns the result of the shared `_parse` helper directly (`src/mcp_server_sql_analyzer/server.py:101-102`). `_parse` builds the message from raw input (`server.py:62-83`):

```python
if not _valid_dialect(dialect):
    return None, ParseResult(
        is_valid=False,
        message=f"Unsupported dialect: {dialect}",
        position=None,
    )
...
except sqlglot.errors.ParseError as e:
    errors = e.errors[0]
    result = ParseResult(
        is_valid=False,
        message=str(e),
```

`str(e)` contains the SQL around the error with the failing token wrapped in `\x1b[4m ... \x1b[0m`. The same helper serves `transpile_sql`, `get_all_table_references` and `get_all_column_references`, so one fix covers all four tools.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/j4c0bs/mcp-server-sql-analyzer.git mcp-server-sql-analyzer` (append `@d6d69c0c55826d6baa5033820078d1c72453ee33` to the URL to match the tested commit).
3. Call the tool with `{"sql": "SELECT 1", "dialect": "<b>tofu-poc</b>"}`:

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
               print(await session.call_tool("lint_sql",
                                             {"sql": "SELECT 1", "dialect": "<b>tofu-poc</b>"}))

   asyncio.run(main())
   ```
4. Observe: the result's `message` is `Unsupported dialect: <b>tofu-poc</b>`, markup unchanged.

## Expected behavior
An unknown dialect produces a fixed error that does not repeat the input verbatim (or repeats it quoted and length-limited). Parse errors are returned without raw control characters or ANSI escape codes.

## Actual behavior
The input is echoed unchanged. Logged outputs from fuzzing:

```
{"is_valid": false, "message": "Unsupported dialect: t${\"s\"\u007f\"\r", "position": null}
{"is_valid": false, "message": "Expected }. Line 1, Col: 7.\n  {{\u0013P\u001e\f\u001b[4m]\u001b[0m\u007f\u007f\u007f\u0000", "position": {"line": 1, "column": 7}}
```

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection. The README suggests asking the assistant to run every generated query through `lint_sql`, so the tool is called often on text the model has assembled. The output is JSON text, so most MCP clients show it as plain text and nothing renders. The risk is limited to clients or UIs that render tool output as HTML or Markdown without escaping, or terminals that interpret the echoed escape sequences. Severity is low; this is a hardening issue.

## Suggested fix
- For an unknown dialect, return a fixed message such as `Unsupported dialect` (optionally with `repr(dialect)[:64]`) and point to `dialects://all`.
- For parse errors, build the message from the line and column already read from `e.errors[0]`, or strip control characters from `str(e)` (for example `re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(e))`).

## Status on the default branch
Still present at `d6d69c0` (2025-07-01). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only (tokens `{{` and `${`).
- Campaigns and executions: recover-pc 4608 exec / 2676 success.
- Evidence (verbatim, trimmed):
  - `{'sql': '{{\x13P\x1e\x0c]\x7f\x7f\x7f\x00', 'dialect': ''}` -> `{"is_valid": false, "message": "Expected }. Line 1, Col: 7.\\n  {{\\u0013P\\u001e\\f\\u001b[4m]\\u001b[0m\\u007f\\u007f\\u007f\\u0000", ...}`
  - `{'sql': '"s"\x7f"\r\x04\x7f\x7fe\r\x04\x7f\x7f', 'dialect': 't${"s"\x7f"\r'}` -> `{"is_valid": false, "message": "Unsupported dialect: t${\\"s\\"\\u007f\\"\\r", "position": null}`
- Hand-check hints: weak. Only template braces (`{{`, `${`) were seen echoed into a JSON error string; no rendering context in this server, and a linter echoing the bad input is expected. The `<b>tofu-poc</b>` call is derived from `server.py:65`, not from a log. The README "Tips" line about validating all generated SQL with `lint_sql` is real (README.md, "Tips" section). Same root cause as the other three sql-analyzer drafts; consider one combined issue. Not run.
</details>
