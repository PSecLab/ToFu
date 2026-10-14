# Missing output encoding in `get_all_column_references`: `sql` and `dialect` are echoed raw in error messages

**Repository:** `j4c0bs/mcp-server-sql-analyzer` · **Tool:** `get_all_column_references` · **Tested commit:** `d6d69c0`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_all_column_references` parses a SQL string with sqlglot and returns the column references. When the dialect is unknown or the SQL does not parse, the returned `message` contains the caller's `dialect` or a slice of the caller's `sql` verbatim, plus sqlglot's ANSI underline escape codes. Nothing is escaped or stripped. This is harmless when the client shows the result as plain text, but a client that renders tool output as HTML or Markdown will render caller-supplied markup.

## Details
The tool calls the shared `_parse` helper (`src/mcp_server_sql_analyzer/server.py:224-226`), which builds the message from raw input (`server.py:62-83`):

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

`str(e)` from sqlglot contains the SQL around the error position and wraps the failing token in `\x1b[4m ... \x1b[0m`. Control characters from the input, including ESC, pass through unchanged. The same `_parse` is used by `lint_sql`, `transpile_sql` and `get_all_table_references`, so one fix covers all four tools.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/j4c0bs/mcp-server-sql-analyzer.git mcp-server-sql-analyzer` (append `@d6d69c0c55826d6baa5033820078d1c72453ee33` to the URL to match the tested commit).
3. Call the tool with `{"sql": "SELECT a FROM t", "dialect": "<b>tofu-poc</b>"}`, and with the logged input `{"sql": "{\"\" {{\"\"", "dialect": ""}`:

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
               print(await session.call_tool("get_all_column_references",
                                             {"sql": "SELECT a FROM t", "dialect": "<b>tofu-poc</b>"}))
               print(await session.call_tool("get_all_column_references",
                                             {"sql": "{\"\" {{\"\"", "dialect": ""}))

   asyncio.run(main())
   ```
4. Observe: the first result's `message` is `Unsupported dialect: <b>tofu-poc</b>`, with the markup unchanged. The second result's `message` echoes the SQL with `\u001b[4m` / `\u001b[0m` around the failing token.

## Expected behavior
Error messages do not carry caller input verbatim into the result, or they neutralise it: control characters (including ESC) removed, and the unknown dialect either omitted or quoted with `repr()` and length-limited.

## Actual behavior
The input is returned unchanged inside `message`. Logged output from fuzzing:

```
{"is_valid": false, "message": "Expected }. Line 1, Col: 8.\n  {\"\" {{\u001b[4m\"\"\u001b[0m", "position": {"line": 1, "column": 8}}
```

## Impact
The tool arguments come from the model, which can be steered by prompt injection, and the reflected text goes back to the client. The result is JSON text in a `TextContent` block, so in most MCP clients this is not exploitable. It becomes a problem only in a client or web UI that renders tool output as HTML or Markdown without escaping, or prints it to a terminal that interprets escape sequences. Severity is low; this is a hardening issue.

## Suggested fix
- For an unknown dialect, return a fixed message such as `Unsupported dialect` (optionally with `repr(dialect)[:64]`) and point to the `dialects://all` resource.
- For parse errors, build the message from the line and column the code already reads from `e.errors[0]`, or at least strip control characters from `str(e)` (for example `re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(e))`) so the ANSI codes and raw control bytes do not reach the client.

## Status on the default branch
Still present at `d6d69c0` (2025-07-01). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` (token `{{` echoed), plus `check_invalid_json` (flags the JSON-looking input).
- Campaigns and executions: recover-pc 4608 exec / 2557 success.
- Evidence (verbatim, trimmed):
  - `{'sql': '{"" {{""', 'dialect': ''}` -> `{"is_valid": false, "message": "Expected }. Line 1, Col: 8.\\n  {\\"\\" {{\\u001b[4m\\"\\"\\u001b[0m", "position": {"line": 1, "column": 8}}`
  - `{'sql': '"sql"{{"" {M^users; --\\u202e.pdql"202e.pdql', 'dialect': ''}` -> message echoes the SQL with ANSI codes around `users`.
- Hand-check hints: weak. ToFu only saw template braces `{{` echoed into a JSON error string; no HTML/Markdown rendering context exists in this server, and echoing the bad SQL in a lint error is expected behaviour for a linter. The `<b>tofu-poc</b>` dialect call is derived from `server.py:65`, not from a log. The more concrete (still minor) observation is raw control characters and sqlglot ANSI codes passing through to the client (closer to CWE-150 than CWE-79). Consider filing one combined issue for all four tools instead of four. Not run.
</details>
