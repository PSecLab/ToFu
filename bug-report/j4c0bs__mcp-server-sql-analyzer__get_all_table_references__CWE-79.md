# Missing output encoding in `get_all_table_references`: `dialect` and `sql` are echoed raw in error messages

**Repository:** `j4c0bs/mcp-server-sql-analyzer` · **Tool:** `get_all_table_references` · **Tested commit:** `d6d69c0`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_all_table_references` parses SQL with sqlglot and lists the tables and CTEs it references. If the dialect is unknown, the reply is `Unsupported dialect: <dialect>` with the caller's string inserted verbatim; if the SQL does not parse, the reply carries sqlglot's error text, which includes the input SQL and ANSI underline codes. Nothing is escaped or stripped, so a client that renders tool output as HTML or Markdown would render caller-supplied markup.

## Details
The tool calls the shared `_parse` helper (`src/mcp_server_sql_analyzer/server.py:168-170`), which builds the message from raw input (`server.py:62-83`):

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

The `ParseResult` is returned as-is (`server.py:169-170`). Control characters in the input, such as `\x7f` or ESC, pass through. The same helper serves `lint_sql`, `transpile_sql` and `get_all_column_references`, so one fix covers all four tools.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/j4c0bs/mcp-server-sql-analyzer.git mcp-server-sql-analyzer` (append `@d6d69c0c55826d6baa5033820078d1c72453ee33` to the URL to match the tested commit).
3. Call the tool with `{"sql": "SELECT a FROM t", "dialect": "<b>tofu-poc</b>"}`:

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
               print(await session.call_tool("get_all_table_references",
                                             {"sql": "SELECT a FROM t", "dialect": "<b>tofu-poc</b>"}))

   asyncio.run(main())
   ```
4. Observe: the result's `message` is `Unsupported dialect: <b>tofu-poc</b>`, markup unchanged.

## Expected behavior
An unknown dialect produces a fixed error that does not repeat the input verbatim (or repeats it quoted and length-limited), and parse errors are returned without raw control characters.

## Actual behavior
The input is echoed unchanged. Logged output from fuzzing, where the dialect string contained `\x7f` bytes and `{{{`:

```
{"is_valid": false, "message": "Unsupported dialect: \u007f\u007f\u007f\u007f\u007f\u007f\"l\"s{{{\u007f\u007f\u007f\u007f\u007f\u007f\u007fgr", "position": null}
```

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection, and the reflected text returns to the client. The output is JSON text, so in most MCP clients nothing renders. It matters only for a client or UI that renders tool output as HTML or Markdown without escaping, or a terminal that interprets escape sequences. Severity is low; this is a hardening issue.

## Suggested fix
- For an unknown dialect, return a fixed message such as `Unsupported dialect` (optionally with `repr(dialect)[:64]`) and point to `dialects://all`.
- For parse errors, build the message from the line and column already read from `e.errors[0]`, or strip control characters from `str(e)` (for example `re.sub(r"[\x00-\x08\x0b-\x1f\x7f]", "", str(e))`).

## Status on the default branch
Still present at `d6d69c0` (2025-07-01). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` (token `{{`), `check_invalid_json`; `check_introspection_type_confusion` also fired for this tool but is not part of this finding.
- Campaigns and executions: recover-pc 4608 exec / 1597 success.
- Evidence (verbatim, trimmed):
  - `{'sql': '"l"s{{{', 'dialect': ''}` -> `{"is_valid": false, "message": "Invalid expression / Unexpected token. Line 1, Col: 5.\\n  \\"l\\"s\\u001b[4m{\\u001b[0m{{", "position": {"line": 1, "column": 5}}`
  - `{'sql': '"sql": "/e"\x00\x00\x00: "post\x7f\x7f\x7f\x7f', 'dialect': '\x7f\x7f\x7f\x7f\x7f\x7f"l"s{{{\x7f\x7f\x7f\x7f\x7f\x7f\x7fgr'}` -> `Unsupported dialect: \u007f...\"l\"s{{{...gr`
- Hand-check hints: weak. Only `{{` template braces were echoed, into a JSON error string; the server has no HTML/Markdown rendering context, and reflecting the bad dialect/SQL in an error is ordinary behaviour. The `<b>tofu-poc</b>` call is derived from `server.py:65`, not from a log. Same root cause as the other three sql-analyzer drafts; consider one combined issue. Not run.
</details>
