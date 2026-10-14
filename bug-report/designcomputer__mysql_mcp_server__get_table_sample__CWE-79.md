# Missing output encoding in `get_table_sample`: a rejected `table_name` is echoed raw in the error (and in the log)

**Repository:** `designcomputer/mysql_mcp_server` · **Tool:** `get_table_sample` · **Tested commit:** `d88c510`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_table_sample` returns a few rows from a table. It validates `table_name` with `validate_identifier`, which is good, but the rejection message embeds the raw value, and the tool returns that message to the client. Markup or template syntax in `table_name` therefore comes back unescaped. The same raw value is also written to the server log, so CR/LF in it can forge log lines. Neither needs a database connection.

## Details
`src/mysql_mcp_server/server.py:37-51` at `d88c510`:

```python
def validate_identifier(name: str) -> str:
    ...
    if not re.match(r'^[a-zA-Z0-9_$]+$', name):
        raise ValueError(f"Invalid identifier '{name}': only alphanumeric, underscore, and $ are allowed")
    return name

def parse_table_arg(name: str) -> Tuple[Optional[str], str]:
    ...
    return None, validate_identifier(name)
```

`call_tool` (`server.py:404-418`) calls `parse_table_arg(arguments.get("table_name"))` before any database work and catches the exception:

```python
        elif name == "get_table_sample":
            db, tbl = parse_table_arg(arguments.get("table_name"))
            ...
    except Exception as e:
        logger.error(f"Error in call_tool: {str(e)}")
        logger.error(traceback.format_exc())
        ...
        return [TextContent(type="text", text=f"Error calling tool {name}: {str(e)}")]
```

The identifier check itself blocks SQL injection into the backtick-quoted table reference. The problem is only that the rejected value is quoted back and logged as-is. A side note: `$` in `re.match` also matches just before a trailing newline, so `users\n` passes the check. Using `re.fullmatch(r'[A-Za-z0-9_$]+', name)` closes that.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. No database is needed: the call fails in `validate_identifier` before `get_db_config` runs.
2. Install the server from source:
   ```
   git clone https://github.com/designcomputer/mysql_mcp_server.git
   cd mysql_mcp_server && git checkout d88c510f603413d1abad9c5cce2bd542d705e27c
   uv venv .venv && source .venv/bin/activate
   uv pip install -e .
   ```
   The client script below starts it with `python -m mysql_mcp_server`.
3. Call the tool with these arguments:
   ```json
   {"table_name": "<b>tofu-poc</b>{{7*7}}", "limit": 5}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "mysql_mcp_server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_table_sample", {"table_name": "<b>tofu-poc</b>{{7*7}}", "limit": 5})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Error calling tool get_table_sample: Invalid identifier '<b>tofu-poc</b>{{7*7}}': only alphanumeric, underscore, and $ are allowed`. With `{"table_name": "tofu\r\nFAKE-LOG-ENTRY", "limit": 5}` instead, the server's stderr shows an `Error in call_tool: Invalid identifier 'tofu` record followed by a line that starts with `FAKE-LOG-ENTRY`.

## Expected behavior
A rejected identifier should produce a fixed message such as `Invalid table name: only letters, digits, _ and $ are allowed`, or quote an escaped and length-capped copy. Log records should stay on one line.

## Actual behavior
The rejected value is reflected verbatim. From the fuzzing run:

```
Error calling tool get_table_sample: Invalid identifier '""{{{': only alphanumeric, underscore, and $ are allowed
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in data the model reads can steer them. The tool result then carries caller-chosen markup into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low. The log path lets the same input add fake lines to the server log, also low severity.

## Suggested fix
Do not echo the rejected value in `validate_identifier`; a fixed message is enough. If you want to show it, use `repr(name)[:64]`. Switch the check to `re.fullmatch`. In `call_tool`, escape `\r` and `\n` in `str(e)` before logging (or log `repr(str(e))`), and consider moving the full traceback to `logger.debug`. The same change fixes `get_schema_info`, which shares `parse_table_arg`.

## Status on the default branch
Still present at `d88c510` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
- #89 "VULN: SQL Injection" (issue, closed 2026-05-31): SQL injection through the table name in `read_resource()`; it recommends whitelist validation of table names, which is what `validate_identifier` now does. It does not mention the rejected value being echoed or logged; not a report of this bug.
- #86 "feat: 添加多个新文件并改进功能" (PR, closed 2026-05-31): CHANGELOG.md credits this PR with "Added strict regex validation for all database and table identifiers". The PR body does not discuss the rejection message.
- #50 "An error" (issue, closed 2026-05-31): a report of an unhelpful error text ("Failed raising error."). CHANGELOG.md says global exception handling was added in response (Issue #50); that is the handler that now returns and logs `str(e)` unchanged. Not a security report.
- Documentation: README.md: "Other special characters are rejected to prevent SQL injection." (Security Considerations, about `get_schema_info` and `get_table_sample`; documents the validation but not the content of the rejection message)
- Documentation: README.md: "Passwords and SSH private keys are automatically masked in server logs." (the only documented log sanitization; line breaks are not covered)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`; `check_introspection_log_injection` fired on the same calls.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,040 ok (60 s).
- Evidence (verbatim, trimmed): `{'table_name': '""{{{', 'limit': 0}` -> `'Error calling tool get_table_sample: Invalid identifier \'""{{{\': only alphanumeric, underscore, and $ are allowed'`; `{'table_name': '{{"', 'limit': 0}` -> same shape. Log alert content: traceback from `server.py` line 405 -> 51 -> 43 ending `ValueError: Invalid identifier '{{"': only alphanumeric, underscore, and $ are allowed`.
- Hand-check hints: weak for the XSS framing. Only `{{` was reflected, into a plain-text error. The `<b>` and `\r\n` reproductions are derived from the code (lines 43, 414, 418), not from a logged run. The logged CWE-117 alert fired on the traceback's own newlines, not on CR/LF from input, so it is not evidence either; the DB-free log-forging path is real by code reading but unverified. Same root cause as `get_schema_info`; file one issue for both.
</details>
