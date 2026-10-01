# Log injection in `execute_sql`: CR/LF from the `query` reaches the server log through MySQL error messages

**Repository:** `designcomputer/mysql_mcp_server` · **Tool:** `execute_sql` · **Tested commit:** `d88c510`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`execute_sql` runs a caller-supplied SQL statement. When MySQL rejects the statement, the server logs the MySQL error text with `logger.error` and no neutralization. MySQL error messages quote fragments of the statement (for example the `near '...'` part of a syntax error), so CR/LF characters in `query` end up as raw line breaks in the server log. Anyone who can influence the query can forge extra log lines.

## Details
`src/mysql_mcp_server/server.py:543-547` at `d88c510`:

```python
            except Error as e:
                # Extract and log specific MySQL error messages.
                error_msg = getattr(e, 'msg', None) or str(e) or 'Unknown MySQL error'
                logger.error(f"Error executing SQL: {error_msg}")
                return [TextContent(type="text", text=f"Error executing query: {error_msg}")]
```

Logging is set up at lines 28-32 with `logging.basicConfig` and the default format, so records go to stderr one message per line, with no escaping of `\r` or `\n`. In stdio mode, MCP clients usually capture the server's stderr into their own log files.

The `Calling tool:` line at 381 is not affected, because it formats the arguments dict with `repr()`, which escapes newlines. The generic handler at lines 413-415 also logs `str(e)` and a full traceback for non-MySQL exceptions; a traceback is multi-line by design, so that alone is not injection, but any exception message carrying caller text is written raw there too.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, and a disposable local MySQL 8 server. For example:
   ```
   docker run --rm -d --name tofu-mysql -e MYSQL_ALLOW_EMPTY_PASSWORD=yes -e MYSQL_DATABASE=tofu -p 127.0.0.1:3306:3306 mysql:8
   ```
   The statement below fails at parse time, so the database user needs no table privileges.
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
   {"query": "SELEC tofu\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="python",
           args=["-m", "mysql_mcp_server"],
           env={"MYSQL_HOST": "127.0.0.1", "MYSQL_PORT": "3306", "MYSQL_USER": "root",
                "MYSQL_PASSWORD": "", "MYSQL_DATABASE": "tofu"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("execute_sql", {"query": "SELEC tofu\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the server's stderr (printed in the same terminal) shows an `ERROR - Error executing SQL: You have an error in your SQL syntax; ... near 'SELEC tofu` record, and the next physical line starts with `FAKE-LOG-ENTRY`, outside the original record. The exact MySQL wording depends on the server version.

## Expected behavior
Each log record stays on one line. Control characters from caller input or from upstream error text are escaped (for example as `\r` and `\n`) before they are written.

## Actual behavior
The MySQL error text is written verbatim, so a line break in the query starts a new line in the log that looks like a separate entry.

## Impact
In MCP the LLM writes the SQL, and prompt injection in data the model reads (including rows returned by earlier queries) can steer it. An attacker can then add fake lines to the server log, for example to hide a destructive statement among invented entries or to mislead someone reviewing the client's MCP logs. This does not give data access beyond what `execute_sql` already allows. Severity is low.

## Suggested fix
Neutralize CR/LF before logging. The simplest option is to log `repr(error_msg)` at line 546, or to add a `logging.Filter`/`Formatter` that replaces `\r` and `\n` in `record.getMessage()` for every record. For lines 414-415, escape `str(e)` the same way and consider `logger.debug` for the full traceback.

## Status on the default branch
Still present at `d88c510` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
- No related issue or pull request among all 65 issues and 30 pull requests (fetched 2026-10-01). The security reports (#84, #89, #92) cover SQL injection, Dockerfile secrets and the unauthenticated SSE transport, not log output.
- Documentation: README.md: "Passwords and SSH private keys are automatically masked in server logs." (the only documented log sanitization; CR/LF in logged MySQL error text is not covered)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,558 ok (60 s); e2-0922 1,024 / 985 (60 s).
- Evidence (verbatim, trimmed): `{'query': ''}` -> `'Error calling tool execute_sql: Query is required'`, alert on logged content `'Traceback (most recent call last):\n  File ".../server.py", line 386, in call_tool\n    raise ValueError("Query is required")\nValueError: Query is required\n'`. The other two rows (`1' OR '1'='1`, `SELECT SLEEP(100);`) returned `Missing required database configuration` (no DB was configured in the run) and alerted on the same kind of traceback.
- Hand-check hints: unclear. The logged alerts are false positives as evidence: none of the inputs contained CR/LF, and the sanitizer fired on the newlines of a server-generated traceback (line 415). The fuzzing runs had no database, so the path in this draft (MySQL error text at line 546) was never exercised. The draft is derived from the code plus MySQL's usual `near '...'` error format, not from a run; verify with a real MySQL before filing. A stronger, DB-free variant of the same weakness exists in `get_schema_info`/`get_table_sample`: `validate_identifier` (line 43) puts the raw `table_name` into the exception that line 414 logs, so `\r\n` in `table_name` forges a log line without any database. Consider filing one CWE-117 issue covering both. `SECURITY.md` is a MySQL hardening guide, not a disclosure policy.
</details>
