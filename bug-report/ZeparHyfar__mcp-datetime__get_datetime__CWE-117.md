# Log injection in `get_datetime`: CR/LF in an unknown `format` forges lines in the server log

**Repository:** `ZeparHyfar/mcp-datetime` · **Tool:** `get_datetime` · **Tested commit:** `d517593`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_datetime` looks up the caller's `format` in a fixed table. When the value is not in the table, the server logs the error message, and that message contains the raw `format` value. A value with CR/LF ends the log record early and adds a new line that looks like a real log entry. The log goes to stderr, and some MCP clients save that stream to a log file.

## Details
`format_datetime` puts the unchecked value into the exception text (`src/mcp_datetime/server.py:51-52`), and the tool handler logs that text unchanged (`src/mcp_datetime/server.py:107-116`):

```python
    if format_type not in formats:
        raise ValueError(f"Unknown format type: {format_type}")
...
    if name == "get_datetime":
        try:
            format_type = arguments.get("format")
            if not format_type:
                raise ValueError("Format type is required")
            formatted_time = format_datetime(format_type)
            return [TextContent(type="text", text=formatted_time)]
        except ValueError as e:
            logger.error("Format error: %s", str(e))
            raise RuntimeError(str(e)) from e
```

The logger is set up with `logging.basicConfig(level=logging.INFO)` (`server.py:12`), which writes `LEVEL:name:message` lines to stderr. Nothing escapes or strips control characters in `format_type` before line 115.

## Steps to reproduce
1. Prerequisites: Python 3.12+. No accounts or network access needed.
2. Install from source as the README describes: `git clone https://github.com/ZeparHyfar/mcp-datetime.git && cd mcp-datetime && pip install -e .` The entry point is `mcp-datetime`.
3. Call the tool with `{"format": "tofu-poc\r\nINFO:mcp-datetime:FAKE-LOG-ENTRY"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-datetime", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_datetime", {"format": "tofu-poc\r\nINFO:mcp-datetime:FAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (the client script lets it through to the terminal). It shows two lines:

   ```
   ERROR:mcp-datetime:Format error: Unknown format type: tofu-poc
   INFO:mcp-datetime:FAKE-LOG-ENTRY
   ```

   The second line was never logged by the server.

## Expected behavior
The invalid value is logged on one line, with CR/LF escaped (for example `'tofu-poc\r\nINFO:...'` via `%r`), or the value is left out of the log message.

## Actual behavior
The raw value is logged. The fuzzer captured this log record for the input `{'format': 'log\n/etc/shadow'}`:

```
Format error: Unknown format type: log\n/etc/shadow
```

## Impact
`format` is chosen by the LLM, so prompt injection from content the agent reads can set it. An attacker can add fake lines to the server's stderr log, or to the client's log file if the client stores server stderr. This can mislead someone reading the logs. There is no code execution or data access. Low severity.

## Suggested fix
Log the value with `%r`, or leave it out: `logger.error("Format error: unknown format type %r", format_type)`. A simpler option is to check `format_type` against the table before building the message and log only a fixed string. Building the `ValueError` message with `{format_type!r}` (`server.py:52`) also keeps the returned error to one line.

## Status on the default branch
Still present at `d517593` (2024-12-13). The default branch has no commits after the tested commit.

## Prior reports
None found. Searched the 1 issue and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` (runtime capture of logger `mcp-datetime` records). Also triggered: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak` (not part of this claim; no file handling in this server).
- Campaigns and executions: `recover-pc` 500 execs / 0 success (60 s); `e2-0922` 500 / 0 (60 s). Zero successes is expected: every fuzzed `format` is unknown and raises.
- Evidence (verbatim, trimmed): input `{'format': 'log\n/etc/shadow'}`, output `None`, logged `'Format error: Unknown format type: log\n/etc/shadow'`; input `{'format': '^\x19\x10\r\x12\x1e\x0bc:0"[]'}`, logged with raw `\r`; input `{'format': '\x00\x00\x00\x00\x00\x00\x00\r\x7f\x7f'}`, logged with raw `\r`.
- Hand-check hints: real. Caller `format` reaches `logger.error` at `server.py:115` unescaped, and ToFu's runtime tracer captured the record with the raw newline. Low severity: stderr only, no file handler in the server. The exact stderr text in step 4 is derived from the `basicConfig` default format, not run. Not verified: whether the RuntimeError comes back to the client as an `isError` result or a protocol error with this `mcp` version; the log line is written before that point either way.
</details>
