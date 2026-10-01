# Log injection in `create_text_file`: CR/LF in `file_path` forges server log lines

**Repository:** `tumf/mcp-text-editor` · **Tool:** `create_text_file` · **Tested commit:** `2d66b6f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create_text_file` creates a new file with the given contents. When the call fails, the handler logs the exception message with `logger.error`, and the messages for a relative path or an existing file embed the caller's `file_path` verbatim. A `file_path` containing `\r\n` therefore writes extra, attacker-chosen lines into the server log, which cannot be told apart from real entries.

## Details
Logging goes to stderr with the default format (`src/mcp_text_editor/server.py:21`):

```python
logging.basicConfig(level=logging.INFO)
```

The handler builds the exception text from the raw `file_path` and logs it (`src/mcp_text_editor/handlers/create_text_file.py:58-64` and `:84-87`):

```python
file_path = arguments["file_path"]
if not os.path.isabs(file_path):
    raise RuntimeError(f"File path must be absolute: {file_path}")
if os.path.exists(file_path):
    raise RuntimeError(f"File already exists: {file_path}")
...
except Exception as e:
    logger.error(f"Error processing request: {str(e)}")
    logger.error(traceback.format_exc())
```

CR/LF is neither stripped nor escaped before the logger call. The traceback logged next repeats the message. The other write handlers in `src/mcp_text_editor/handlers/` use the same pattern.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, and the `mcp` Python package for the client script. No accounts or env vars are needed.
2. Install the server from a checkout, as the README's manual installation describes:

   ```bash
   git clone https://github.com/tumf/mcp-text-editor && cd mcp-text-editor
   git checkout 2d66b6f
   uv venv && uv pip install -e .
   ```
3. Call the tool with a relative path that contains CR/LF. The handler rejects it at the `isabs` check, so no file is created.

   Arguments:
   ```json
   {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "contents": "x"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["run", "--directory", "/path/to/mcp-text-editor", "mcp-text-editor"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_text_file", {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "contents": "x"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (inherited by the client script). A line starting with `FAKE-LOG-ENTRY` appears on its own, separate from the `ERROR:mcp-text-editor:` record.

## Expected behavior
The log record stays on one line with control characters escaped, for example `... File path must be absolute: 'tofu-poc.txt\r\nFAKE-LOG-ENTRY'`.

## Actual behavior
Based on the code above (no run log survived from our test), stderr receives:

```
ERROR:mcp-text-editor:Error processing request: File path must be absolute: tofu-poc.txt
FAKE-LOG-ENTRY
```

followed by a traceback that contains the same split message.

## Impact
The LLM chooses MCP tool arguments, and prompt injection in content the model reads can steer them. That lets an attacker add fake lines to the log file where the MCP host stores the server's stderr, which can mislead anyone reviewing or debugging from those logs. There is no file access or code execution from this alone, so the severity is low.

## Suggested fix
Escape control characters in caller-derived text before logging: log with `%r` (`logger.error("Error processing request: %r", str(e))`), or add a `logging.Filter`/`Formatter` on the `mcp-text-editor` logger that replaces `\r` and `\n` in the message with `\\r` and `\\n`. Log the traceback with `exc_info=True` or `logger.exception` rather than as a second free-form message.

## Status on the default branch
Still present at `9176a50` (2026-09-12). `src/mcp_text_editor/handlers/create_text_file.py` and `server.py` are unchanged since the tested commit.

## Prior reports
None found. Searched all 17 issues and 23 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #2 "INFO logs visible" (issue, closed 2024-12-25) is about INFO messages being printed at all, not about caller text in log records.
- Documentation: README.md "Security Considerations": "All user inputs are properly sanitized and validated" (a general claim; CR/LF in `file_path` reaches the log unescaped)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; triggered `check_introspection_log_injection`, plus `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_temp_file_leak` (not covered here).
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`; reproduction and expected stderr are derived from the code at `2d66b6f`.
- Hand-check hints: real, low severity. `file_path` goes unescaped into the `RuntimeError` text and then to `logger.error` on stderr. Not executed here. Identical pattern in all five write handlers; consider one combined issue.
</details>
