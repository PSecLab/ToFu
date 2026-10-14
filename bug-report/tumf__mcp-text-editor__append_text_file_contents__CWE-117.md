# Log injection in `append_text_file_contents`: CR/LF in `file_path` forges server log lines

**Repository:** `tumf/mcp-text-editor` · **Tool:** `append_text_file_contents` · **Tested commit:** `2d66b6f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`append_text_file_contents` appends text to an existing file. When the call fails, the handler logs the exception message with `logger.error`, and several of those messages embed the caller's `file_path` verbatim. A `file_path` containing `\r\n` therefore writes extra, attacker-chosen lines into the server log. Anyone reading that log later cannot tell the forged lines from real ones.

## Details
Logging goes to stderr with the default format (`src/mcp_text_editor/server.py:21`):

```python
logging.basicConfig(level=logging.INFO)
```

The handler puts the raw `file_path` into the exception text and then logs it (`src/mcp_text_editor/handlers/append_text_file_contents.py:63-69` and `:105-108`):

```python
file_path = arguments["file_path"]
if not os.path.isabs(file_path):
    raise RuntimeError(f"File path must be absolute: {file_path}")
if not os.path.exists(file_path):
    raise RuntimeError(f"File does not exist: {file_path}")
...
except Exception as e:
    logger.error(f"Error processing request: {str(e)}")
    logger.error(traceback.format_exc())
```

Nothing strips or escapes CR/LF before the message reaches the logger. The traceback logged on the next line repeats the same message. The same pattern exists in every handler under `src/mcp_text_editor/handlers/`.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, and the `mcp` Python package for the client script. No accounts or env vars are needed.
2. Install and start the server from a checkout, as the README's manual installation describes:

   ```bash
   git clone https://github.com/tumf/mcp-text-editor && cd mcp-text-editor
   git checkout 2d66b6f
   uv venv && uv pip install -e .
   ```
3. Call the tool with a relative path that contains CR/LF. The handler rejects it before touching the filesystem, so no file is read or written.

   Arguments:
   ```json
   {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "file_hash": "0", "contents": "x"}
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
               result = await session.call_tool("append_text_file_contents", {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "file_hash": "0", "contents": "x"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (the client script inherits it, so it prints in the same terminal). A line that starts with `FAKE-LOG-ENTRY` appears on its own, outside the `ERROR:mcp-text-editor:` record that produced it.

## Expected behavior
The log record stays on one line, with control characters escaped, for example `ERROR:mcp-text-editor:Error processing request: File path must be absolute: 'tofu-poc.txt\r\nFAKE-LOG-ENTRY'`.

## Actual behavior
Based on the code above (no run log survived from our test), stderr receives:

```
ERROR:mcp-text-editor:Error processing request: File path must be absolute: tofu-poc.txt
FAKE-LOG-ENTRY
```

The traceback that follows contains the same split message.

## Impact
In MCP the tool arguments are chosen by the LLM, and prompt injection in a file or web page the model reads can steer them. An attacker who can do that can add fake lines to whatever file the MCP host writes the server's stderr into. That can hide activity or mislead someone debugging from the logs. It does not give file access or code execution, so the severity is low.

## Suggested fix
Escape control characters before logging caller-derived text. For example log with a format argument and `%r` (`logger.error("Error processing request: %r", str(e))`), or install a `logging.Filter`/`Formatter` on the `mcp-text-editor` logger that replaces `\r` and `\n` in `record.getMessage()` with `\\r` and `\\n`. Use `logger.exception(...)` or `exc_info=True` for the traceback instead of logging `traceback.format_exc()` as a second free-form message.

## Status on the default branch
Still present at `9176a50` (2026-09-12). The only change since the tested commit is in `src/mcp_text_editor/text_editor.py` (empty patch list check); the handlers are unchanged.

## Prior reports
None found. Searched all 17 issues and 23 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #2 "INFO logs visible" (issue, closed 2024-12-25) is about INFO messages being printed at all, not about caller text in log records.
- Documentation: README.md "Security Considerations": "All user inputs are properly sanitized and validated" (a general claim; CR/LF in `file_path` reaches the log unescaped)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; triggered `check_introspection_log_injection`, plus `check_introspection_incomplete_cleanup` and `check_introspection_temp_file_leak` (not covered by this draft).
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`, so the reproduction and the "Actual behavior" excerpt are derived from the code at `2d66b6f`, not from a captured run.
- Hand-check hints: real, low severity. `file_path` flows unescaped into `RuntimeError` text and then into `logger.error` (stderr, default `basicConfig` format). Not executed here. The single fuzzer call failed (0 successes), which fits the error path that does the logging. The same pattern is in all five write handlers (`append`, `create`, `delete`, `insert`, `patch`); consider filing one combined issue instead of five.
</details>
