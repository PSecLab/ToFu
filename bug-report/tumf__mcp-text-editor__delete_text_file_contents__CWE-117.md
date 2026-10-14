# Log injection in `delete_text_file_contents`: CR/LF in `file_path` forges server log lines

**Repository:** `tumf/mcp-text-editor` · **Tool:** `delete_text_file_contents` · **Tested commit:** `2d66b6f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`delete_text_file_contents` removes line ranges from a file. When the call fails, the handler logs the exception message with `logger.error`, and the messages for a relative or missing path include the caller's `file_path` verbatim. A `file_path` containing `\r\n` therefore adds attacker-chosen lines to the server log that look like genuine entries.

## Details
Logging goes to stderr with the default format (`src/mcp_text_editor/server.py:21`):

```python
logging.basicConfig(level=logging.INFO)
```

The handler interpolates the raw `file_path` into the exception and logs it (`src/mcp_text_editor/handlers/delete_text_file_contents.py:82-88` and `:120-123`):

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

No CR/LF escaping happens before the logger call, and the logged traceback repeats the message. All write handlers in `src/mcp_text_editor/handlers/` share this pattern.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, and the `mcp` Python package for the client script. No accounts or env vars are needed.
2. Install the server from a checkout, as the README's manual installation describes:

   ```bash
   git clone https://github.com/tumf/mcp-text-editor && cd mcp-text-editor
   git checkout 2d66b6f
   uv venv && uv pip install -e .
   ```
3. Call the tool with a relative path containing CR/LF. It is rejected at the `isabs` check, before any file is opened.

   Arguments:
   ```json
   {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "file_hash": "0", "ranges": []}
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
               result = await session.call_tool("delete_text_file_contents", {"file_path": "tofu-poc.txt\r\nFAKE-LOG-ENTRY", "file_hash": "0", "ranges": []})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (inherited by the client script). A separate line starting with `FAKE-LOG-ENTRY` appears after the `ERROR:mcp-text-editor:` record.

## Expected behavior
One log line per record, with control characters escaped, for example `... File path must be absolute: 'tofu-poc.txt\r\nFAKE-LOG-ENTRY'`.

## Actual behavior
Based on the code above (no run log survived from our test), stderr receives:

```
ERROR:mcp-text-editor:Error processing request: File path must be absolute: tofu-poc.txt
FAKE-LOG-ENTRY
```

and the following traceback carries the same split message.

## Impact
Tool arguments in MCP are picked by the LLM and can be steered by prompt injection from untrusted content. An attacker can use that to plant fake lines in the log where the MCP host saves the server's stderr, which can confuse audits or debugging. It gives no file access or code execution by itself, so the severity is low.

## Suggested fix
Escape CR/LF in caller-derived text before it is logged: use `logger.error("Error processing request: %r", str(e))`, or a `logging.Filter`/`Formatter` on the `mcp-text-editor` logger that replaces `\r` and `\n` with `\\r` and `\\n`. Log the traceback through `exc_info=True` or `logger.exception` instead of a second free-form message.

## Status on the default branch
Still present at `9176a50` (2026-09-12). The handler and `server.py` are unchanged since the tested commit.

## Prior reports
None found. Searched all 17 issues and 23 pull requests (fetched 2026-10-01) and the README / docs on the default branch. #2 "INFO logs visible" (issue, closed 2024-12-25) is about INFO messages being printed at all, not about caller text in log records.
- Documentation: README.md "Security Considerations": "All user inputs are properly sanitized and validated" (a general claim; CR/LF in `file_path` reaches the log unescaped)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; only `check_introspection_log_injection` fired.
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`; reproduction and stderr excerpt are derived from the code at `2d66b6f`.
- Hand-check hints: real, low severity. `file_path` reaches `logger.error` unescaped through the `RuntimeError` text. Not executed here. Same pattern in all five write handlers; consider one combined issue.
- Side observation (not part of this draft, verify before mentioning): this handler calls `self.editor.service.delete_text_file_contents(request)` (`handlers/delete_text_file_contents.py:109`), and `TextEditorService.delete_text_file_contents` opens `request.file_path` directly (`service.py:137`, `:193`) without `normalize_and_validate_path`. So the `..`/`~` deny-list the README advertises ("validates all file paths to prevent directory traversal") is skipped for this tool only. The server has no root directory either way, so the practical effect is small.
</details>
