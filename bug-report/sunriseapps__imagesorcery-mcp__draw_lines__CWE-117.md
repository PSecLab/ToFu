# Log injection in `draw_lines`: CR/LF in `input_path` is written unescaped to the server log

**Repository:** `sunriseapps/imagesorcery-mcp` · **Tool:** `draw_lines` · **Tested commit:** `2f77957`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`draw_lines` draws lines on the image at `input_path`. It logs `input_path` with an f-string before validating it (`draw_lines.py:50`), and again when the file does not exist (`draw_lines.py:54`). The `imagesorcery` logger writes messages as they are, so `\r\n` inside the argument starts a new, unprefixed line in `imagesorcery.log` and on stderr. A caller can forge or split log entries.

## Details
`draw_lines.py:50` logs the caller's `input_path` before any check, and `draw_lines.py:54` logs it again when the path does not exist:

```python
# src/imagesorcery_mcp/tools/draw_lines.py:50-55
logger.info(f"Draw lines tool requested for image: {input_path} with {len(lines)} lines")

# Check if input file exists
if not os.path.exists(input_path):
    logger.error(f"Input file not found: {input_path}")
    raise FileNotFoundError(f"Input file not found: {input_path}. Please provide a full path to the file.")
```

The `imagesorcery` logger is configured in `src/imagesorcery_mcp/logging_config.py:15-31`: a `RotatingFileHandler` on `logs/imagesorcery.log` next to the package and a `StreamHandler` on stderr, both with the format `'%(asctime)s - %(name)s.%(module)s:%(lineno)d - %(levelname)s - %(message)s'`. No filter or formatter escapes CR or LF in `%(message)s`, and the argument is a plain `str` field, so pydantic accepts `\r\n` in it.

The value reaches the log a third time. `server.py:64-68` installs FastMCP's `ErrorHandlingMiddleware(logger=logger, include_traceback=True)`. When the tool raises the `FileNotFoundError` built from the raw value, that middleware logs the exception text and traceback through the same logger. ToFu's runs captured these `Error in tools/call: ToolError: ...` entries. `output_path` (or the path generated from `input_path`) is logged the same way once a valid image has been read, for example `draw_lines.py:92`.

## Steps to reproduce
1. Prerequisites: Python 3.10 or newer (`requires-python = ">=3.10"` in `pyproject.toml`). No API keys, accounts, models or images are needed: the call stops at the file-existence check, before any image or model is loaded, so `imagesorcery-mcp --post-install` is not required. Telemetry is off by default (`config.py:72`), so the call does not send anything off the machine.
2. Install from a checkout of the tested commit (README, "Development Setup") and use the stdio entry point `imagesorcery-mcp` (`pyproject.toml:39`):

   ```bash
   git clone https://github.com/sunriseapps/imagesorcery-mcp.git
   cd imagesorcery-mcp
   git checkout 2f77957
   python -m venv venv && source venv/bin/activate
   pip install -e .
   ```

   With the editable install the log file is `src/imagesorcery_mcp/logs/imagesorcery.log` (`logging_config.py:5`). The client below starts the server itself; run it from the same venv (the `mcp` package comes in with `fastmcp`).
3. Call `draw_lines` with an `input_path` that does not exist and contains CR/LF. Arguments:

   ```json
   {"input_path": "/tmp/tofu-poc-missing.png\r\nFAKE-LOG-ENTRY", "lines": []}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="imagesorcery-mcp", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("draw_lines", {"input_path": "/tmp/tofu-poc-missing.png\r\nFAKE-LOG-ENTRY", "lines": []})
               print(result)

   asyncio.run(main())
   ```
4. Open `src/imagesorcery_mcp/logs/imagesorcery.log`, or read the script's stderr (the MCP client forwards the server's stderr). Expected content, derived from the code (not captured):

   ```
   <timestamp> - imagesorcery.draw_lines:50 - INFO - Draw lines tool requested for image: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY with 0 lines
   <timestamp> - imagesorcery.draw_lines:54 - ERROR - Input file not found: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY
   <timestamp> - imagesorcery.<module>:<line> - ERROR - Error in tools/call: ToolError: Error calling tool 'draw_lines': Input file not found: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY. Please provide a full path to the file.
   Traceback (most recent call last):
   ...
   ```

   Each line that starts with `FAKE-LOG-ENTRY` has no timestamp, logger or level prefix. A real attacker would format it to look like a genuine entry.

## Expected behavior
CR and LF in caller-supplied values are escaped (for example written as `\r\n`) or removed before logging, so one tool call only produces well-formed, prefixed log entries.

## Actual behavior
Every `\r\n` in `input_path` starts a new physical line in the log file and on stderr. The tool call fails with `Input file not found`, but by then the value has already been logged at `draw_lines.py:50` and `draw_lines.py:54`, and it is logged again by the error middleware.

ToFu's fuzzing run captured the caller's path written verbatim into the log. The call was `{'input_path': '', 'lines': [], 'output_path': ''}`, and the log record began:

```
Error in tools/call: ToolError: Error calling tool 'draw_lines': Input file not found: . Please provide a full path to the file.
Traceback (most recent call last):
  ...
```

The line breaks in that record come from the traceback, not from the input; the record only shows that the raw value is logged. The reproduction above adds the CR/LF.

## Impact
In MCP the model chooses tool arguments, and prompt injection in content it reads (a web page, a document, or text inside an image) can steer them. Whoever controls `input_path` can add lines to `imagesorcery.log` and to the stderr log that the MCP client keeps, for example an entry that looks like a successful operation or one that breaks up a real error. If the server runs with `--transport=streamable-http` (the README shows a `--host=0.0.0.0` example), any client that can reach the endpoint can do this directly. There is no code execution or data disclosure. The impact is limited to log integrity, which matters mostly where these logs are parsed, forwarded or used for auditing. Low severity.

## Suggested fix
Fix it once in `logging_config.py` instead of in each tool: add a filter to both handlers that escapes CR and LF in the final message.

```python
class _EscapeCRLF(logging.Filter):
    def filter(self, record):
        msg = record.getMessage()
        record.msg = msg.replace("\r", "\\r").replace("\n", "\\n")
        record.args = ()
        return True

handler.addFilter(_EscapeCRLF())
console_handler.addFilter(_EscapeCRLF())
```

Tracebacks passed through `exc_info` are formatted after the message and stay multi-line. If a message embeds a traceback as text, the filter puts it on one line; that is the trade-off.

If you would rather fix it per call, log caller values with `!r` (for example `f"Input file not found: {input_path!r}"`) at `draw_lines.py:50` and `draw_lines.py:54`, and use `!r` in the `FileNotFoundError` message at `draw_lines.py:55` too, because the error middleware logs that text. The same pattern appears in the other tools of this server (`blur`, `change_color`, `config`, `crop`, `detect`, `draw_arrows`, `draw_circles`, `draw_rectangles`, `draw_texts`, `fill`, `find`, `get_metainfo`, `ocr`, `overlay`, `resize`, `rotate`), so the central filter is the smaller change.

## Status on the default branch
Still present at `2f77957` (2026-05-19). The tested commit is the current head of the default branch, so the code quoted above is the latest code.

## Prior reports
- #17 "[Security] Path Traversal via unsanitized input_path/output_path parameters" (issue, closed 2026-05-19): same `*_path` arguments and the same tool code, but a different weakness (CWE-22); it says nothing about logging. The default branch now has an opt-in `IMAGESORCERY_AVAILABLE_PATHS` check (`middlewares/path_access.py`, head `2f77957` of 2026-05-19, the day #17 was closed). That check does not escape anything, is off by default, and when it rejects a path it logs the normalized path unescaped with `logger.warning`. Does not fix this.
- Documentation: README.md, "File Access Restrictions": "By default, ImageSorcery MCP does not restrict file paths." (path scope only). `src/imagesorcery_mcp/README.md` says the ErrorHandlingMiddleware ensures "all errors are logged consistently" with tracebacks, which is the third logging path above. No README, CONFIG.md or package README mentions escaping logged values.
- No other related item among the 10 issues and 6 pull requests (fetched 2026-10-01). #11 (a Claude Desktop error log attached as a file) has no readable body about logging content.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`.
- Campaigns and executions: recover-pc: 500 calls, 0 successful (60 s budget); e2-0922: 1 call, 0 successful (60 s budget).
- Evidence (verbatim, trimmed):
  ```
  input:  {'input_path': '', 'lines': [], 'output_path': ''}
  output: None
  logged: 'Error in tools/call: ToolError: Error calling tool 'draw_lines': Input file not found: . Please provide a full path to the file.\nTraceback (most recent call last):\n  File "/scratch/tofu/eval/targets/sunriseapps__imagesorcery-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool_manager.py", l...
  ```
  ```
  input:  {'input_path': '/etc/passwd\x00', 'lines': [], 'output_path': '/tmp/evil.png'}
  output: None
  logged: 'Error in tools/call: ToolError: Error calling tool 'draw_lines': Input file not found: /etc/passwd\x00. Please provide a full path to the file.\nTraceback (most recent call last):\n  File "/scratch/tofu/eval/targets/sunriseapps__imagesorcery-mcp/.venv/lib/python3.13/site-packages/fastmcp/tools/tool...
  ```
  ```
  input:  {'input_path': '/tmp/valid_image.png', 'lines': 'not_an_array', 'output_path': '/tmp/output.png'}
  output: None
  logged: 'Error in tools/call: McpError: Input validation error: Invalid value 'not_an_array'\nTraceback (most recent call last):\n  File "/scratch/tofu/eval/targets/sunriseapps__imagesorcery-mcp/src/imagesorcery_mcp/middlewares/validation.py", line 19, in on_message\n    return await call_next(context)\n   ...
  ```
- Hand-check hints: Real, low severity, confirmed by reading the code at 2f77957: `input_path` reaches `logger.info` at `draw_lines.py:50` and `logger.error` at `draw_lines.py:54` as a raw f-string value, the handlers in `logging_config.py` do no CR/LF escaping, and the field is a plain `str`. Not shown by ToFu's evidence: the newlines in the flagged log records come from FastMCP's traceback (`include_traceback=True`), and none of the three evidence inputs contains `\r` or `\n`. `check_introspection_log_injection` appears to fire on any newline in a log record, so treat the alert itself as a detector false positive and this draft as a code-review finding. One evidence call did put a raw NUL byte from `input_path` (`'/etc/passwd\x00'`) into the log record, which is the same missing neutralization but not CR/LF. The reproduction is derived from the code and was not executed (read-only rule). The same root cause covers all 17 tools ToFu flagged in this repo; consider filing one consolidated issue instead of 17.
</details>
