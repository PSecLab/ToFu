# Log injection in `get_metainfo`: CR/LF in `input_path` is written unescaped to the server log

**Repository:** `sunriseapps/imagesorcery-mcp` · **Tool:** `get_metainfo` · **Tested commit:** `2f77957`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_metainfo` returns file and image metadata for `input_path`. It logs `input_path` with an f-string before validating it (`metainfo.py:25`), and again when the file does not exist (`metainfo.py:34`). The `imagesorcery` logger writes messages as they are, so `\r\n` inside the argument starts a new, unprefixed line in `imagesorcery.log` and on stderr. A caller can forge or split log entries.

## Details
`metainfo.py:25` logs the caller's `input_path` before any check, and `metainfo.py:34` logs it again when the path does not exist:

```python
# src/imagesorcery_mcp/tools/metainfo.py:25-35
logger.info(f"Get metainfo tool requested for image: {input_path}")

# Check if input_path is empty
if not input_path or not input_path.strip():
    logger.error("Input path is empty. Please provide a full path to the image file.")
    raise ValueError("input_path cannot be empty. Please provide a full path to the image file.")

# Check if input file exists
if not os.path.exists(input_path):
    logger.error(f"Input file not found: {input_path}")
    raise FileNotFoundError(f"Input file not found: {input_path}. Please provide a full path to the file.")
```

The `imagesorcery` logger is configured in `src/imagesorcery_mcp/logging_config.py:15-31`: a `RotatingFileHandler` on `logs/imagesorcery.log` next to the package and a `StreamHandler` on stderr, both with the format `'%(asctime)s - %(name)s.%(module)s:%(lineno)d - %(levelname)s - %(message)s'`. No filter or formatter escapes CR or LF in `%(message)s`, and the argument is a plain `str` field, so pydantic accepts `\r\n` in it.

The value reaches the log a third time. `server.py:64-68` installs FastMCP's `ErrorHandlingMiddleware(logger=logger, include_traceback=True)`. When the tool raises the `FileNotFoundError` built from the raw value, that middleware logs the exception text and traceback through the same logger. ToFu's runs captured these `Error in tools/call: ToolError: ...` entries.

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
3. Call `get_metainfo` with an `input_path` that does not exist and contains CR/LF. Arguments:

   ```json
   {"input_path": "/tmp/tofu-poc-missing.png\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("get_metainfo", {"input_path": "/tmp/tofu-poc-missing.png\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Open `src/imagesorcery_mcp/logs/imagesorcery.log`, or read the script's stderr (the MCP client forwards the server's stderr). Expected content, derived from the code (not captured):

   ```
   <timestamp> - imagesorcery.metainfo:25 - INFO - Get metainfo tool requested for image: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY
   <timestamp> - imagesorcery.metainfo:34 - ERROR - Input file not found: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY
   <timestamp> - imagesorcery.<module>:<line> - ERROR - Error in tools/call: ToolError: Error calling tool 'get_metainfo': Input file not found: /tmp/tofu-poc-missing.png
   FAKE-LOG-ENTRY. Please provide a full path to the file.
   Traceback (most recent call last):
   ...
   ```

   Each line that starts with `FAKE-LOG-ENTRY` has no timestamp, logger or level prefix. A real attacker would format it to look like a genuine entry.

## Expected behavior
CR and LF in caller-supplied values are escaped (for example written as `\r\n`) or removed before logging, so one tool call only produces well-formed, prefixed log entries.

## Actual behavior
Every `\r\n` in `input_path` starts a new physical line in the log file and on stderr. The tool call fails with `Input file not found`, but by then the value has already been logged at `metainfo.py:25` and `metainfo.py:34`, and it is logged again by the error middleware.

No log from the fuzzing run survived for this tool, so there is no captured output to quote. The behaviour above is derived from the code.

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

If you would rather fix it per call, log caller values with `!r` (for example `f"Input file not found: {input_path!r}"`) at `metainfo.py:25` and `metainfo.py:34`, and use `!r` in the `FileNotFoundError` message at `metainfo.py:35` too, because the error middleware logs that text. The same pattern appears in the other tools of this server (`blur`, `change_color`, `config`, `crop`, `detect`, `draw_arrows`, `draw_circles`, `draw_lines`, `draw_rectangles`, `draw_texts`, `fill`, `find`, `ocr`, `overlay`, `resize`, `rotate`), so the central filter is the smaller change.

## Status on the default branch
Still present at `2f77957` (2026-05-19). The tested commit is the current head of the default branch, so the code quoted above is the latest code.

## Prior reports
- #17 "[Security] Path Traversal via unsanitized input_path/output_path parameters" (issue, closed 2026-05-19): same `*_path` arguments and the same tool code, but a different weakness (CWE-22); it says nothing about logging. The default branch now has an opt-in `IMAGESORCERY_AVAILABLE_PATHS` check (`middlewares/path_access.py`, head `2f77957` of 2026-05-19, the day #17 was closed). That check does not escape anything, is off by default, and when it rejects a path it logs the normalized path unescaped with `logger.warning`. Does not fix this.
- Documentation: README.md, "File Access Restrictions": "By default, ImageSorcery MCP does not restrict file paths." (path scope only). `src/imagesorcery_mcp/README.md` says the ErrorHandlingMiddleware ensures "all errors are logged consistently" with tracebacks, which is the third logging path above. No README, CONFIG.md or package README mentions escaping logged values.
- No other related item among the 10 issues and 6 pull requests (fetched 2026-10-01). #11 (a Claude Desktop error log attached as a file) has no readable body about logging content.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. Other sanitizers that fired for this tool, not covered by this draft: `check_file_access`, `check_resource_exhaustion`.
- Campaigns and executions: e2-0922: 1 call, 0 successful (60 s budget).
- Evidence (verbatim, trimmed): none. No run log survived for this tool (`log_available: false`).
- Hand-check hints: Real, low severity, confirmed by reading the code at 2f77957: `input_path` reaches `logger.info` at `metainfo.py:25` and `logger.error` at `metainfo.py:34` as a raw f-string value, the handlers in `logging_config.py` do no CR/LF escaping, and the field is a plain `str`. No run log survived (`log_available: false`). e2-0922 made 1 call with 0 successes and its input is unknown, so I cannot say what fired. It is most likely the same traceback-newline trigger seen for the other tools in this repo, not a caller-supplied CRLF. The reproduction is derived from the code and was not executed (read-only rule). The same root cause covers all 17 tools ToFu flagged in this repo; consider filing one consolidated issue instead of 17.
</details>
