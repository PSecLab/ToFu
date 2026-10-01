# Log injection in `config`: CR/LF in `key` or `value` is written unescaped to the server log

**Repository:** `sunriseapps/imagesorcery-mcp` · **Tool:** `config` · **Tested commit:** `2f77957`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`config` reads or updates the server configuration by dotted `key`. Its first statement logs `action`, `key` and `value` with an f-string (`config.py:84`). The `imagesorcery` logger writes messages as they are, so `\r\n` inside `key` or a string `value` starts a new, unprefixed line in `imagesorcery.log` and on stderr. A caller can forge or split log entries.

## Details
`src/imagesorcery_mcp/tools/config.py:84` logs the raw arguments before anything is checked. An unknown key then raises `KeyError`, which is logged at `config.py:182`:

```python
# src/imagesorcery_mcp/tools/config.py:84, 117-119, 181-182
logger.info(f"Config tool called with action='{action}', key='{key}', value='{value}', persist={persist}")
...
            else:
                if key not in config_dict:
                    raise KeyError(f"Configuration key '{key}' not found")
...
except KeyError as e:
    logger.error(f"Configuration key error: {e}")
```

`action` is constrained by `pattern="^(get|set|reset)$"` (`config.py:57`), but `key` is `Optional[str]` and `value` is `Optional[Union[str, int, float, bool]]`, so both accept `\r\n`. `config.py:182` happens to be safe, because `str()` of a `KeyError` is the repr of its message, which escapes the CR/LF. Line 84 is not.

The `imagesorcery` logger is configured in `src/imagesorcery_mcp/logging_config.py:15-31`: a `RotatingFileHandler` on `logs/imagesorcery.log` next to the package and a `StreamHandler` on stderr, both with the format `'%(asctime)s - %(name)s.%(module)s:%(lineno)d - %(levelname)s - %(message)s'`. No filter or formatter escapes CR or LF in `%(message)s`, and nothing in the tool strips them.

## Steps to reproduce
1. Prerequisites: Python 3.10 or newer (`requires-python = ">=3.10"` in `pyproject.toml`). No API keys, accounts, models or images are needed. A `get` with an unknown key does not change the configuration. Telemetry is off by default (`config.py:72`), so the call does not send anything off the machine.
2. Install from a checkout of the tested commit (README, "Development Setup") and use the stdio entry point `imagesorcery-mcp` (`pyproject.toml:39`):

   ```bash
   git clone https://github.com/sunriseapps/imagesorcery-mcp.git
   cd imagesorcery-mcp
   git checkout 2f77957
   python -m venv venv && source venv/bin/activate
   pip install -e .
   ```

   With the editable install the log file is `src/imagesorcery_mcp/logs/imagesorcery.log` (`logging_config.py:5`). The client below starts the server itself; run it from the same venv (the `mcp` package comes in with `fastmcp`).
3. Call `config` with a `key` that contains CR/LF. Arguments:

   ```json
   {"action": "get", "key": "tofu\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("config", {"action": "get", "key": "tofu\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Open `src/imagesorcery_mcp/logs/imagesorcery.log`, or read the script's stderr (the MCP client forwards the server's stderr). Expected content, derived from the code (not captured):

   ```
   <timestamp> - imagesorcery.config:84 - INFO - Config tool called with action='get', key='tofu
   FAKE-LOG-ENTRY', value='None', persist=False
   <timestamp> - imagesorcery.config:182 - ERROR - Configuration key error: "Configuration key 'tofu\r\nFAKE-LOG-ENTRY' not found"
   ```

   The line that starts with `FAKE-LOG-ENTRY` has no timestamp, logger or level prefix. A real attacker would format it to look like a genuine entry. The second entry stays on one line only because of the `KeyError` repr.

## Expected behavior
CR and LF in caller-supplied values are escaped (for example written as `\r\n`) or removed before logging, so one tool call only produces well-formed, prefixed log entries.

## Actual behavior
The `\r\n` in `key` starts a new physical line in the log file and on stderr. The tool returns its normal `{"action": "get", "error": ..., "available_keys": [...]}` result, so nothing tells the caller or the operator that the log was altered.

None of the output ToFu captured demonstrates this directly. The flagged records were multi-line pydantic validation errors, for example after `{'action': 'set', 'key': 'blur.strength', 'value': -1, 'persist': True}`, where the line breaks come from pydantic's error formatting and the caller value appears only as a repr (`input_value=-1`).

## Impact
In MCP the model chooses tool arguments, and prompt injection in content it reads (a web page, a document, or text inside an image) can steer them. Whoever controls `key` or `value` can add lines to `imagesorcery.log` and to the stderr log that the MCP client keeps, for example an entry that looks like a successful operation or one that breaks up a real error. If the server runs with `--transport=streamable-http` (the README shows a `--host=0.0.0.0` example), any client that can reach the endpoint can do this directly. There is no code execution or data disclosure. The impact is limited to log integrity, which matters mostly where these logs are parsed, forwarded or used for auditing. Low severity.

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

If you would rather fix it per call, log the caller values with `!r` at `config.py:84` (`f"Config tool called with action={action!r}, key={key!r}, value={value!r}, persist={persist}"`), and do the same at `config.py:128` and `config.py:162`, which log `key` on the success paths. The same pattern appears in the other tools of this server (`blur`, `change_color`, `crop`, `detect`, `draw_arrows`, `draw_circles`, `draw_lines`, `draw_rectangles`, `draw_texts`, `fill`, `find`, `get_metainfo`, `ocr`, `overlay`, `resize`, `rotate`), so the central filter is the smaller change.

## Status on the default branch
Still present at `2f77957` (2026-05-19). The tested commit is the current head of the default branch, so the code quoted above is the latest code.

## Prior reports
None found. Searched all 10 issues and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The only security report, #17 (path traversal, closed 2026-05-19), covers `*_path` arguments, not `config`, and does not mention logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. Other sanitizers that fired for this tool, not covered by this draft: `check_introspection_insecure_file_permissions`, `check_introspection_sensitive_data_logging`.
- Campaigns and executions: recover-pc: 4096 calls, 424 successful (60 s budget); e2-0922: 1 call, 0 successful (60 s budget).
- Evidence (verbatim, trimmed):
  ```
  input:  {'action': '', 'key': '', 'value': '', 'persist': False}
  output: None
  logged: 'Error in tools/call: McpError: Input validation error in tool 'config': check that all parameters are correctly named and have the right types\nTraceback (most recent call last):\n  File "/scratch/tofu/eval/targets/sunriseapps__imagesorcery-mcp/src/imagesorcery_mcp/middlewares/validation.py", line ...
  ```
  ```
  input:  {'action': 'set', 'key': 'blur.strength', 'value': -1, 'persist': True}
  output: '{"action":"set","error":"Invalid configuration update: 1 validation error for ImageSorceryConfig\\nblur.strength\\n  Input should be greater than or equal to 1 [type=greater_than_equal, input_value=-1, input_type=int]\\n    For further information visit https://errors.pydantic.dev/2.13/v/greater_th...
  logged: 'Configuration value error: Invalid configuration update: 1 validation error for ImageSorceryConfig\nblur.strength\n  Input should be greater than or equal to 1 [type=greater_than_equal, input_value=-1, input_type=int]\n    For further information visit https://errors.pydantic.dev/2.13/v/greater_tha...
  ```
  ```
  input:  {'action': 'set', 'key': 'detection.confidence_threshold', 'value': 'not_a_number', 'persist': False}
  output: '{"action":"set","error":"Invalid configuration update: 1 validation error for ImageSorceryConfig\\ndetection.confidence_threshold\\n  Input should be a valid number, unable to parse string as a number [type=float_parsing, input_value=\'not_a_number\', input_type=str]\\n    For further information v...
  logged: 'Configuration value error: Invalid configuration update: 1 validation error for ImageSorceryConfig\ndetection.confidence_threshold\n  Input should be a valid number, unable to parse string as a number [type=float_parsing, input_value='not_a_number', input_type=str]\n    For further information visi...
  ```
- Hand-check hints: Real, low severity, confirmed by reading the code at 2f77957: `key` and a string `value` reach `logger.info` at `config.py:84` as raw f-string values, and the handlers in `logging_config.py` do no CR/LF escaping. Not shown by ToFu's evidence: the flagged records contain newlines from pydantic's multi-line `ValidationError` logged at `config.py:190` and from the FastMCP traceback (`include_traceback=True`), and the caller values appear there only as repr. None of the three evidence inputs contains `\r` or `\n`, so treat the alert itself as a detector false positive and this draft as a code-review finding. `config.py:182` is safe by accident (KeyError repr). `config.py:128` and `config.py:162` log `key` raw on success paths, but a CRLF key probably cannot reach them (line 128 needs the key to exist in the config dict; line 162 needs `update_config` to accept it), and I did not trace `update_config`. The reproduction is derived from the code and was not executed (read-only rule). The same root cause covers all 17 tools ToFu flagged in this repo; consider filing one consolidated issue instead of 17.
</details>
