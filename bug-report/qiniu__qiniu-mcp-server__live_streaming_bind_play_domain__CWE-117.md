# Log injection in `live_streaming_bind_play_domain`: CR/LF in `domain` is written unescaped to the server log

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `live_streaming_bind_play_domain` · **Tested commit:** `52dd335`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`live_streaming_bind_play_domain` binds a playback domain to a live-streaming bucket through the Qiniu live API. The caller's `domain` (and `bucket`) are interpolated into f-string log messages without escaping CR/LF. When the API returns a non-2xx status, the error line is written to stderr at the default log level, so a `domain` containing a newline produces a forged extra log line. Severity is low.

## Details
`src/mcp_server/core/live_streaming/live_streaming.py:235-283` (tested commit), trimmed:

```python
async def bind_play_domain(self, bucket: str, domain: str, domain_type: str = "live") -> Dict[str, Any]:
    url = f"{self._build_bucket_url(bucket)}/?domain"
    data = {"domain": domain, "type": domain_type}
    ...
    logger.info(f"Binding playback domain: {domain} (type: {domain_type}) to bucket: {bucket}")
    async with aiohttp.ClientSession() as session:
        async with session.post(url, headers=headers, json=data) as response:
            ...
            else:
                logger.error(f"Failed to bind playback domain: {domain}, status: {status}, response: {text}")
```

The package sets `logging.basicConfig(level=logging.ERROR)` in `src/mcp_server/__init__.py:7`, which logs to stderr. With that default only the `logger.error` line (`:275`) is emitted; the `logger.info` lines (`:257`, `:265`) carry the same raw values but are suppressed unless the level is lowered. The tool schema (`src/mcp_server/core/live_streaming/tools.py:92-119`) only requires `domain` to be a string. `domain` reaches the API inside a JSON body, so the request itself is not affected; only the log line is.

## Steps to reproduce
1. Prerequisites: Python 3.12, `uv`, and network access to the Qiniu live endpoint (`mls.cn-east-1.qiniumiku.com` by default, override with `QINIU_LIVE_ENDPOINT`). Use the name of a live bucket that exists in your account, so that `https://<bucket>.<endpoint>` resolves. Any credentials work: the line is logged on the error branch, which runs whenever the API rejects the request (for example invalid credentials or an invalid domain).
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
   Configure `QINIU_ACCESS_KEY`/`QINIU_SECRET_KEY` or `QINIU_LIVE_API_KEY` in `.env` if you want to use real credentials.
3. Call the tool with:

   ```json
   {"bucket": "<your-live-bucket>", "domain": "play.example.com\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/path/to/qiniu-mcp-server", "run", "qiniu-mcp-server"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "live_streaming_bind_play_domain",
                   {"bucket": "<your-live-bucket>", "domain": "play.example.com\r\nFAKE-LOG-ENTRY"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (the client script inherits it). The error line is split in two, and the second line starts with `FAKE-LOG-ENTRY`.

## Expected behavior
CR, LF and other control characters from tool arguments are escaped (or the value is rejected) before it is written to a log, so one call produces one log line.

## Actual behavior
No run log survived for this item; the following is derived from the code. On a non-2xx response the server writes:

```
ERROR:qiniu-mcp:Failed to bind playback domain: play.example.com
FAKE-LOG-ENTRY, status: <status>, response: <body>
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. An attacker who controls `domain` can add fake lines to the server's stderr log. If that stream is collected into a log file or monitoring system, forged entries can mislead whoever reads it. There is no effect on the API call itself. Severity is low.

## Suggested fix
- Log user-supplied values with `%r` (or escape `\r` and `\n`) instead of f-strings, for example `logger.error("Failed to bind playback domain: %r, status: %s", domain, status)`.
- Validate `domain` as a hostname (letters, digits, `-`, `.`) before sending it to the API.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 10 issues and 52 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); triggered `check_introspection_incomplete_cleanup`, `check_introspection_log_injection`, `check_introspection_temp_file_leak`, `check_resource_exhaustion`.
- Campaigns and executions: e2-0922, 1 exec / 0 ok (60 s budget).
- Evidence: none. `log_available: false`, so the reproduction and the expected log text are derived from the code, not from a run.
- Hand-check hints: real per code, low severity, not runtime-verified. `domain` goes raw into `logger.error` at `live_streaming.py:275`, which is emitted at the default ERROR level. Caveat on the fuzzer alert itself: the single call failed (0 ok), so the response branch with `logger.error` did not run in that call; the tracer patches `Logger._log` for every logger, so the captured record was either the INFO line at `:257` (only if the harness had INFO enabled) or a record from another library. Could not tell which. Also note `set_logging_level` in `application.py:23-29` passes `level.lower()` to `logger.setLevel`, which Python rejects for lowercase names, so clients cannot lower the level through MCP. Untested assumption in step 1: `<bucket>.mls.cn-east-1.qiniumiku.com` must resolve.
- Separate, more serious finding worth its own issue (not what ToFu flagged here): `bucket` is placed into the hostname by `_build_bucket_url` (`live_streaming.py:48-61`, `https://{bucket}.{endpoint}`) with no validation. A `bucket` such as `attacker.example#` makes the request go to `attacker.example` with the `Authorization` header from `_get_auth_header` (`Bearer <QINIU_LIVE_API_KEY>` if set, otherwise `Qiniu <access_key>:<request signature>`). Same pattern in `create_bucket`, `create_stream` and `bind_push_domain`. Read from code only, not executed.
</details>
