# Log injection in `live_streaming_create_stream`: CR/LF in `stream` is written unescaped to the server log

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `live_streaming_create_stream` · **Tested commit:** `52dd335`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`live_streaming_create_stream` creates a stream in a live-streaming bucket through the Qiniu live API. The caller's `stream` and `bucket` are interpolated into f-string log messages without escaping CR/LF. When the API returns a non-2xx status, the error line is written to stderr at the default log level, so a `stream` containing a newline produces a forged extra log line. Severity is low.

## Details
`src/mcp_server/core/live_streaming/live_streaming.py:137-182` (tested commit), trimmed:

```python
async def create_stream(self, bucket: str, stream: str) -> Dict[str, Any]:
    url = self._build_stream_url(bucket, stream)
    ...
    logger.info(f"Creating stream: {stream} in bucket: {bucket} at {url}")
    async with aiohttp.ClientSession() as session:
        async with session.put(url, headers=headers, data=bodyJson) as response:
            ...
            else:
                logger.error(f"Failed to create stream: {stream}, status: {status}, response: {text}")
```

The package sets `logging.basicConfig(level=logging.ERROR)` in `src/mcp_server/__init__.py:7`, which logs to stderr. With that default only the `logger.error` line (`:174`) is emitted; the `logger.info` lines (`:156`, `:164`) carry the same raw values but are suppressed unless the level is lowered. The tool schema (`src/mcp_server/core/live_streaming/tools.py:39-61`) only requires `bucket` and `stream` to be strings.

## Steps to reproduce
1. Prerequisites: Python 3.12, `uv`, and network access to the Qiniu live endpoint (`mls.cn-east-1.qiniumiku.com` by default, override with `QINIU_LIVE_ENDPOINT`). Use the name of a live bucket that exists in your account, so that `https://<bucket>.<endpoint>` resolves. Any credentials work: the line is logged on the error branch, which runs whenever the API rejects the request.
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
3. Call the tool with:

   ```json
   {"bucket": "<your-live-bucket>", "stream": "tofu-poc\r\nFAKE-LOG-ENTRY"}
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
                   "live_streaming_create_stream",
                   {"bucket": "<your-live-bucket>", "stream": "tofu-poc\r\nFAKE-LOG-ENTRY"},
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
ERROR:qiniu-mcp:Failed to create stream: tofu-poc
FAKE-LOG-ENTRY, status: <status>, response: <body>
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. An attacker who controls `stream` can add fake lines to the server's stderr log. If that stream is collected into a log file or monitoring system, forged entries can mislead whoever reads it. Severity is low.

## Suggested fix
- Log user-supplied values with `%r` (or escape `\r` and `\n`) instead of f-strings, for example `logger.error("Failed to create stream: %r, status: %s", stream, status)`.
- Validate `stream` and `bucket` against the allowed name characters before building the URL. For `bucket` this also matters for the request itself, because it becomes part of the hostname (`_build_stream_url`, `live_streaming.py:63-76`).

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 10 issues and 52 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); triggered `check_introspection_log_injection`, `check_resource_exhaustion`.
- Campaigns and executions: e2-0922, 1 exec / 0 ok (60 s budget).
- Evidence: none. `log_available: false`, so the reproduction and the expected log text are derived from the code, not from a run.
- Hand-check hints: real per code, low severity, not runtime-verified. `stream` goes raw into `logger.error` at `live_streaming.py:174`, emitted at the default ERROR level. One assumption: `stream` is also part of the request URL path; I expect URL parsing to strip or percent-encode the CR/LF so the request still goes out (Python's `urlsplit` strips `\r\n\t`), but I did not check which yarl/aiohttp version does what. If aiohttp raises instead, only the suppressed INFO line at `:156` is reached and the default-config impact disappears. The fuzzer's single call failed (0 ok), so the `logger.error` branch did not run in that call; the tracer records every logger, and the captured record could not be identified.
- Separate, more serious finding worth its own issue (not what ToFu flagged here): `bucket` is placed into the hostname (`https://{bucket}.{endpoint}/{stream}`) with no validation, so a `bucket` such as `attacker.example#` sends the PUT, with the `Authorization` header (`Bearer <QINIU_LIVE_API_KEY>` if set), to an attacker-chosen host. Same in `create_bucket`, `bind_push_domain`, `bind_play_domain`. Also `create_bucket` (`live_streaming.py:97-105`, not in this group) `print()`s the request headers, including `Authorization`, to stdout, which is the JSON-RPC channel in stdio mode. Read from code only.
</details>
