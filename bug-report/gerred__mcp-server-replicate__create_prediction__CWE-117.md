# Log output not neutralized in `create_prediction`: multi-line exception text is logged as-is on every retry

**Repository:** `gerred/mcp-server-replicate` · **Tool:** `create_prediction` · **Tested commit:** `568024c`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create_prediction` posts the caller's model input to `POST /predictions` through `ReplicateClient._make_request()`, which retries on any `httpx.HTTPError`. Each retry logs `str(e)` without escaping line breaks, and the final failure logs it again, so one failed call writes several split records. The line break comes from httpx's own error message, and the caller's `input` goes into the JSON body, not into the log. This is a low-severity log-hygiene report, not an exploitable log-forging bug.

## Details
`src/mcp_server_replicate/replicate_client.py:141-170` at `568024c`:

```python
        for attempt in range(MAX_RETRIES):
            try:
                response = await self.http_client.request(method, endpoint, **kwargs)
                await self._handle_response(response)
                response.raise_for_status()
                ...
            except httpx.HTTPError as e:
                self._retry_count += 1
                if attempt == MAX_RETRIES - 1:
                    raise
                ...
                logger.warning(
                    f"Request failed: {str(e)}. "
                    f"Retrying in {delay:.2f} seconds "
                    f"(attempt {attempt + 1}/{MAX_RETRIES})"
                )
```

The tool (`server.py:702-757`) calls `client.create_prediction()` (`replicate_client.py:740-801`), which calls `_make_request("POST", "/predictions", json=body)` and on final failure logs `logger.error(f"Failed to create prediction: {str(err)}")` at line 800. For a non-2xx response, `raise_for_status()` raises `httpx.HTTPStatusError`. In httpx 0.28.1 (pinned in `uv.lock`) that message contains the URL and a literal `\n` before `For more information check: ...`. Both f-strings pass it through unchanged. The root logger is set up in `server.py:295` and writes to stderr.

Related: `_make_request` retries every `httpx.HTTPError`, including 4xx responses such as 401 or 422 that will not succeed on retry. That adds roughly 3 to 5 seconds of backoff to every failed call.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. The server refuses to start without `REPLICATE_API_TOKEN` (`server.py:299-303`). Use an invalid value such as `r8_invalid_token_for_testing` so the API answers 401. No prediction is created and no credits are used.
2. Check out the tested commit and start the server: `git clone https://github.com/gerred/mcp-server-replicate && cd mcp-server-replicate && git checkout 568024c && REPLICATE_API_TOKEN=r8_invalid_token_for_testing uv run mcp-server-replicate`. The script below starts it for you.
3. Call the tool with `{"input": {"version": "tofu-poc", "prompt": "tofu poc"}, "confirmed": true}` (`confirmed` must be `true`, otherwise the tool only returns a confirmation prompt):

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--directory", "/path/to/mcp-server-replicate", "mcp-server-replicate"],
           env={**os.environ, "REPLICATE_API_TOKEN": "r8_invalid_token_for_testing"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "create_prediction",
                   {"input": {"version": "tofu-poc", "prompt": "tofu poc"}, "confirmed": True},
               )
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (`stdio_client` forwards it to your terminal). Expect two `Request failed: ...` warnings (attempts 1/3 and 2/3) and one `Failed to create prediction: ...` error. Each is split, with a line starting `For more information check:`.

## Expected behavior
Each log record stays on one line. Line breaks inside interpolated exception text are escaped (for example as `\n`).

## Actual behavior
The record is split across two lines. Logged content captured by ToFu's tracer (the `\n` was a real line break):

```
Request failed: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/predictions'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401. Retrying in 1.57 seconds (attempt 1/3)
```

## Impact
Low. The caller (the LLM, possibly steered by prompt injection) controls `input`, but `input` is sent in the JSON body and is not part of the logged text. The line break comes from a fixed httpx template, so the caller cannot choose what appears on the extra line. The practical effect is that line-based log parsers see broken records. It is mainly a hardening gap: because the code logs `str(err)` verbatim everywhere, any future exception that carries caller text would be logged raw.

## Suggested fix
Escape CR/LF before logging, either per call or once in a formatter:

```python
def _one_line(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")

logger.warning("Request failed: %s. Retrying in %.2f seconds (attempt %d/%d)",
               _one_line(str(e)), delay, attempt + 1, MAX_RETRIES)
```

A `logging.Formatter` subclass that escapes `\r` and `\n` in `record.getMessage()` would cover every call in `replicate_client.py` at once. Separately, consider retrying only on network errors, 429 and 5xx, and failing fast on other 4xx responses.

## Status on the default branch
Still present at `568024c` (2025-02-28). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 1 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Fired per evidence: `check_introspection_log_injection`, `check_resource_exhaustion` (also listed for the tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`).
- Campaigns and executions: `corpus-sbx`: 1 exec, 1 success, 60 s budget; `e2-0922`: 1 exec, 1 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'input': {'version': 0, 'parameters': []}, 'confirmed': True}`, output `None`. Analysis: "Resource exhaustion/Timeout detected: Execution took 4.38 seconds (Limit: 2.0s). Introspection Log Injection Alert (CWE-117): ... (logger:mcp_server_replicate.replicate_client)! Logged content: 'Request failed: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/predictions'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401. Retrying in 1.57 seconds (attempt 1/3)'." Two more inputs (`version: []`, `version: 'v1.2.3'`) give the same logged content.
- Hand-check hints: **weak, likely a false positive for CWE-117.** The `\n` is from httpx's `HTTPStatusError` template (`httpx/_models.py:812-817` in 0.28.1, read from the local uv cache), not from input. ToFu's `check_introspection_log_injection` (`src/sanitizers/introspection.py:807`) flags any record containing `\n`/`\r` with no provenance check. The 401 is only because the fuzz run used a dummy token. The resource-exhaustion alert (4+ s) is explained by the retry backoff on 401 (attempt 0 delay 1-2 s, attempt 1 delay 2-3 s), which I mention in the draft as a side note. Recommend not filing, or folding all nine replicate CWE-117 items into one low-priority hardening issue (the 4xx-retry point could go in that issue).
</details>
