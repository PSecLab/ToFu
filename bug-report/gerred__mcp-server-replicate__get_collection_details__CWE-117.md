# Log output not neutralized in `get_collection_details`: multi-line exception text is logged as-is

**Repository:** `gerred/mcp-server-replicate` · **Tool:** `get_collection_details` · **Tested commit:** `568024c`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_collection_details` requests `GET /collections/{collection_slug}` from the Replicate API. When the call fails, the client logs `str(err)` without escaping line breaks, so one error becomes two physical log lines. The caller's slug appears in that log line (inside the URL), but the line break itself comes from httpx's error message. httpx rejects CR/LF in the URL, so a caller cannot use the slug to start a new log line. This is a low-severity log-hygiene report.

## Details
`src/mcp_server_replicate/replicate_client.py:599-628` at `568024c`:

```python
        try:
            response = await self.http_client.get(f"/collections/{collection_slug}")
            response.raise_for_status()
            ...
        except httpx.HTTPStatusError as err:
            if err.response.status_code == 404:
                raise ValueError(f"Collection not found: {collection_slug}")
            logger.error(f"HTTP error getting collection: {str(err)}")
            raise Exception(f"Failed to get collection: {str(err)}") from err
        except Exception as err:
            logger.error(f"Failed to get collection: {str(err)}")
            raise Exception(f"Failed to get collection: {str(err)}") from err
```

For a non-2xx, non-404 response, `raise_for_status()` raises `httpx.HTTPStatusError`. In httpx 0.28.1 (pinned in `uv.lock`) that message contains the request URL and a literal `\n` before `For more information check: ...`. The f-string passes it through unchanged. The root logger is set up in `server.py:295` and writes to stderr. The tool wrapper is `server.py:667-672`.

What the caller controls: the slug is inserted into the URL path, so printable characters show up in the log, percent-encoded (`1'%20OR%20'1'='1` in the fuzz log). Control characters do not get that far. httpx 0.28.1 raises `InvalidURL` for any non-printable ASCII character in a URL, and its message shows the character as its `repr()` (for example `'\r'`). That lands in the `except Exception` branch and is logged on one line.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. The server refuses to start without `REPLICATE_API_TOKEN` (`server.py:299-303`). Use an invalid value such as `r8_invalid_token_for_testing` so the API answers 401.
2. Check out the tested commit and start the server: `git clone https://github.com/gerred/mcp-server-replicate && cd mcp-server-replicate && git checkout 568024c && REPLICATE_API_TOKEN=r8_invalid_token_for_testing uv run mcp-server-replicate`. The script below starts it for you.
3. Call the tool with `{"collection_slug": "tofu-poc"}`:

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
               result = await session.call_tool("get_collection_details", {"collection_slug": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (`stdio_client` forwards it to your terminal). One `logger.error` call produces two lines; the second starts with `For more information check:`. Optionally repeat with `{"collection_slug": "tofu\r\nFAKE-LOG-ENTRY"}`: that call should log a single `Failed to get collection: Invalid non-printable ASCII character in URL, '\r' ...` line, which shows the caller cannot inject a line of its own.

## Expected behavior
Each log record stays on one line. Line breaks inside interpolated exception text are escaped (for example as `\n`).

## Actual behavior
The record is split across two lines. Logged content captured by ToFu's tracer (the `\n` was a real line break):

```
HTTP error getting collection: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/collections/1'%20OR%20'1'='1'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

## Impact
Low. The caller (the LLM, possibly steered by prompt injection) can put printable, percent-encoded text into the first line, but cannot add a line break, so it cannot forge a separate log entry. The practical effect is that line-based log parsers see a broken record. It is mainly a hardening gap: because the code logs `str(err)` verbatim everywhere, any future exception that carries raw caller text would be logged unescaped.

## Suggested fix
Escape CR/LF before logging, either per call or once in a formatter:

```python
def _one_line(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")

logger.error("HTTP error getting collection: %s", _one_line(str(err)))
```

A `logging.Formatter` subclass that escapes `\r` and `\n` in `record.getMessage()` would cover every call in `replicate_client.py` at once. Validating `collection_slug` against the slug format (for example `^[a-z0-9-]+$`) before building the URL would also be reasonable.

## Status on the default branch
Still present at `568024c` (2025-02-28). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 1 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. PR #1 "fix: create id field on models in collections" (closed 2025-01-06) touched `get_collection_details`, but it only fixed a pydantic validation error on collection models and does not change logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Fired: `check_introspection_log_injection` (also listed for the tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`).
- Campaigns and executions: `e2-0922`: 500 execs, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'collection_slug': "1' OR '1'='1"}`, output `None`. Analysis: "Logged content: 'HTTP error getting collection: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/collections/1'%20OR%20'1'='1'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401'." Same pattern for `{'collection_slug': ''}` and `{'collection_slug': '[object Object]'}`.
- Hand-check hints: **weak, likely a false positive for CWE-117.** The `\n` is from httpx's `HTTPStatusError` template (`httpx/_models.py:812-817` in 0.28.1). I read httpx 0.28.1 `_urlparse.py:221-229` from the local uv cache: any non-printable ASCII char in the URL raises `InvalidURL` with `{char!r}`, so CR/LF in the slug cannot reach the log raw. I did not run the optional `\r\n` call. ToFu's `check_introspection_log_injection` (`src/sanitizers/introspection.py:807`) flags any record containing `\n`/`\r` with no provenance check. Recommend not filing, or folding all nine replicate CWE-117 items into one low-priority hardening issue.
</details>
