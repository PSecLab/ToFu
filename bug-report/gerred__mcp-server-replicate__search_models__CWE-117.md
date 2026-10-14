# Log output not neutralized in `search_models`: multi-line exception text is logged as-is

**Repository:** `gerred/mcp-server-replicate` · **Tool:** `search_models` · **Tested commit:** `568024c`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`search_models` sends the caller's `query` to the Replicate API as the body of a `QUERY /models` request. When the call fails, the client logs `str(err)` without escaping line breaks, so one error becomes two physical log lines. The line break comes from httpx's own error message. The `query` text is sent in the request body and is not part of the logged message. This is a low-severity log-hygiene report, not an exploitable log-forging bug.

## Details
`src/mcp_server_replicate/replicate_client.py:463-517` at `568024c`:

```python
            url = "/models"
            if cursor:
                url = f"{url}?cursor={cursor}"
            response = await self.http_client.request(
                "QUERY",
                url,
                content=query,
                headers={"Content-Type": "text/plain"}
            )
            response.raise_for_status()
            ...
        except httpx.HTTPError as err:
            logger.error(f"HTTP error during model search: {str(err)}")
            raise Exception(f"Failed to search models: {str(err)}") from err
```

For a non-2xx response, `raise_for_status()` raises `httpx.HTTPStatusError`. In httpx 0.28.1 (pinned in `uv.lock`) that message contains the URL and a literal `\n` before `For more information check: ...`. The f-string passes it through unchanged. The root logger is set up in `server.py:295` and writes to stderr. The tool wrapper is `server.py:645-657`; it does not pass a cursor, so the URL is always `/models`.

Every client method in `replicate_client.py` uses the same `logger.error(f"...{str(err)}")` pattern (lines 245 to 800).

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. The server refuses to start without `REPLICATE_API_TOKEN` (`server.py:299-303`). Use an invalid value such as `r8_invalid_token_for_testing` so the API answers 401.
2. Check out the tested commit and start the server: `git clone https://github.com/gerred/mcp-server-replicate && cd mcp-server-replicate && git checkout 568024c && REPLICATE_API_TOKEN=r8_invalid_token_for_testing uv run mcp-server-replicate`. The script below starts it for you.
3. Call the tool with `{"query": "tofu poc"}`:

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
               result = await session.call_tool("search_models", {"query": "tofu poc"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (`stdio_client` forwards it to your terminal). One `logger.error` call produces two lines; the second starts with `For more information check:`.

## Expected behavior
Each log record stays on one line. Line breaks inside interpolated exception text are escaped (for example as `\n`).

## Actual behavior
The record is split across two lines. Logged content captured by ToFu's tracer (the `\n` was a real line break):

```
HTTP error during model search: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/models'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401
```

## Impact
Low. The caller (the LLM, possibly steered by prompt injection) controls `query`, but `query` is not part of the logged text, and the line break comes from a fixed httpx template. The practical effect is that line-based log parsers see a broken record. It is mainly a hardening gap: because the code logs `str(err)` verbatim everywhere, any future exception that carries caller text would be logged raw.

## Suggested fix
Escape CR/LF before logging, either per call or once in a formatter:

```python
def _one_line(text: str) -> str:
    return text.replace("\r", "\\r").replace("\n", "\\n")

logger.error("HTTP error during model search: %s", _one_line(str(err)))
```

A `logging.Formatter` subclass that escapes `\r` and `\n` in `record.getMessage()` would cover every call in `replicate_client.py` at once.

## Status on the default branch
Still present at `568024c` (2025-02-28). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 1 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Fired: `check_introspection_log_injection` only.
- Campaigns and executions: `e2-0922`: 1 exec, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): inputs `{'query': ''}`, `{'query': '{{7*7}}'}`, `{'query': '%x %x %x %x'}`, output `None` each. Analysis: "Unneutralized CRLF newline character detected in log output (logger:mcp_server_replicate.replicate_client)! Logged content: 'HTTP error during model search: Client error '401 Unauthorized' for url 'https://api.replicate.com/v1/models'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/401'." The logged content is identical for every input, which supports that input does not reach the log.
- Hand-check hints: **weak, likely a false positive for CWE-117.** The `\n` is from httpx's `HTTPStatusError` template (`httpx/_models.py:812-817` in 0.28.1, read from the local uv cache). ToFu's `check_introspection_log_injection` (`src/sanitizers/introspection.py:807`) flags any record containing `\n`/`\r` with no provenance check. The 401 is only because the fuzz run used a dummy token. Recommend not filing, or folding all nine replicate CWE-117 items into one low-priority hardening issue.
</details>
