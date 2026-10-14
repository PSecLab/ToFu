# Log injection in `extract-mcp-servers-from-url`: `url` and fetched content are logged without neutralizing CR/LF

**Repository:** `chatmcp/mcp-server-collector` · **Tool:** `extract-mcp-servers-from-url` · **Tested commit:** `24dfe07`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`extract-mcp-servers-from-url` fetches a URL through `mcp-server-fetch` and passes the text to an LLM. Before that, it writes the caller's `url` and the full fetched text into an INFO log record with an f-string. Neither value is escaped, so a `url` containing CR/LF, or a fetched page containing newlines, can add forged lines to the log. This only matters when a log handler is configured, which the package does not do by default.

## Details
`src/mcp_server_collector/server.py`:

```python
# :77
url = arguments.get("url")
...
content = await call_fetch_tool(url)          # :81
...
logger.info(f"Fetched content from {url}: {content}")             # :104
mcp_servers = await extract_mcp_servers_from_content(content)
...
logger.info(f"Extracted MCP Servers from {url}: {mcp_servers}")   # :110
```

`url` comes straight from the tool arguments. `content` is the raw page (or the fetch tool's error text), up to 100000 characters (`fetch.py:19`). `extract.py:16` also logs the whole prompt, which embeds `content`. None of these strip or escape `\r` and `\n`.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. The first call downloads `mcp-server-fetch` via `uvx`, which needs network access to PyPI. No OpenAI key is needed: the log line is written before the OpenAI call.
2. Clone the repo and run `uv sync`. The package configures no log handler, so start it with INFO logging to stderr enabled (see the `args` below).
3. Call the tool with `{"url": "tofu-poc\r\nFAKE-LOG-ENTRY"}`. This is not a valid URL, so no request is made; the fetch tool returns a validation error and the server logs it:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/path/to/mcp-server-collector", "run", "python", "-c",
                 "import logging; logging.basicConfig(level=logging.INFO); "
                 "import mcp_server_collector; mcp_server_collector.main()"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "extract-mcp-servers-from-url", {"url": "tofu-poc\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr: `FAKE-LOG-ENTRY: 1 validation error for Fetch` starts a new line with no logger prefix, so it reads as a separate entry.

## Expected behavior
CR and LF in logged values are escaped (for example, shown as `\r\n`) or removed, so one call produces one log record per line.

## Actual behavior
The values are logged verbatim. ToFu's tracer captured this record for `{"url": "../../../../etc/passwd"}` (the newlines here come from the fetch tool's error text):

```
Fetched content from ../../../../etc/passwd: 1 validation error for Fetch
url
  Input should be a valid URL, relative URL without a base [type=url_parsing, ...]
```

## Impact
`url` is chosen by the LLM and can be steered by prompt injection, and `content` is whatever the fetched page contains, so both are attacker-influenced. If an operator adds a log handler (file, syslog, a log collector), forged lines can mislead whoever reads those logs. Low severity: by default these INFO records are not written anywhere.

## Suggested fix
Escape CR/LF before logging, for example `safe = s.replace("\r", "\\r").replace("\n", "\\n")`, or log with `%r` (`logger.info("Fetched content from %r", url)`). Consider logging only the length or a short prefix of `content` and of the prompt in `extract.py:16`, rather than the full page.

## Status on the default branch
Still present at `24dfe07` (2024-12-09). The default branch head is the tested commit.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The issues are a missing LICENSE (#1) and an mcp.so listing removal request (#5); the pull requests add deployment config and badges. The README only lists the tool and its `url` argument and says nothing about logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; `check_introspection_log_injection` on all evidence calls. Also fired for this tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_resource_exhaustion` (not analysed here).
- Campaigns and executions: recover-pc 1 exec / 0 ok; e2-0922 1 exec / 0 ok. Only one call per campaign ran.
- Evidence (verbatim, trimmed): `{'url': '../../../../etc/passwd'}` -> output `None`; logged `'Fetched content from ../../../../etc/passwd: 1 validation error for Fetch\nurl\n  Input should be a valid URL, relative URL without a base ...'`. Same for `'/etc/passwd\x00'` and `'..\\..\\..\\..\\windows\\win.ini'`.
- Hand-check hints: weak. The sink is real (`server.py:104` f-string logs `url` and `content` raw). But in the evidence the CR/LF came from `mcp-server-fetch`'s pydantic error text, not from the caller's `url`, which held no newline. The repo configures no handler on the `mcp-server-collector` logger (no `basicConfig`/`addHandler` in `src/`), so INFO records are dropped by Python's last-resort handler unless something else configures logging; I could not check whether the `mcp` SDK does (not installed locally). My reproduction depends on adding `basicConfig` at launch. The more relevant risk in this tool is that it fetches any caller URL via `mcp-server-fetch` with `raw: True`, which is outside this CWE. Reproduction not executed by me.
</details>
