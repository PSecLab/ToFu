# Possible log injection in `yfinance_get_holders`: `symbol` is logged raw when a holder section fails

**Repository:** `narumiruna/yfinance-mcp` · **Tool:** `yfinance_get_holders` · **Tested commit:** `9ce2bda`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`yfinance_get_holders` fetches six holder sections for a ticker. When fetching a section raises, the server logs a warning through `loguru` that includes the caller's `symbol` unchanged. A `\r` or `\n` in `symbol` would then start a new line on stderr. Our fuzzer flagged this tool, but the line it captured came from the `yfinance` library itself, not from the caller's input. This report is based on code reading and has not been confirmed in a run.

## Details
`src/yfmcp/server.py:1793-1809` (tested commit):

```python
async def _fetch_holder_section(symbol: str, ticker: yf.Ticker, attr_name: str, ...) -> None:
    try:
        df = await asyncio.to_thread(lambda t=ticker: getattr(t, attr_name))
    except Exception as exc:
        logger.warning("Failed to fetch {} for {}: {}", attr_name, symbol, exc)
        fetch_errors.append(exc)
        return
```

`symbol` is a free string (`Annotated[str, ...]`, `server.py:1834-1835`) and is never validated. `logger` is `loguru` (`server.py:9`). No sink is configured, so loguru's default stderr sink is used, which writes the message as is. MCP hosts usually capture server stderr into their own log files.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`. For the warning to fire, the holder fetch must raise. A network error is one way to make that happen; we have not confirmed that yfinance raises instead of handling the error itself.
2. Install and start the server as the README describes:
   `git clone https://github.com/narumiruna/yfinance-mcp.git && cd yfinance-mcp && git checkout 9ce2bda && uv sync`
3. Call the tool with:

   ```json
   {"symbol": "AAPL\r\nFAKE-LOG-ENTRY", "max_rows": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv", args=["run", "--directory", "/path/to/yfinance-mcp", "yfmcp"],
           env={"HTTPS_PROXY": "http://127.0.0.1:9", "PATH": "/usr/bin:/bin:/usr/local/bin"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("yfinance_get_holders",
                   {"symbol": "AAPL\r\nFAKE-LOG-ENTRY", "max_rows": 1})
               print(result)

   asyncio.run(main())
   ```
   (`HTTPS_PROXY` points at a closed local port only to make the fetch fail.)
4. Look at the server's stderr for a `WARNING ... Failed to fetch major_holders for AAPL` line followed by a line that starts with `FAKE-LOG-ENTRY`.

## Expected behavior
`symbol` is validated as a ticker before use, or escaped before it is logged.

## Actual behavior
Not observed in our run. The only CR/LF the fuzzer saw came from the third-party `yfinance` logger, and it did not contain the symbol:

```
logger yfinance: 'HTTP Error 404: Not Found\r\n'
```

The tool itself returned `{"error": "No holder data available for '../../../../etc/passwd'. ...", "error_code": "NO_DATA", ...}`.

## Impact
The LLM chooses `symbol`, and prompt injection can steer it. If the warning path is reached, an attacker can add fake lines to the stderr log the MCP host keeps. Low severity. The same pattern exists in other loguru calls that include caller values, such as `server.py:1735` (option chain `symbol` and `date`).

## Suggested fix
Validate `symbol` against a ticker pattern (for example `^[A-Za-z0-9.\-^=]{1,20}$`) at the top of each tool. Or configure loguru with a `patcher` / custom format that escapes `\r` and `\n` in the message.

## Status on the default branch
Still present at `16656f6` (2026-09-29). There are no changes under `src/` since the tested commit; the log call is still at `src/yfmcp/server.py:1807`.

## Prior reports
None found. Searched all 6 issues and 171 pull requests (fetched 2026-10-01) and the README / docs on the default branch. Most pull requests are dependency bumps. #121 "feat: get holders tool", #122 "Add `yfinance_get_holders` and return `NETWORK_ERROR` for retryable holder fetch failures" and #124 "[codex] Limit holder output rows" (PRs, all closed 2026-05-04) built this tool; none mentions logging or symbol validation. No issue or pull request mentions log injection, CR/LF or loguru output.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection`. Also fired: `check_invalid_json`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok (60 s); e2-0922 1 exec / 1 ok (60 s). Only one call per campaign.
- Evidence (verbatim, trimmed):
  - `{'symbol': '../../../../etc/passwd', 'max_rows': 10}` -> `'{"error": "No holder data available for \'../../../../etc/passwd\'. Verify the symbol is correct.", "error_code": "NO_DATA", "details": {"symbol": "../../../../etc/passwd"}}'`; logged by `yfinance`: `'HTTP Error 404: Not Found\r\n'`.
  - Same symbol with `max_rows: 0`, same output and log line.
- Hand-check hints: unclear. The ToFu alert itself is a false positive for this repo: the CR/LF is in an upstream HTTP error message logged by the yfinance library, with no caller input in it. The vector in this draft (`symbol` into `logger.warning` at `server.py:1807`) is from code reading only. I could not check whether yfinance 1.7.0 raises from `Ticker.major_holders` etc. on network errors (if it swallows them, the line is never logged), and I did not run the repro. ToFu's log hook appears to cover stdlib `logging` only, so loguru calls would not show up in its evidence. Recommend not filing unless the repro shows the forged line.
</details>
