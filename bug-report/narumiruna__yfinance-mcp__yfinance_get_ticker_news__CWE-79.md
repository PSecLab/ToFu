# Missing output encoding in `yfinance_get_ticker_news`: `symbol` is echoed raw into the error reply

**Repository:** `narumiruna/yfinance-mcp` · **Tool:** `yfinance_get_ticker_news` · **Tested commit:** `9ce2bda`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`yfinance_get_ticker_news` fetches news for a ticker. When there is no news, or the fetch fails, the JSON error reply repeats the caller's `symbol` in both the `error` message and `details.symbol`. The symbol is not validated, so any text, including markup, comes back. The reply is JSON in a plain MCP text block, so this is low severity.

## Details
`src/yfmcp/server.py:791-809` (tested commit):

```python
try:
    ticker = await asyncio.to_thread(yf.Ticker, symbol)
    news = await asyncio.to_thread(ticker.get_news)
...
if not news:
    return create_error_response(
        f"No news articles available for '{symbol}'. "
        "This may indicate an invalid symbol or no recent news coverage.",
        error_code="NO_DATA",
        details={"symbol": symbol},
    )
```

`create_error_response` serializes with `json.dumps(..., ensure_ascii=False)` (`src/yfmcp/utils.py:6-24`). That escapes quotes and control characters but leaves `<`, `>` and `{{` as they are. The exception path at `server.py:796-801` echoes `symbol` the same way.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, network access to Yahoo Finance (without it, the `API_ERROR` path echoes the symbol too).
2. Install and start the server as the README describes:
   `git clone https://github.com/narumiruna/yfinance-mcp.git && cd yfinance-mcp && git checkout 9ce2bda && uv sync`
3. Call the tool with:

   ```json
   {"symbol": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv", args=["run", "--directory", "/path/to/yfinance-mcp", "yfmcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("yfinance_get_ticker_news",
                   {"symbol": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `<b>tofu-poc</b>` unchanged in `error` and in `details.symbol`.

## Expected behavior
`symbol` is checked against a ticker pattern and rejected with `INVALID_PARAMS` if it does not match, so free text is never echoed.

## Actual behavior
From the fuzzing run:

```
{"error": "No news articles available for '{{\"'. This may indicate an invalid symbol or no recent news coverage.", "error_code": "NO_DATA", "details": {"symbol": "{{\""}}
```

## Impact
The LLM chooses `symbol`, and prompt injection can steer it. The echoed value goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity.

## Suggested fix
Validate `symbol` once, for example with `Field(pattern=r"^[A-Za-z0-9.\-^=]{1,20}$")` on the parameter, and reuse it for every tool that takes a ticker.

## Status on the default branch
Still present at `16656f6` (2026-09-29). There are no changes under `src/` since the tested commit; the reply is still built at `src/yfmcp/server.py:803-809`.

## Prior reports
None found about escaping or symbol validation. Searched all 6 issues and 171 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #79 "feat: improve code quality with constants and structured error handling" (PR, closed 2026-01-01): introduced the `error` / `error_code` / `details` replies, with "Detailed context (symbol, sector, parameters, exception info)". The echo of `symbol` in `details` is intended by this design; nothing about encoding.
- Documentation: AGENTS.md: "Errors MUST be returned via `create_error_response()` with structured JSON (`error`, `error_code`, optional `details`)." (the same design rule; says nothing about escaping caller input)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output`. `check_invalid_json` also fired via the "Silent Bug" rule (input-side only; the reply is valid JSON).
- Campaigns and executions: corpus-sbx 512 exec / 512 ok (60 s). Not seen in e2-0922.
- Evidence (verbatim, trimmed):
  - `{'symbol': '{{"'}` -> `{"error": "No news articles available for '{{\"'. ...", "error_code": "NO_DATA", "details": {"symbol": "{{\""}}`
  - `{'symbol': '\x7f\x7f\x7f\x7f\x7f\x7f]{{"'}` -> same, with DEL bytes.
  - `{'symbol': '\x7f\x7f\x7f\x7f\x7f\x7f]{{\x7f\x7f\x7f\x7f\x7f"'}` -> same.
- Hand-check hints: weak. Only `{{` was echoed, inside a JSON string in a plain-text reply (confirmed at `server.py:803-809`). The `<b>` payload is my substitution and was not run. Probably not worth filing as XSS; a "validate ticker symbols" hardening note at most.
</details>
