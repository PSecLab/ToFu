# `get-price` leaves an aiohttp session unclosed after a failed exchange call (flagged as CWE-117, no caller input in the log)

**Repository:** `Nayshins/mcp-server-ccxt` · **Tool:** `get-price` · **Tested commit:** `f7ddee5`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get-price` fetches a ticker for `symbol` from the selected exchange through `ccxt.async_support`. In our runs the exchange call failed (HTTP 451 from Binance, HTTP 403 from Bybit) and, after the tool returned, asyncio logged a multi-line `Unclosed client session` error. Our fuzzer reported this as log injection because the log record contains a newline. The record is asyncio's own message and contains no tool argument, so this is not a log injection. What remains is an aiohttp `ClientSession` that is not closed after a failed call.

## Details
The handler at `src/server.py:242-251` calls `exchange.fetch_ticker(symbol)`. The shared error handling and cleanup is at `src/server.py:363-374` (tested commit):

```python
    except ccxt.BaseError as e:
        return [
            types.TextContent(
                type="text",
                text=f"Error accessing cryptocurrency data: {str(e)}"
            )
        ]
    finally:
        # Clean up exchange connections
        for instance in exchange_instances.values():
            await instance.close()
        exchange_instances.clear()
```

`src/server.py` has no logging calls at all. The flagged record came from the `asyncio` logger: aiohttp reports a `ClientSession` that is garbage-collected without being closed as `Unclosed client session` followed by `client_session: <...>` on a second line. The `finally` block already calls `close()` on the cached instances, so the leaked session is probably one that ccxt opened outside, or after, that close. We did not pin down which request opens it.

## Steps to reproduce
1. Prerequisites: Python 3.10+, network access to Binance. The leak was observed when the exchange rejected the request (HTTP 451 "restricted location"); we did not check whether a successful call also leaks.
2. Install and start: `git clone https://github.com/Nayshins/mcp-server-ccxt.git && cd mcp-server-ccxt && uv pip install mcp ccxt`, then the server is `python src/server.py` (the command used by `Dockerfile` and `smithery.yaml`).
3. Call the tool with:

   ```json
   {"symbol": "BTC/USDT", "exchange": "binance"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["src/server.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get-price", {"symbol": "BTC/USDT", "exchange": "binance"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. After a failed exchange call an `Unclosed client session` / `client_session: <aiohttp.client.ClientSession object at 0x...>` error appears. Setting `PYTHONASYNCIODEBUG=1` in the server's environment should make aiohttp include a `source_traceback` showing where the session was created.

## Expected behavior
Every HTTP session opened while serving a call is closed before the call finishes, and no `Unclosed client session` error is logged.

## Actual behavior
The tool returned the exchange error:

```
Error accessing cryptocurrency data: binance GET https://api.binance.com/api/v3/exchangeInfo 451  {
  "code": 0,
  "msg": "Service unavailable from a restricted location according to 'b. Eligibility' in https://www.binance.com/en/terms. ..."
}
```

and asyncio logged:

```
Unclosed client session
client_session: <aiohttp.client.ClientSession object at 0x7a0d80ecb250>
```

## Impact
None of the tool arguments reach any log, so an attacker steering the LLM's arguments (for example through prompt injection) cannot forge log lines here. The practical effect is noisy error output on stderr and, over a long session, possibly leaked connections. This is a reliability bug, not a security issue.

## Suggested fix
Make sure every exchange instance used by a call is closed after all of its requests have finished. Running once with `PYTHONASYNCIODEBUG=1` should show which ccxt request creates the leaked session. No log neutralization is needed, since the server writes no logs of its own.

## Status on the default branch
Still present at `f7ddee5` (2025-02-17). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); evidence fired `check_introspection_log_injection` (logger `asyncio`). Also triggered for this tool: `check_introspection_type_confusion`, `check_resource_exhaustion` (not reviewed).
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 exec / 1 ok (60 s budgets). The exec record says 1 call per campaign while three distinct corpus-sbx inputs are in the evidence, so the counts may be per sequence.
- Evidence (verbatim, trimmed):
  - `{'symbol': '', 'exchange': 'binance'}` -> `Error accessing cryptocurrency data: binance GET https://api.binance.com/api/v3/exchangeInfo 451 ...`; logged `'Unclosed client session\nclient_session: <aiohttp.client.ClientSession object at 0x7a0d80ecb250>'`.
  - `{'symbol': 'http://127.0.0.1:8500', 'exchange': 'binance'}` -> same 451; same asyncio record.
  - `{'symbol': '"symbol": "ETH/USDT", "exchane"g :"', 'exchange': 'binance'}` -> same 451; same asyncio record.
- Hand-check hints: weak, false positive for CWE-117. The newline is part of asyncio's fixed `Unclosed client session` message format, and no caller input appears in the record. `src/server.py` has no logger. The identical alert fired on all six data tools of this repo (`get-price`, `get-market-summary`, `get-top-volumes`, `get-historical-ohlcv`, `get-price-change`, `get-volume-history`); at most file one combined, non-security bug about the session leak, or drop all six. Every run was geo-blocked (451/403), so no tool returned market data. Root cause of the leak not verified (ccxt source not available offline); one guess is a parallel request inside ccxt's `load_markets` still in flight when `close()` runs.
</details>
