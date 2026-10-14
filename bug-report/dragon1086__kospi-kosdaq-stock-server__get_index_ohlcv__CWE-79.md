# Missing output encoding in `get_index_ohlcv`: an invalid `fromdate` is echoed raw in the error

**Repository:** `dragon1086/kospi-kosdaq-stock-server` · **Tool:** `get_index_ohlcv` · **Tested commit:** `8455054`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_index_ohlcv` returns OHLCV data for a KRX index over a date range. When `fromdate` or `todate` is not a valid date, `validate_date` raises a `ValueError` that embeds the raw input, and the tool returns that message as the `error` field. Any markup or template syntax in the date argument comes back unescaped in the tool result. The same string is also written unchanged to the server's log file.

## Details
`kospi_kosdaq_stock_server.py:119-130` at `8455054`:

```python
def validate_date(date_str: Union[str, int]) -> str:
    try:
        if isinstance(date_str, int):
            date_str = str(date_str)
        if '-' in date_str:
            parsed_date = datetime.strptime(date_str, '%Y-%m-%d')
            return parsed_date.strftime('%Y%m%d')
        datetime.strptime(date_str, '%Y%m%d')
        return date_str
    except ValueError:
        raise ValueError(f"Date must be in YYYYMMDD format. Input value: {date_str}")
```

`get_index_ohlcv` (`kospi_kosdaq_stock_server.py:459-490`) calls `validate_date(fromdate)` first and catches every exception:

```python
    try:
        fromdate = validate_date(fromdate)
        todate = validate_date(todate)
        ...
    except Exception as e:
        error_message = f"Data retrieval failed: {str(e)}"
        logger.error(error_message)
        return {"error": error_message}
```

Nothing escapes, filters or truncates the value before it is returned. The date check runs before the KRX client is created, so no credentials are needed to reach this path. `logger.error` writes to the file handler set up at lines 23-30, so CR/LF in the argument also lands in the log as-is.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No `KRX_ID`/`KRX_PW` or Kakao credentials are needed, and the Playwright browser is not used on this path.
2. Install and start the server from source:
   ```
   git clone https://github.com/dragon1086/kospi-kosdaq-stock-server.git
   cd kospi-kosdaq-stock-server && git checkout 8455054a043376cfde22e472c3fb3241bcc57f32
   uv venv .venv && source .venv/bin/activate
   uv pip install -e .
   python kospi_kosdaq_stock_server.py
   ```
3. Call the tool with these arguments:
   ```json
   {"fromdate": "<b>tofu-poc</b>{{7*7}}", "todate": "20240131", "ticker": "1001", "freq": "d"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["kospi_kosdaq_stock_server.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_index_ohlcv", {"fromdate": "<b>tofu-poc</b>{{7*7}}", "todate": "20240131", "ticker": "1001", "freq": "d"})
               print(result)

   asyncio.run(main())
   ```
   Run the script from the repository directory with the virtual environment active.
4. What to observe: the text content is a JSON object whose `error` value ends with `Input value: <b>tofu-poc</b>{{7*7}}`, with the markup and braces unchanged.

## Expected behavior
An invalid date should produce a fixed message, for example `fromdate must be YYYYMMDD or YYYY-MM-DD`, or one that quotes an escaped and length-capped copy of the value.

## Actual behavior
The raw argument is reflected. From the fuzzing run (input `fromdate = '$-`-'$`{{"t{"t `):

```
{
  "error": "Data retrieval failed: Date must be in YYYYMMDD format. Input value: '$-`-'$`{{\"t{\"t "
}
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in untrusted content can steer them. The result then carries caller-chosen markup back into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low. The unescaped copy in the log file is a separate, small log-forging concern.

## Suggested fix
Make `validate_date` reject bad input with a fixed message instead of echoing it. A strict pattern check (`^\d{8}$` or `^\d{4}-\d{2}-\d{2}$`) before `strptime` keeps the error short. If you want to show the value, use `repr()` and cap it at a few dozen characters. Strip or escape CR/LF before passing the message to `logger.error`. Because all date-taking tools share `validate_date`, one change covers `get_stock_ohlcv`, `get_stock_market_cap`, `get_stock_fundamental`, `get_stock_trading_volume` and `get_index_ohlcv`.

## Status on the default branch
Still present at `0e6446f` (2026-09-11). `kospi_kosdaq_stock_server.py` is identical at the tested commit and at HEAD. The only commit since (`0e6446f`, PR #12) changes `krx_data_client.py`, `pyproject.toml` and adds a test.

## Prior reports
None found. Searched all 2 issues and 8 pull requests (fetched 2026-10-01) and the README / README_LEGACY on the default branch. The README only documents the `YYYYMMDD` date format. Issue #8 "Security scan results for kospi-kosdaq-stock-server - 97/100" (open 2026-04-04) is a third-party scan of all tools; its only note is that the resource descriptions are Korean-only, and it does not mention echoed input.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. `check_introspection_log_injection` also fired for this tool according to `triggered`, but none of the evidence rows show its logged content.
- Campaigns and executions: corpus-sbx 3,072 exec / 3,070 ok (60 s).
- Evidence (verbatim, trimmed): input `{'fromdate': '\'$-`-\'$`{{"t{"t ', 'todate': '', 'ticker': '', 'freq': ''}` -> `'{\n  "error": "Data retrieval failed: Date must be in YYYYMMDD format. Input value: \'$-`-\'$`{{\\"t{\\"t "\n}'`. Two more inputs of the same shape (with `\x7f` bytes) gave the same output.
- Hand-check hints: weak. Only `{{` was reflected, into JSON text content. The `<b>` reproduction is derived from reading `validate_date` (line 130), not from a logged run. All five date-taking tools in this repo share the same root cause; consider filing one combined issue instead of five. A possibly stronger angle is CWE-117: `logger.error(error_message)` writes the raw value to the file log configured at lines 23-30, so `\r\n` in `fromdate` would forge a log line. That angle was not checked against a run log. The tested `mcp` version in `uv.lock` is 1.25.0.
</details>
