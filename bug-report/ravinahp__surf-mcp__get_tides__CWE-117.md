# Multi-line error text in `get_tides` log output (fuzzer report; caller CR/LF appears blocked by httpx)

**Repository:** `ravinahp/surf-mcp` · **Tool:** `get_tides` · **Tested commit:** `8364990`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_tides` builds a Storm Glass URL from `latitude`, `longitude` and `date`, and logs `str(e)` when the request fails. Our fuzzer flagged the log line because it contained a newline. That newline is part of httpx's own fixed error text, not the caller's input. A CR or LF in `date` makes httpx reject the URL with an error that shows the character escaped. So we found no way for a caller to forge log lines. A smaller, related problem is that `date` is not validated or URL-encoded before it goes into the query string.

## Details
`src/surf/stormglass_api.py:63-76` (tested commit) builds the query string by hand:

```python
params = {
    "lat": latitude,
    "lng": longitude,
    "start": f"{date}T00:00:00Z",
    "end": f"{date}T23:59:59Z"
}
param_string = "&".join(f"{k}={v}" for k, v in params.items())
full_url = f"{url}?{param_string}"
```

and `make_request` logs any exception (`stormglass_api.py:27-34`):

```python
except Exception as e:
    logger.error(f"API request failed: {str(e)}")
```

For an HTTP 4xx, `str(e)` is httpx's `HTTPStatusError` message, which always contains a newline before `For more information check: ...`. For a `date` containing `\r` or `\n`, httpx 0.28.1 (the version in `uv.lock`) raises `InvalidURL("Invalid non-printable ASCII character in URL, '\r' at position N.")`, with the character shown escaped. `date` is otherwise free text (the docstring asks for `YYYY-MM-DD` but nothing checks it), so `&` or `#` in it changes the request's query parameters.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`. A Storm Glass API key is optional: without one the API answers with an error, which is enough here.
2. Install and start the server as the README describes: `git clone https://github.com/ravinahp/surf-mcp.git && cd surf-mcp && uv sync`
3. Call the tool with:

   ```json
   {"latitude": 0.0, "longitude": 0.0, "date": "2024-06-01\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv", args=["--directory", "/path/to/surf-mcp", "run", "surf-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_tides", {
                   "latitude": 0.0, "longitude": 0.0, "date": "2024-06-01\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Check the server's stderr for the `API request failed: ...` line and whether `FAKE-LOG-ENTRY` starts its own line. We expect it not to, because httpx rejects the URL and the error shows `'\r'` escaped. The server adds no log handlers of its own; where the ERROR line ends up depends on the logging set up by the `mcp` package.

## Expected behavior
`date` is validated as `YYYY-MM-DD` before use, and query parameters are passed to httpx through `params=` so they are encoded.

## Actual behavior
The fuzzer only recorded httpx's own two-line message:

```
API request failed: Client error '422 Unprocessable Entity' for url 'https://api.stormglass.io/v2/tide/extremes/point?lat=0.0&lng=0.0&start=T00:00:00Z&end=T23:59:59Z'
For more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/422
```

The tool returned `Unable to fetch tide data for this location.`

## Impact
None shown for log injection. `date` is chosen by the LLM and can be steered by prompt injection, but caller CR/LF does not reach the log raw. The unvalidated `date` lets a caller add or override query parameters on the Storm Glass request, which is sent with the server's API key. That is minor.

## Suggested fix
Validate `date` with `datetime.date.fromisoformat(date)` and return a clear error if it fails. Pass parameters with `client.get(url, params=params, ...)` instead of building the query string by hand. Optionally log `repr(e)` or replace newlines so each failure stays on one log line.

## Status on the default branch
Unchanged at `8364990` (2025-01-14). The tested commit is the current default branch head.

## Prior reports
None found. The repository has 0 issues and 1 pull request (#1, a directory badge), fetched 2026-10-01; searched those and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_introspection_log_injection` only.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok (60 s); e2-0922 1 exec / 1 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'latitude': 0.0, 'longitude': 0.0, 'date': ''}` -> `'Unable to fetch tide data for this location.'`; logged `API request failed: Client error '422 Unprocessable Entity' for url '...?lat=0.0&lng=0.0&start=T00:00:00Z&end=T23:59:59Z'\nFor more information check: ...`
  - `{'latitude': 35.6895, 'longitude': 139.6917, 'date': ''}` -> same shape.
  - `{'latitude': -9999999999, 'longitude': 9999999999, 'date': '2024-06-01'}` -> same shape.
- Hand-check hints: weak, likely false positive. Recommend not filing as CWE-117. The newline in every evidence line is httpx's fixed `HTTPStatusError` text; no caller input contained CR/LF. I checked httpx 0.28.1's `_urlparse.py` (local copy, same version as `uv.lock`): it raises `InvalidURL` for any non-printable ASCII character and formats it with `!r`, so CR/LF in `date` should be logged escaped. Not run. The only possibly useful report is "validate `date` and use `params=`" (query parameter injection, CWE-88-like), which is low value.
</details>
