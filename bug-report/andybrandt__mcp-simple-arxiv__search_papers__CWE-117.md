# Log output not neutralized in `search_papers`: HTTP error text is logged verbatim as multi-line records (low impact)

**Repository:** `andybrandt/mcp-simple-arxiv` · **Tool:** `search_papers` · **Tested commit:** `fc9262e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
When the arXiv API answers `search_papers` with an HTTP error, `ArxivClient.search` logs `f"HTTP error while searching: {e}"`. The httpx exception text spans two lines and contains the full request URL, which is built from the caller's `query`, date filter and `max_results`. The message is written without escaping line breaks, so every such failure produces a multi-line log record. The caller's own input is percent-encoded inside the URL, so this path does not appear to let a caller inject a forged line. The practical impact is low.

## Details
`mcp_simple_arxiv/arxiv_client.py:173-182` builds the request from caller input, and `:219-221` logs the exception:

```python
params = {
    "search_query": query,
    "max_results": max_results,
    "sortBy": sort_by.value,
    "sortOrder": sort_order.value,
}

async with httpx.AsyncClient(timeout=20.0) as client:
    try:
        response = await client.get(self.base_url, params=params)
        response.raise_for_status()
        ...
    except httpx.HTTPError as e:
        logger.error(f"HTTP error while searching: {e}")
        raise ValueError(f"arXiv API HTTP error: {str(e)}")
```

`query` comes from `search_papers` (`mcp_simple_arxiv/server.py:215-226`), wrapped as `({query}) AND submittedDate:[...]` when dates are given. httpx encodes query parameters, and the logged URLs show it (`'` became `%27`, `[` became `%5B`, spaces became `+`). A CR/LF in `query` should therefore appear as `%0D%0A`, not as a line break. The line break ToFu saw is the fixed `\nFor more information check: ...` suffix that httpx adds to `HTTPStatusError` messages.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and network access to `export.arxiv.org`.
2. Install and start as the README describes: `pip install mcp-simple-arxiv`. The server command is `python -m mcp_simple_arxiv`.
3. Call the tool:
   ```json
   {"query": "ti:tofu\r\nFAKE-LOG-ENTRY", "max_results": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "mcp_simple_arxiv"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "search_papers", {"query": "ti:tofu\r\nFAKE-LOG-ENTRY", "max_results": 1})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr, which is shown in the terminal running the script. If arXiv answers with an HTTP error (during fuzzing every search received `406 Not Acceptable`), the record spans two lines: `HTTP error while searching: Client error '...' for url '...'` followed by `For more information check: https://developer.mozilla.org/...`. The injected `\r\n` shows up percent-encoded in the URL. If arXiv answers 200, nothing is logged.

## Expected behavior
Each log record stays on one line. Exception text is logged with line breaks and other control characters escaped (for example via `repr()` or a formatter that escapes them), or the status code and URL are logged as separate fields.

## Actual behavior
The record contains a raw newline from the httpx message. From the fuzzing run (log content as reported by ToFu's tracer, newline shown as `\n`):

```
HTTP error while searching: Client error '406 Not Acceptable' for url 'https://export.arxiv.org/api/query?search_query=%281%27+OR+%271%27%3D%271%29+AND+submittedDate%3A%5B201901010000+TO+201912312359%5D&max_results=0&sortBy=lastUpdatedDate&sortOrder=descending'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/406
```

## Impact
`query` is chosen by the LLM and can be steered by prompt injection. Based on the code and the logged URLs, the caller cannot place its own CR/LF into this log line, because httpx percent-encodes it. The only effect is that one error spans two lines, which can confuse line-based log parsing. Low severity. It is reported mainly so that error logging escapes control characters as a matter of practice.

## Suggested fix
- Log `e.response.status_code` and `e.request.url` as separate values, or log `repr(str(e))`. Alternatively, install a `logging.Formatter` that replaces `\r` and `\n` in the message.
- Apply the same treatment to the other `logger.error` calls in `arxiv_client.py` (lines 262, 307, 312).

## Status on the default branch
Still present at `fc9262e` (2026-02-19). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` (all evidence), `check_resource_exhaustion` on two calls (2.8-2.9 s vs 2.0 s limit; network latency plus the 3 s rate limiter, not a bug).
- Campaigns and executions: corpus-sbx 512 exec / 482 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'query': "1' OR '1'='1", 'max_results': 0, 'sort_by': 'updated_date', 'sort_order': 'descending', 'date_from': '2019-01-01', 'date_to': '2019-12-31'}` -> output `None`; logged `HTTP error while searching: Client error '406 Not Acceptable' for url '...search_query=%281%27+OR+%271%27%3D%271%29+AND+submittedDate...'\nFor more information check: ...`
  - `{'query': 'ti:"neural networks" AND cat:cs.AI', 'max_results': 10, ...}` -> same 406 record
  - `{'query': '..\\..\\..\\..\\windows\\win.ini', 'max_results': -1, ...}` -> same 406 record
- Hand-check hints: weak, likely a false positive. The newline that triggered the alert is httpx's own `HTTPStatusError` template (`\nFor more information check:`), not caller input. Caller input is visibly percent-encoded in every logged URL. No evidence call contained CR/LF. The gpt41-corpus VM logs for the sibling tools show the same pattern: every log-injection hit is this httpx message. The 406 responses on valid queries suggest arXiv was blocking or rate-limiting the test host. I could not check arXiv's behavior because arxiv.org is blocked here. I recommend not filing, or filing only as a hygiene note. The reproduction above was derived from the code and has not been run.
</details>
