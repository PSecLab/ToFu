# Log output not neutralized in `get_paper_data`: HTTP error text is logged verbatim as multi-line records (low impact)

**Repository:** `andybrandt/mcp-simple-arxiv` · **Tool:** `get_paper_data` · **Tested commit:** `fc9262e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_paper_data` looks up a paper by `paper_id` through `ArxivClient.get_paper`. When arXiv answers with an HTTP error (an empty or malformed ID gives `400 Bad Request`), the client logs `f"HTTP error while fetching paper: {e}"`. The httpx exception text spans two lines and includes the request URL with the caller's ID in it. The message is logged without escaping line breaks. The caller's ID is percent-encoded in the URL, so this path does not appear to let a caller forge a log line. The practical impact is low.

## Details
`mcp_simple_arxiv/arxiv_client.py:240-263`:

```python
params = {
    "id_list": paper_id,
    "max_results": 1
}

async with httpx.AsyncClient(timeout=20.0) as client:
    try:
        response = await client.get(self.base_url, params=params)
        response.raise_for_status()
        ...
    except httpx.HTTPError as e:
        logger.error(f"HTTP error while fetching paper: {e}")
        raise ValueError(f"arXiv API HTTP error: {str(e)}")
```

`paper_id` comes straight from the tool argument (`mcp_simple_arxiv/server.py:263-265`). httpx encodes it into the query string, and the logged URLs show it (`[object Object]` became `%5Bobject+Object%5D`). A CR/LF in `paper_id` should therefore appear as `%0D%0A`. The raw line break in the record comes from httpx's fixed `\nFor more information check: ...` suffix.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and network access to `export.arxiv.org`.
2. Install and start as the README describes: `pip install mcp-simple-arxiv`. The server command is `python -m mcp_simple_arxiv`.
3. Call the tool twice:
   ```json
   {"paper_id": ""}
   {"paper_id": "2103.08220\r\nFAKE-LOG-ENTRY"}
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
               for pid in ["", "2103.08220\r\nFAKE-LOG-ENTRY"]:
                   result = await session.call_tool("get_paper_data", {"paper_id": pid})
                   print(repr(pid), result)

   asyncio.run(main())
   ```
4. Observe the server's stderr, shown in the terminal running the script. The first call writes a two-line record: `HTTP error while fetching paper: Client error '400 Bad Request' for url 'https://export.arxiv.org/api/query?id_list=&max_results=1'` followed by `For more information check: ...`. For the second call, if arXiv rejects the ID with an HTTP error, the injected `\r\n` appears percent-encoded in the URL.

## Expected behavior
Each log record stays on one line. Exception text is logged with line breaks and other control characters escaped, or the status code and URL are logged as separate fields.

## Actual behavior
From the fuzzing run (log content as reported by ToFu's tracer, newline shown as `\n`):

```
HTTP error while fetching paper: Client error '400 Bad Request' for url 'https://export.arxiv.org/api/query?id_list=%5Bobject+Object%5D&max_results=1'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
```

## Impact
`paper_id` is chosen by the LLM and can be steered by prompt injection. Based on the code and the logged URLs, the caller cannot put its own CR/LF into this record, because httpx percent-encodes it. The only effect is that one error spans two lines, which can confuse line-based log parsing. Low severity. It is reported mainly so that error logging escapes control characters as a matter of practice.

## Suggested fix
- Log `e.response.status_code` and `e.request.url` as separate values, or log `repr(str(e))`. Alternatively, install a `logging.Formatter` that replaces `\r` and `\n` in messages.
- Validate `paper_id` against the arXiv ID formats (`^\d{4}\.\d{4,5}(v\d+)?$` and the old `archive/NNNNNNN` form) before calling the API. That also avoids the round trip for empty or junk IDs.

## Status on the default branch
Still present at `fc9262e` (2026-02-19). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` (all evidence), `check_resource_exhaustion` on two calls (3.0-3.5 s vs 2.0 s limit; the client's 3 s rate limiter, not a bug). `check_introspection_incomplete_cleanup` and `check_introspection_temp_file_leak` also fired on this tool, with no evidence attached.
- Campaigns and executions: e2-0922 1 exec / 0 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'paper_id': ''}` -> output `None`; logged `HTTP error while fetching paper: Client error '400 Bad Request' for url 'https://export.arxiv.org/api/query?id_list=&max_results=1'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400`
  - `{'paper_id': 'null'}` -> same record with `id_list=null`
  - `{'paper_id': '[object Object]'}` -> same record with `id_list=%5Bobject+Object%5D`
- Hand-check hints: weak, likely a false positive. The newline is httpx's `HTTPStatusError` template, not caller input. No evidence input contained CR/LF, and caller input is percent-encoded in the logged URL. The gpt41-corpus VM log for this tool (29 log-injection hits) shows only this same httpx message. I could not confirm what arXiv returns for a CR/LF-bearing ID (arxiv.org is blocked here). I recommend not filing, or filing only as a hygiene note. The reproduction above was derived from the code and has not been run.
</details>
