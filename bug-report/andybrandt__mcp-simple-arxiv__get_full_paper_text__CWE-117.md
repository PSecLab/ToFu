# Log output not neutralized in `get_full_paper_text`: raw `paper_id` and multi-line exception text written to the error log (low impact)

**Repository:** `andybrandt/mcp-simple-arxiv` · **Tool:** `get_full_paper_text` · **Tested commit:** `fc9262e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_full_paper_text` looks up `paper_id`, downloads the PDF and converts it with Docling. Two of its error paths log the caller's `paper_id` as raw text, and the lookup path logs the multi-line httpx exception text. Nothing escapes line breaks before logging. In the fuzzing run only the httpx message (with the ID percent-encoded) was seen. The raw-ID log lines are reached only after arXiv has accepted the ID, so it is unclear whether a caller can actually get a CR/LF into them.

## Details
`mcp_simple_arxiv/arxiv_client.py:285` first calls `get_paper(paper_id)`, which on an HTTP error logs `f"HTTP error while fetching paper: {e}"` (line 262). That message contains a raw newline from httpx and the request URL, with the ID percent-encoded.

If the lookup succeeds, the conversion error paths log the original `paper_id` unescaped (`arxiv_client.py:306-313`):

```python
except asyncio.TimeoutError:
    error_msg = f"Timeout: PDF conversion exceeded 120 seconds for paper {paper_id}"
    logger.error(error_msg)
    return error_msg

except Exception as e:
    logger.error(f"Error converting paper {paper_id} to Markdown: {e}", exc_info=True)
    return f"Error while converting paper to Markdown: {str(e)}"
```

`paper_id` reaches these lines unchanged from the tool argument (`mcp_simple_arxiv/server.py:316-328`), with no format check. Any CR/LF in it would start a new line in the log. The open question is whether arXiv returns an entry with a PDF link for an ID containing CR/LF. For malformed IDs it returned `400` during fuzzing, which ends at line 262 instead.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and network access to `export.arxiv.org` and `arxiv.org`. Docling is installed as a dependency.
2. Install and start as the README describes: `pip install mcp-simple-arxiv`. The server command is `python -m mcp_simple_arxiv`.
3. Call the tool:
   ```json
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
               result = await session.call_tool(
                   "get_full_paper_text", {"paper_id": "2103.08220\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr, shown in the terminal running the script. If arXiv rejects the ID, you get the two-line httpx record from line 262, with `%0D%0AFAKE-LOG-ENTRY` encoded in the URL. If arXiv accepts the ID and the conversion then fails or times out, the record from line 307 or 312 contains the raw ID, and `FAKE-LOG-ENTRY` starts a line of its own.

## Expected behavior
Each log record stays on one line. Caller-supplied values and exception text are logged with control characters escaped (for example `%r` formatting). `paper_id` is validated against the arXiv ID format before use.

## Actual behavior
From the fuzzing run (log content as reported by ToFu's tracer, newline shown as `\n`):

```
HTTP error while fetching paper: Client error '400 Bad Request' for url 'https://export.arxiv.org/api/query?id_list=null&max_results=1'\nFor more information check: https://developer.mozilla.org/en-US/docs/Web/HTTP/Status/400
```

No fuzzing call reached lines 307 or 312.

## Impact
`paper_id` is chosen by the LLM and can be steered by prompt injection. If a CR/LF-bearing ID gets past the arXiv lookup, the caller can add fake lines to the server's log, which misleads anyone reading or parsing it. If it does not, the only effect is a two-line record from httpx's message. Either way the severity is low.

## Suggested fix
- Validate `paper_id` against the arXiv ID formats (`^\d{4}\.\d{4,5}(v\d+)?$` and the old `archive/NNNNNNN` form) at the start of the tool.
- Log values with `%r` (`logger.error("Error converting paper %r to Markdown: %s", paper_id, e)`), or install a formatter that escapes `\r` and `\n`. Do the same for line 262.

## Status on the default branch
Still present at `fc9262e` (2026-02-19). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_introspection_log_injection` and `check_resource_exhaustion` (3.4-6.0 s vs 2.0 s limit; the method calls `_wait_for_rate_limit()` twice, at line 283 and inside `get_paper`, so 3 s or more is expected and not a bug). `check_introspection_incomplete_cleanup` and `check_introspection_temp_file_leak` also fired on this tool, with no evidence attached.
- Campaigns and executions: e2-0922 1 exec / 0 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'paper_id': ''}` (twice) -> output `None`; logged `HTTP error while fetching paper: Client error '400 Bad Request' for url 'https://export.arxiv.org/api/query?id_list=&max_results=1'\nFor more information check: ...`
  - `{'paper_id': 'null'}` -> same record with `id_list=null`
- Hand-check hints: weak. The ToFu alert itself is a false positive: the newline is httpx's `HTTPStatusError` template and no input contained CR/LF. The gpt41-corpus VM log for this tool (13 hits) shows only that same message. The raw-`paper_id` logging at lines 307/312 is real in the code, but reaching it needs arXiv to return 200 with a PDF link for a CR/LF-bearing ID. Most likely arXiv returns 400 instead. I could not verify this because arxiv.org is blocked here. I recommend filing only as a hygiene note, combined with the other two arxiv drafts. The tool is registered with `task=True` (FastMCP background tasks). I assumed a plain `call_tool` still runs it synchronously, but did not verify that. The reproduction above was derived from the code and has not been run.
</details>
