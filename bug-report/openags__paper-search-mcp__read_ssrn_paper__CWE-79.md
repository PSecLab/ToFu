# Missing output encoding in `read_ssrn_paper`: an invalid `paper_id` is echoed verbatim in the error text

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_ssrn_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`read_ssrn_paper` calls `SSRNSearcher.download_pdf`, which returns `Invalid SSRN paper id: <paper_id>` for unrecognized IDs, and passes that string straight back as the tool result. Markup, template braces and control characters such as NUL and ESC come back unchanged. The result is plain text, so this only matters for MCP clients that render tool output as HTML/Markdown or print it raw to a terminal. Low severity.

## Details
`paper_search_mcp/server.py:1241-1253` returns `SSRNSearcher.read_paper(...)`. `paper_search_mcp/academic_platforms/ssrn.py:166-168` returns the `download_pdf` message when it is not a `.pdf` path, and `ssrn.py:120-122` builds it:

```python
abstract_id = self._extract_abstract_id(paper_id)
if not abstract_id:
    return f"Invalid SSRN paper id: {paper_id}"
...
pdf_path = self.download_pdf(paper_id, save_path)
if not pdf_path.endswith(".pdf"):
    return pdf_path
```

`paper_id` is interpolated without escaping or removing control characters.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No network or API key is needed: the invalid-ID path returns before any request.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with harmless markup and an ESC byte:

   ```json
   {"paper_id": "<b>tofu-poc</b>{{7*7}}\u001b[1mTOFU", "save_path": ""}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "paper_search_mcp.server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("read_ssrn_paper",
                   {"paper_id": "<b>tofu-poc</b>{{7*7}}\x1b[1mTOFU", "save_path": ""})
               print(repr(result.content[0].text))

   asyncio.run(main())
   ```
4. Observe that the result is `Invalid SSRN paper id: <b>tofu-poc</b>{{7*7}}\x1b[1mTOFU`, unchanged.

## Expected behavior
Error messages either omit the rejected value or include a neutralized form, for example `repr()` of a truncated value.

## Actual behavior
The input is reflected unchanged. From the fuzzing run:

```
{'paper_id': '\x00{{{{{{{{{{{{', 'save_path': ''}
-> Invalid SSRN paper id: \x00{{{{{{{{{{{{
```

## Impact
`paper_id` is chosen by the LLM and can be steered by prompt injection, but the reflection only goes back to the same client. Harm needs a client that renders tool results as HTML/Markdown without sanitizing, or writes them raw to a terminal. No server-side effect. Severity: low.

## Suggested fix
Return a fixed `Invalid SSRN paper id` message, or include `repr(paper_id[:100])`. Fixing `download_pdf` covers both `read_ssrn_paper` and `download_ssrn`.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `ssrn.py` is unchanged.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/116); only `check_reflected_output`.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; repo24 176640 / 176640 (4200 s).
- Evidence (verbatim, trimmed):
  - `{'paper_id': '\x00{{{{{{{{{{{{', 'save_path': ''}` -> `Invalid SSRN paper id: \x00{{{{{{{{{{{{`
  - `{'paper_id': '{{{{{"paper_=d": "12367AAAAAAAAAAAAAAAA890123456ave_\x11path": e_path": "ds', 'save_path': ''}` -> echoed unchanged after `Invalid SSRN paper id: `
  - `{'paper_id': '{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{\x00\x00{{', 'save_path': ''}` -> echoed unchanged
- Hand-check hints: weak. Only `{{` template braces were flagged, into a plain-text error; there is no HTML rendering in this server. Same root cause as the `download_ssrn` draft; file at most once, ideally as a line in a hardening issue.
</details>
