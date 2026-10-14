# Missing output encoding in `search-google-web`: `keyword` is echoed raw into the no-results reply

**Repository:** `adityak74/mcp-scholarly` · **Tool:** `search-google-web` · **Tested commit:** `c2d69ee`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`search-google-web` runs a Google web search via the SerpBase API and formats the results. When a search returns nothing, it builds the reply `f"No results for {keyword}."`, inserting the caller's `keyword` with no encoding. The successful path also inserts `keyword` into a header line. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity. The tool is registered unconditionally (`src/mcp_scholarly/server.py:40`); without `SERPBASE_API_KEY` the search returns no results, so the echoing `No results for ...` path is the one every call takes.

## Details
`src/mcp_scholarly/server.py:48-55` at the tested commit:

```python
def search_google_web(keyword: str) -> str:
    if not keyword:
        raise ValueError("Missing keyword")
    serpbase = SerpBaseSearch()
    results = serpbase.search(keyword)
    if not results:
        return f"No results for {keyword}."
    return f"Search articles for {keyword}:\n" + "\n\n\n".join(results)
```

`keyword` is used unencoded on both branches. The result titles/snippets from SerpBase are also joined in without encoding, so upstream content would pass through too.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`. No API key is needed: without `SERPBASE_API_KEY` the tool is still registered and the search returns no results, which takes the echoing path.
2. Install and start as the README describes: `uvx mcp-scholarly` (or `uv --directory <path> run mcp-scholarly`).
3. Call the tool with:

   ```json
   {"keyword": "<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx", args=["mcp-scholarly"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("search-google-web",
                   {"keyword": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the reply `No results for <img src=x onerror=alert(1)>.`, with the markup unchanged.

## Expected behavior
`keyword` is escaped before being placed in the reply, or the no-results message does not repeat the raw query.

## Actual behavior
The value is returned verbatim. From the fuzzing run:

```
No results for ;{{;".
No results for ;{{;{.
No results for ;{{;{{;{{.
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. The reply returns to the same client. In a client that renders tool output as HTML or Markdown, injected markup in `keyword` would render in the user's view. In a plain-text client there is no effect. The tool reads no local files; it makes an outbound request to the SerpBase API with the keyword as the query (its intended function).

## Suggested fix
Escape HTML/Markdown special characters in `keyword` before interpolating it, or drop the raw query from the no-results message. Apply the same encoding to result titles and snippets taken from the API before returning them.

## Status on the default branch
Still present at `c2d69ee` (2026-08-24/25). This is the tested commit and the current default-branch head; `search_google_web` is unchanged.

## Prior reports
- No issue or PR reports the unescaped echo. Searched all 6 issues and 11 pull requests (fetched 2026-10-01); none mentions escaping, XSS or output encoding.
- #17 "feat: add SerpBase (Google) search engine via REST API" (PR, closed 2026-08-25; its code is on the default branch): introduced `search-google-web` and its `No results for {keyword}.` reply; no encoding was added. Its body also says the tool "is registered unconditionally but degrades to "No results" without a key", which matches `server.py` on the default branch (no condition on `@mcp.tool`; `SerpBaseSearch.search` returns `[]` when no key is set). So the echo is reachable without `SERPBASE_API_KEY` (the Summary and steps above reflect this).
- #8 "Add MseeP.ai badge to README" and #10 "Add MseeP.ai badge" (PRs, closed 2025-05-05 and 2026-05-28): third-party badge PRs reporting an automated scan score of 100/100 with no findings listed; not related to this echo.
- Documentation: README.md: "Optional; only registered when `SERPBASE_API_KEY` is set." (contradicts the unconditional registration in `server.py`; no security notes).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx`, 2,048 executions, 1,171 successful, 60 s budget.
- Evidence (verbatim, trimmed): `{'keyword': ';{{;"'}` -> `No results for ;{{;".`; `{'keyword': ';{{;{'}` -> `No results for ;{{;{.`; `{'keyword': ';{{;{{;{{'}` -> `No results for ;{{;{{;{{.`. Token matched: `{{`.
- Hand-check hints: weak. Clean reflection of the caller's query into an MCP `text` reply; no `<`/`>` in evidence but the code does no encoding (plain f-string), so markup would pass through. The tool is registered without a key, and with no key every query returns no results, which is the echoing path the fuzzer hit. Exploitable only in a client that renders tool output as HTML/Markdown. Low severity.
</details>
