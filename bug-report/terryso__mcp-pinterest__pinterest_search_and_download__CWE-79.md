# Missing output encoding in `pinterest_search_and_download`: `keyword` is echoed unescaped into the tool result

**Repository:** `terryso/mcp-pinterest` · **Tool:** `pinterest_search_and_download` · **Tested commit:** `b2b1b39`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`pinterest_search_and_download` searches Pinterest for a keyword, downloads the images into the configured download directory and reports what it saved. The caller's `keyword` is placed verbatim into the first line of the result, and scraped titles, URLs and error messages follow unescaped. HTML or Markdown in the keyword therefore reaches any client that renders tool output. The keyword is sanitized correctly for the directory name, so this is an output-encoding issue only.

## Details
`pinterest-mcp-server.ts` (tested commit). The keyword is only trimmed (line 554). It is sanitized for the directory name (line 633) but echoed raw in the result (lines 674-678):

```ts
          if ('keyword' in args && typeof args.keyword === 'string') {
            keyword = args.keyword.trim();
// ...
      const keywordDir = path.join(downloadDir, keyword.replace(/\s+/g, '_').replace(/[^a-zA-Z0-9_一-龥]/g, ''));
// ...
      const contentItems = [
        {
          type: 'text',
          text: `搜索并下载了 ${validResults.length} 张与"${keyword}"相关的图片`
        },
```

Lines 686-737 add `validResults[index]?.title`, `result.url`, `result.path`, `failed.url` and `failed.error` the same way.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No accounts. Chrome is optional: without it the search returns 0 results immediately, which is enough to see the echo. The call creates one sub-directory named after the sanitized keyword inside the download directory, so point `MCP_PINTEREST_DOWNLOAD_DIR` at a temp dir.
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/terryso/mcp-pinterest.git
   cd mcp-pinterest && npm install && npm run build
   mkdir -p /tmp/tofu-pinterest
   # server entry point: MCP_PINTEREST_DOWNLOAD_DIR=/tmp/tofu-pinterest node dist/pinterest-mcp-server.js
   ```
3. Call the tool:
   ```json
   {"keyword": "<img src=x onerror=alert(1)> **tofu-poc**", "limit": 1, "headless": true}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/pinterest-mcp-server.js"],
                                      env={"MCP_PINTEREST_DOWNLOAD_DIR": "/tmp/tofu-pinterest"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("pinterest_search_and_download",
                   {"keyword": "<img src=x onerror=alert(1)> **tofu-poc**", "limit": 1, "headless": True})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the first text item is `搜索并下载了 0 张与"<img src=x onerror=alert(1)> **tofu-poc**"相关的图片`, with the markup unchanged. The directory created under `/tmp/tofu-pinterest` has a sanitized name (`img_srcx_onerroralert1_tofupoc`).

## Expected behavior
Caller input and scraped page content are escaped (or clearly delimited, e.g. in a code span) before they are placed into text that a client may render.

## Actual behavior
The keyword is reflected byte for byte. From the fuzzing run (input `"\x00{{"`):

```
搜索并下载了 0 张与"\x00{{"相关的图片
成功: 0, 失败: 0
```

## Impact
Low. MCP tool results are usually treated as plain text, and the keyword is chosen by the LLM, so the main risk is a client that renders tool output as Markdown or HTML: then a keyword steered by prompt injection, or a Pinterest pin title, can inject links, images or markup into the user's view. There is no server-side effect beyond the (correctly sanitized) download directory.

## Suggested fix
- Escape `<`, `>`, `&` and Markdown control characters in `keyword` before building the message, or wrap it in a code span.
- Apply the same encoding to the scraped `title`, `url`, `path` and `error` strings (lines 686-737).
- Optionally return the results as structured JSON fields instead of interpolated prose.

## Status on the default branch
Still present at `b2b1b39` (2025-07-02). The tested commit is the current head of the default branch.

## Prior reports
- Issues and pull requests: none related. Searched all 3 issues and 3 pull requests (fetched 2026-10-01); the only security-related item, PR #5, is a third-party dependency scan (axios advisories), not about output encoding.
- Documentation: `README.md`: "The server automatically sanitizes filenames by replacing illegal characters" (covers file and directory names only, consistent with the correct directory sanitizing noted above; nothing about escaping the text result).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only. The token it matched was `{{`, not HTML.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok (60 s budget).
- Evidence (verbatim, trimmed), corpus-sbx:
  - `{'keyword': '"\x00{{"\x7f\x7f\x7f", "l"\x7f\x7f\x7f"\x00\x00 , "dadless"', 'limit': 0, 'headless': False}` -> `搜索并下载了 0 张与""\x00{{"\x7f\x7f\x7f", "l"\x7f\x7f\x7f"\x00\x00 , "dadless""相关的图片` / `成功: 0, 失败: 0`
  - `{'keyword': '\x00{{', 'limit': 0, 'headless': False}` -> `搜索并下载了 0 张与"\x00{{"相关的图片` / `成功: 0, 失败: 0`
  - `{'keyword': '"keywor":\x009fite{{"', 'limit': 0, 'headless': False}` -> `搜索并下载了 0 张与""keywor":\x009fite{{""相关的图片` / `成功: 0, 失败: 0`
- Hand-check hints: weak. Only `{{` was echoed, into a plain-text MCP `text` item; the HTML payload in the repro is ours, inferred from the code (line 677), not observed in a run. The sanitized directory name in step 4 is computed by hand from the regex at line 633. The directory sanitizer looks correct (no traversal through `keyword`). Consider merging with the `pinterest_search` draft into one low-priority issue.
</details>
