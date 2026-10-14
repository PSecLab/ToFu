# Missing output encoding in `pinterest_search`: `keyword` is echoed unescaped into the tool result

**Repository:** `terryso/mcp-pinterest` · **Tool:** `pinterest_search` · **Tested commit:** `b2b1b39`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`pinterest_search` searches Pinterest for a keyword and returns the matching image titles and links as text. The caller's `keyword` is placed verbatim into the first line of the result, and the scraped titles and links are placed verbatim after it. Nothing is escaped, so HTML or Markdown in the keyword reaches any client that renders tool output. In a plain-text client this is harmless; in a client that renders Markdown or HTML it is a reflected injection.

## Details
`pinterest-mcp-server.ts` (tested commit). The keyword is only trimmed (line 294), then echoed at lines 442-447:

```ts
          if ('keyword' in args && typeof args.keyword === 'string') {
            keyword = args.keyword.trim();
// ...
      const contentItems = [
        {
          type: 'text',
          text: `Found ${validResults.length} images related to "${keyword}" on Pinterest`
        }
      ];
```

The search itself URL-encodes the keyword (`pinterest-scraper.js:94`), so the request is fine; only the output is unencoded. Lines 450-468 add `result.title`, `result.image_url` and `result.link` from the scraped page the same way.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No accounts or env vars. Chrome is optional: without it the search returns 0 results immediately, which is enough to see the echo.
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/terryso/mcp-pinterest.git
   cd mcp-pinterest && npm install && npm run build
   # server entry point: node dist/pinterest-mcp-server.js
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
       server = StdioServerParameters(command="node", args=["dist/pinterest-mcp-server.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("pinterest_search",
                   {"keyword": "<img src=x onerror=alert(1)> **tofu-poc**", "limit": 1, "headless": True})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the first text item is `Found 0 images related to "<img src=x onerror=alert(1)> **tofu-poc**" on Pinterest`, with the markup unchanged.

## Expected behavior
Caller input and scraped page content are escaped (or clearly delimited, e.g. in a code span) before they are placed into text that a client may render.

## Actual behavior
The keyword is reflected byte for byte. From the fuzzing run:

```
Found 0 images related to ""keyword": "test; rm -rf6\x00\x00\x00\x00\x00\x00\x00 /", "limit": 10, "headless": fals{{{{{" on Pinterest
```

(The fuzzer input was a malformed JSON fragment; quotes, NUL bytes and `{{` all came back unchanged.)

## Impact
Low. MCP tool results are usually treated as plain text, and the keyword is chosen by the LLM, so the main risk is a client that renders tool output as Markdown or HTML: then a keyword steered by prompt injection, or a Pinterest pin title, can inject links, images or markup into the user's view. There is no server-side effect.

## Suggested fix
- Escape `<`, `>`, `&` and Markdown control characters in `keyword` before building the message, or wrap it in a code span.
- Apply the same encoding to `result.title`, `result.image_url` and `result.link` (lines 450-468), which come from third-party pages.
- Optionally return the keyword and results as structured JSON fields instead of interpolated prose.

## Status on the default branch
Still present at `b2b1b39` (2025-07-02). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 3 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only. The token it matched was `{{`, not HTML.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok (60 s budget).
- Evidence (verbatim, trimmed), corpus-sbx:
  - `{'keyword': '"keyword": "test; rm -rf6\x00\x00\x00\x00\x00\x00\x00 /", "limit": 10, "headless": fals{{{{{', 'limit': 0, 'headless': False}` -> `Found 0 images related to ""keyword": "test; rm -rf6\x00... "headless": fals{{{{{" on Pinterest`
  - `{'keyword': '"keyword": "test; rm -rf6\x00\x00\x00\x00\x00\x00\x00 /", "limit": 10, "head*less": fals{{{{{', 'limit': 0, 'headless': False}` -> same shape
  - `{'keyword': '"keyword": "test; rm -rf6\x00\x00\x00\x00\x00it": 10, "head*less": fals{{{{{', 'limit': 0, 'headless': False}` -> same shape
- Hand-check hints: weak. Only `{{` was echoed, into a plain-text MCP `text` item; the HTML payload in the repro is ours, inferred from the code (line 445), not observed in a run. Real impact depends on a client rendering tool output. The scraped `title`/`link` echo (third-party content) is arguably the more relevant part. The "rm -rf" text in the evidence is just fuzzer junk inside a string; nothing was executed. Consider merging with the `pinterest_search_and_download` draft into one low-priority issue.
</details>
