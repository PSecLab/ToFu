# Missing output encoding in `docs_search_docs`: `query` is echoed verbatim in the result text

**Repository:** `ruan11223344/McpDocServer` · **Tool:** `docs_search_docs` · **Tested commit:** `8d82594`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`docs_search_docs` searches the locally crawled documentation and returns a JSON string as a text block. The caller's `query` is copied into that JSON twice, in the `query` field and inside the "no results" message, with no escaping of markup or template characters. The output is plain JSON text, so this only matters if a client renders tool output as HTML or Markdown. This is a low-severity hardening note.

## Details
`server.js:518-536` at `8d82594`:

```js
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            success: true,
            query: query,
            source: source || "all",
            resultsCount: results.length,
            results: results.length > 0 ? results : [
              {
                id: "no-results",
                title: "没有找到匹配结果",
                content: `未找到与 '${query}' 中所有关键词匹配的内容`,
```

`JSON.stringify` escapes quotes and control characters but leaves `<`, `>`, `{{` and `${` as-is. The template literal at line 530 only interpolates the value; it does not evaluate `${` sequences inside `query`, so there is no template injection on the server. The error branch (`server.js:541-555`) also echoes `query` together with `error.stack`, `process.cwd()` and the script directory.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and npm. No crawled docs are needed: no `docs/` folder is checked in, and without one the tool falls back to built-in example data (`server.js:422-439`).
2. Install and start as the README describes:

   ```bash
   git clone https://github.com/ruan11223344/McpDocServer.git
   cd McpDocServer && git checkout 8d82594
   npm install
   ```
3. Call the tool from the repository root with:

   ```json
   {"query": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["server.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("docs_search_docs", {"query": "<b>tofu-poc</b>"})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe: the text contains `"query": "<b>tofu-poc</b>"` and `未找到与 '<b>tofu-poc</b>' 中所有关键词匹配的内容`, with the markup unchanged.

## Expected behavior
If the result is meant to be displayed, user-supplied text is HTML-escaped (`<` as `\u003c` or `&lt;`), or the tool returns only data that the client is expected to escape, without repeating the query inside a human-readable message.

## Actual behavior
The query is echoed unchanged. From the fuzzing run:

```
input:  {"query": "q3ee{{A", "source": "", "limit": 0.0}
output: {"success": true, "query": "q3ee{{A", "source": "all", "resultsCount": 0,
         "results": [{"id": "no-results", "title": "没有找到匹配结果", "content": "未找到与 'q3ee{{A' 中所有关键词匹配的内容", ...}]}
```

## Impact
In MCP the LLM chooses `query`, and prompt injection from untrusted content could put markup in it. The value comes back to the same LLM as plain JSON text, so in most clients nothing is rendered. Only a client that renders tool output as HTML without escaping would be affected, and then only with content the caller supplied. Low severity.

## Suggested fix
- Drop the query from the "no results" message, or return `resultsCount: 0` and an empty `results` array instead of a synthetic entry.
- If the output is meant for display, escape `<`, `>` and `&` before returning it (for example `JSON.stringify(obj).replace(/</g, "\\u003c").replace(/>/g, "\\u003e")`).
- In the error branch, stop returning `error.stack`, `cwd` and `scriptDir` to the caller; log them to stderr instead.

## Status on the default branch
Still present at `8d82594` (2025-03-31). The default branch head is the tested commit.

## Prior reports
None found. Searched all 0 issues and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. The only PR is a third-party scan badge reporting no findings. README.md and README_EN.md say nothing about output encoding or untrusted input.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` (only sanitizer listed for this tool).
- Campaigns and executions: corpus-sbx 3584 exec / 3071 ok (60 s); e2-0922 2048 exec / 1904 ok (300 s).
- Evidence (verbatim, trimmed):
  - `{'query': 'q3ee{{A', 'source': '', 'limit': 0.0}` -> `query` and no-results `content` echo `q3ee{{A`.
  - `{'query': '\x000d0{{d', 'source': '', 'limit': 0.0}` -> echoed as `\u00000d0{{d`.
  - `{'query': '2${', 'source': '', 'limit': 0.0}` -> echoed as `2${`.
- Hand-check hints: weak. The only tokens ToFu saw echoed were template braces (`{{`, `${`), not HTML, and they land in a JSON string inside a plain-text MCP content block. Nothing on the server evaluates them. The `<b>` payload in the repro is derived from code reading (JSON.stringify does not escape `<`), not from the logs, and was not executed. The info leak in the error branch (`error.stack`, `cwd`, `__dirname`) is verified in code and is arguably more useful to report than the echo, but it was not triggered in the logged runs. Side note: `server.js:395` also logs `query` raw to stderr via `log()`.
</details>
