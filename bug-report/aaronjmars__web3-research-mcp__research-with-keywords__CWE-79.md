# Missing output encoding in `research-with-keywords`: `tokenName` and `keywords` are echoed raw in the result text

**Repository:** `aaronjmars/web3-research-mcp` · **Tool:** `research-with-keywords` · **Tested commit:** `e454995`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`research-with-keywords` runs one web search per keyword, stores the combined results as a resource, and returns a summary. The summary interpolates the raw `tokenName` (twice, once inside the resource ID) and the joined `keywords`. Markup or template syntax in these arguments comes back unescaped. This matters for clients that render tool output as HTML or Markdown.

## Details
`src/tools/researchTools.ts:175-217` at `e454995`:

```ts
    async ({ tokenName, tokenTicker, keywords }) => {
      ...
        for (const keyword of keywords) {
          const query = `${tokenName} ${tokenTicker} ${keyword}`;
          ...
        }

        const resourceId = `combined_search_${tokenName.toLowerCase()}_${new Date().getTime()}`;
        ...
              text: `Completed searches for ${tokenName} with keywords: ${keywords.join(
                ", "
              )}\n\nResults saved as resource: research://resource/${resourceId}\n\nHighlights:\n${Object.entries(
```

`tokenName`, `tokenTicker` and each keyword are plain `z.string()` values with no length or character limit. None of them is escaped before the summary is built. Because the resource ID is built from the raw `tokenName`, the returned `research://resource/...` URI can also contain arbitrary characters, including `/`, which may stop it from matching the `research://resource/{id}` template.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. With an empty `keywords` list the tool makes no network requests and needs no API keys.
2. Install and start the server:
   ```
   git clone https://github.com/aaronjmars/web3-research-mcp.git
   cd web3-research-mcp && git checkout e454995982dae9e47ba38fd8e01ffd23c70cff67
   npm install && npm run build
   node dist/server.js
   ```
3. Call the tool with these arguments:
   ```json
   {"tokenName": "<b>tofu-poc</b>{{7*7}}", "tokenTicker": "TOFU", "keywords": []}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/server.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("research-with-keywords", {"tokenName": "<b>tofu-poc</b>{{7*7}}", "tokenTicker": "TOFU", "keywords": []})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `Completed searches for <b>tofu-poc</b>{{7*7}} with keywords:` and the resource line reads `research://resource/combined_search_<b>tofu-poc</b>{{7*7}}_<timestamp>`.

## Expected behavior
`tokenName` and the keywords should be escaped for the output context and capped in length. The resource ID should be built from a sanitized slug (for example `[a-z0-9_-]` only) rather than the raw name.

## Actual behavior
The arguments are reflected verbatim. From the fuzzing run (control bytes shown as `\x..`):

```
Completed searches for "{enN"- maTNe en\x04\x00\x00\x00\x00\x00\x00\x00Na"{{"enN"{ with keywords: 

Results saved as resource: research://resource/combined_search_"{enn"- matne en\x04\x00\x00\x00\x00\x00\x00\x00na"{{"enn"{_1790376581289

Highlights:
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in scraped content can steer them. The summary then carries caller-chosen markup into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low.

## Suggested fix
Escape `tokenName` and each keyword before building the summary (replace `&`, `<`, `>`, `"`, backticks and Markdown brackets) and cap their length. Build `resourceId` from a slug, for example `tokenName.toLowerCase().replace(/[^a-z0-9_-]+/g, "-").slice(0, 40)`. A shared escape helper would also cover `coingecko-search`, `defillama-search`, `create-research-plan` and `search`.

## Status on the default branch
Still present at `ff5dbb1` (2026-10-01). `src/` is identical at the tested commit and at HEAD. The commits since change only `.github/workflows/publish.yml`, `package.json` and `package-lock.json`.

## Prior reports
- No related issue or PR among all 3 issues and 61 pull requests (fetched 2026-10-01). The security-labelled PRs (#42, #44, #50) only bump dependencies.
- Documentation: .github/SECURITY.md: "Please don't open a public issue for a security problem." (asks for GitHub Private Vulnerability Reporting; send this there rather than as a public issue)
- Documentation: .github/SECURITY.md: out of scope lists "Vulnerabilities in the upstream data sources, the MCP client, or the LLM" (the maintainer may treat HTML rendering of tool text as a client issue; the in-scope list does name "injection in the server or CLI")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. `check_invalid_json` also fired (a "silent bug" alert because the JSON-shaped input was accepted); that is not a security finding.
- Campaigns and executions: repo24-b 109,568 exec / 103,328 ok (4,200 s).
- Evidence (verbatim, trimmed): `{'tokenName': '"{enN"- maTNe en\x04\x00\x00\x00\x00\x00\x00\x00Na"{{"enN"{', 'tokenTicker': '', 'keywords': []}` -> `Completed searches for "{enN"- maTNe en\x04...Na"{{"enN"{ with keywords: \n\nResults saved as resource: research://resource/combined_search_"{enn"- matne en\x04...na"{{"enn"{_1790376581289\n\nHighlights:\n`. Two more rows with a 56-char run of `{` gave the same shape.
- Hand-check hints: weak. Only `{{` and control bytes were reflected in a logged run, into plain MCP text content. The `<b>` reproduction is derived from the code at `researchTools.ts:215-217`, not from a logged run. With non-empty `keywords` the tool calls DuckDuckGo via `performSearch` and also echoes third-party result titles and URLs; that path was not analysed. The resource-ID point is a functional side note, not verified by running. `.github/SECURITY.md` asks for private reporting and does not list output encoding in scope; consider a normal hardening issue, or bundle with the other three web3-research-mcp drafts.
</details>
