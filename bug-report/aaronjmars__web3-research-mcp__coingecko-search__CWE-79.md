# Missing output encoding in `coingecko-search`: the `query` is echoed raw in the result text

**Repository:** `aaronjmars/web3-research-mcp` · **Tool:** `coingecko-search` · **Tested commit:** `e454995`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`coingecko-search` looks up candidate CoinGecko coin IDs for a free-text query. The tool interpolates the raw `query` into its result text in both the "no matches" and the "matches" branch. Markup or template syntax in the query comes back unescaped. This matters for clients that render tool output as HTML or Markdown.

## Details
`src/tools/coinGeckoTool.ts:454-488` at `e454995`:

```ts
    async ({ query }) => {
      ...
        const data = (await cgFetch(
          `/search?query=${encodeURIComponent(query)}`
        )) as CoinGeckoSearchResponse;
        const coins = (data.coins ?? []).slice(0, 10);
        if (coins.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No CoinGecko matches for "${query}"`,
        ...
              text: `CoinGecko matches for "${query}":\n\n${lines.join(
```

The query is URL-encoded for the upstream request, which is correct. It is not encoded for the output. The input schema is `z.string()` with no length or character limit.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later, and outbound HTTPS access to `api.coingecko.com`. No API key is needed (`COINGECKO_API_KEY` is optional).
2. Install and start the server:
   ```
   git clone https://github.com/aaronjmars/web3-research-mcp.git
   cd web3-research-mcp && git checkout e454995982dae9e47ba38fd8e01ffd23c70cff67
   npm install && npm run build
   node dist/server.js
   ```
3. Call the tool with these arguments:
   ```json
   {"query": "<b>tofu-poc</b>{{7*7}}"}
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
               result = await session.call_tool("coingecko-search", {"query": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `No CoinGecko matches for "<b>tofu-poc</b>{{7*7}}"`, with the markup unchanged. If CoinGecko returns any coins for the query, the first line `CoinGecko matches for "<b>tofu-poc</b>{{7*7}}":` shows the same reflection. A 429 from CoinGecko produces a fixed error instead; wait a minute and retry.

## Expected behavior
The query should be escaped for the output context (or at least have Markdown/HTML metacharacters neutralized) and capped in length before it is quoted back.

## Actual behavior
The query is reflected verbatim. From the fuzzing runs:

```
{'content': [{'type': 'text', 'text': 'No CoinGecko matches for "${7*7}"'}]}
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in scraped content can steer them. The tool result then carries caller-chosen markup into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low. The same raw query is also stored in the `research://logs` resource via `addLogEntry`.

## Suggested fix
Escape the query before quoting it back, for example with a small helper that replaces `&`, `<`, `>`, `"`, backticks and Markdown link brackets, and truncate it to a reasonable length. The same helper fits the other tools that echo caller text (`defillama-search`, `create-research-plan`, `research-with-keywords`, `search`).

## Status on the default branch
Still present at `ff5dbb1` (2026-10-01). `src/` is identical at the tested commit and at HEAD. The commits since change only `.github/workflows/publish.yml`, `package.json` and `package-lock.json`.

## Prior reports
- No related issue or PR among all 3 issues and 61 pull requests (fetched 2026-10-01). The security-labelled PRs (#42, #44, #50) only bump dependencies.
- Documentation: .github/SECURITY.md: "Please don't open a public issue for a security problem." (asks for GitHub Private Vulnerability Reporting; send this there rather than as a public issue)
- Documentation: .github/SECURITY.md: out of scope lists "Vulnerabilities in the upstream data sources, the MCP client, or the LLM" (the maintainer may treat HTML rendering of tool text as a client issue; the in-scope list does name "injection in the server or CLI")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. `check_resource_exhaustion` also fired for this tool according to `triggered`; not analysed here.
- Campaigns and executions: corpus-sbx 512 exec / 92 ok (60 s); repo24-b 51,712 / 10,504 and 61,440 / 14,394 (4,200 s each). The low success rate is likely CoinGecko rate limiting (429), not checked.
- Evidence (verbatim, trimmed): `{'query': '${7*7}'}` -> `{'content': [{'type': 'text', 'text': 'No CoinGecko matches for "${7*7}"'}]}`; `{'query': '${7*7n}'}` -> same shape; `{'query': '"qu{"query${7*,z\x7f\x7f'}` -> `No CoinGecko matches for ""qu{"query${7*,z\x7f\x7f"`.
- Hand-check hints: weak. Only `${` was reflected, into plain MCP text content. `${...}` is not evaluated by the server (it is data, not a JS template). The `<b>` reproduction is derived from the code at `coinGeckoTool.ts:469`, not from a logged run, and depends on CoinGecko returning no coins or any coins (both branches echo). `.github/SECURITY.md` asks for private vulnerability reporting and does not list output encoding in scope; this is probably best filed as a normal hardening issue, or bundled with the other three web3-research-mcp drafts.
</details>
