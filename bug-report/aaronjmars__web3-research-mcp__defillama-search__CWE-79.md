# Missing output encoding in `defillama-search`: the `query` is echoed raw in the result text

**Repository:** `aaronjmars/web3-research-mcp` · **Tool:** `defillama-search` · **Tested commit:** `e454995`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`defillama-search` scores the cached DeFiLlama protocol list against a free-text query and returns candidate slugs. The raw `query` is interpolated into the result text in both the "no matches" and the "matches" branch. Markup or template syntax in the query comes back unescaped. This matters for clients that render tool output as HTML or Markdown.

## Details
`src/tools/defiLlamaTool.ts:573-628` at `e454995`:

```ts
    async ({ query }) => {
      storage.addLogEntry(`DeFiLlama search: "${query}"`);

      try {
        const protocols = await getProtocols();
        const q = query.trim().toLowerCase();
        ...
        if (scored.length === 0) {
          return {
            content: [
              {
                type: "text",
                text: `No DeFiLlama matches for "${query}"`,
        ...
              text: `DeFiLlama matches for "${query}":\n\n${lines.join(
```

The query is only used for local string matching against `/protocols`, so it never leaves the process. It is not encoded for the output, and the input schema is `z.string()` with no length or character limit.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later, and outbound HTTPS access to `api.llama.fi` (the tool downloads the protocol list once). No API key is needed.
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
               result = await session.call_tool("defillama-search", {"query": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `No DeFiLlama matches for "<b>tofu-poc</b>{{7*7}}"`, with the markup unchanged.

## Expected behavior
The query should be escaped for the output context (or at least have Markdown/HTML metacharacters neutralized) and capped in length before it is quoted back.

## Actual behavior
The query is reflected verbatim. From the fuzzing runs:

```
{'content': [{'type': 'text', 'text': 'No DeFiLlama matches for "${7*7}"'}]}
{'content': [{'type': 'text', 'text': 'No DeFiLlama matches for ""query": "${8*"'}]}
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in scraped content can steer them. The tool result then carries caller-chosen markup into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low.

## Suggested fix
Escape the query before quoting it back (replace `&`, `<`, `>`, `"`, backticks and Markdown brackets) and truncate it to a reasonable length. A shared helper would also cover `coingecko-search`, `create-research-plan`, `research-with-keywords` and `search`, which echo caller text the same way.

## Status on the default branch
Still present at `ff5dbb1` (2026-10-01). `src/` is identical at the tested commit and at HEAD. The commits since change only `.github/workflows/publish.yml`, `package.json` and `package-lock.json`.

## Prior reports
- No related issue or PR among all 3 issues and 61 pull requests (fetched 2026-10-01). The security-labelled PRs (#42, #44, #50) only bump dependencies.
- Documentation: .github/SECURITY.md: "Please don't open a public issue for a security problem." (asks for GitHub Private Vulnerability Reporting; send this there rather than as a public issue)
- Documentation: .github/SECURITY.md: out of scope lists "Vulnerabilities in the upstream data sources, the MCP client, or the LLM" (the maintainer may treat HTML rendering of tool text as a client issue; the in-scope list does name "injection in the server or CLI")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 1,024 exec / 1,022 ok (60 s); repo24-b 161,792 / 161,787 and 251,904 / 251,902 (4,200 s each).
- Evidence (verbatim, trimmed): `{'query': '${7*7}'}` -> `{'content': [{'type': 'text', 'text': 'No DeFiLlama matches for "${7*7}"'}]}`; `{'query': '${8*7}'}` -> same shape; `{'query': '"query": "${8*'}` -> `No DeFiLlama matches for ""query": "${8*"`.
- Hand-check hints: weak. Only `${` was reflected, into plain MCP text content. `${...}` is not evaluated by the server. The `<b>` reproduction is derived from the code at `defiLlamaTool.ts:609`, not from a logged run; a query with `<b>` is very unlikely to match any protocol name or symbol, so the "no matches" branch is the expected one. `.github/SECURITY.md` asks for private vulnerability reporting and does not list output encoding in scope; consider filing as a normal hardening issue, or bundling with the other three web3-research-mcp drafts.
</details>
