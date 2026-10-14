# Missing output encoding in `create-research-plan`: `tokenName` and `tokenTicker` are echoed raw, including HTML tags

**Repository:** `aaronjmars/web3-research-mcp` · **Tool:** `create-research-plan` · **Tested commit:** `e454995`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create-research-plan` stores a fixed research plan and returns it as text. The first line of the result interpolates the raw `tokenName` and `tokenTicker`. Markup such as `<script>` tags passes through unchanged. The tool needs no network access, so the reflection is fully deterministic.

## Details
`src/tools/researchTools.ts:83-162` at `e454995`:

```ts
  server.registerTool(
    "create-research-plan",
    {
      inputSchema: {
        tokenName: z.string().describe("Token name"),
        tokenTicker: z.string().describe("Token ticker symbol"),
      },
    },
    async ({ tokenName, tokenTicker }) => {
      ...
            text: `Created research plan for ${tokenName} (${tokenTicker}):\n\n${JSON.stringify(
              researchPlan,
```

Both arguments are plain `z.string()` with no length or character limit, and nothing escapes them before line 155 builds the result. The same values also go into the `research://logs` resource through `storage.addLogEntry` (line 92).

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No API keys and no network access are needed for this tool.
2. Install and start the server:
   ```
   git clone https://github.com/aaronjmars/web3-research-mcp.git
   cd web3-research-mcp && git checkout e454995982dae9e47ba38fd8e01ffd23c70cff67
   npm install && npm run build
   node dist/server.js
   ```
3. Call the tool with these arguments:
   ```json
   {"tokenName": "<b>tofu-poc</b>{{7*7}}", "tokenTicker": "<i>TOFU</i>"}
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
               result = await session.call_tool("create-research-plan", {"tokenName": "<b>tofu-poc</b>{{7*7}}", "tokenTicker": "<i>TOFU</i>"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `Created research plan for <b>tofu-poc</b>{{7*7}} (<i>TOFU</i>):`, with both values unchanged.

## Expected behavior
The token name and ticker should be escaped for the output context and capped in length before being quoted back. A ticker could also be restricted to a short alphanumeric pattern.

## Actual behavior
Both values are reflected verbatim. From the fuzzing run (tokenName `<script>alert('xss')</script>`; the ticker value is omitted here):

```
Created research plan for <script>alert('xss')</script> (<ticker>):

{
  "projectInfo": {
    "description": "Gather basic information about the project",
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in scraped content can steer them. The result then carries caller-chosen HTML into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low.

## Suggested fix
Escape `tokenName` and `tokenTicker` before interpolating them (replace `&`, `<`, `>`, `"`, backticks and Markdown brackets) and cap their length. Consider validating `tokenTicker` with something like `z.string().regex(/^[A-Za-z0-9.\-]{1,20}$/)`. A shared escape helper would also cover `coingecko-search`, `defillama-search`, `research-with-keywords` and `search`, which echo caller text the same way.

## Status on the default branch
Still present at `ff5dbb1` (2026-10-01). `src/` is identical at the tested commit and at HEAD. The commits since change only `.github/workflows/publish.yml`, `package.json` and `package-lock.json`.

## Prior reports
- No related issue or PR among all 3 issues and 61 pull requests (fetched 2026-10-01). The security-labelled PRs (#42, #44, #50) only bump dependencies.
- Documentation: .github/SECURITY.md: "Please don't open a public issue for a security problem." (asks for GitHub Private Vulnerability Reporting; send this there rather than as a public issue)
- Documentation: .github/SECURITY.md: out of scope lists "Vulnerabilities in the upstream data sources, the MCP client, or the LLM" (the maintainer may treat HTML rendering of tool text as a client issue; the in-scope list does name "injection in the server or CLI")

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 3,072 exec / 3,072 ok (60 s); repo24-b 327,168 / 327,168 (4,200 s).
- Evidence (verbatim, trimmed): `{'tokenName': "<script>alert('xss')</script>", 'tokenTicker': <a traversal-style string>}` -> `Created research plan for <script>alert(\'xss\')</script> (<same string>):\n\n{\n  "projectInfo": ...` (tokens `<script`, `</script>` flagged). Also `{'tokenName': '{{{{{{{{{{{{{{{{{', 'tokenTicker': ''}` -> `Created research plan for {{{{{{{{{{{{{{{{{ ():...` and `{'tokenName': '"#"{{', ...}` -> `Created research plan for "#"{{ ():...`.
- Hand-check hints: weak, though the strongest of the four web3-research-mcp drafts. A logged run shows an actual `<script>` tag reflected unescaped, not just `{{`. The sink is still plain MCP text content, so exploitability depends on the client rendering it. `.github/SECURITY.md` asks for private vulnerability reporting and does not list output encoding in scope; this may be better filed as a normal hardening issue, or bundled with the other three web3-research-mcp drafts.
</details>
