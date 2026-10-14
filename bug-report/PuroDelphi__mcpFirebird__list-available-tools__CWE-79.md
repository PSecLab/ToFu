# Missing output encoding in `list-available-tools`: `category` is echoed raw into the reply header

**Repository:** `PuroDelphi/mcpFirebird` · **Tool:** `list-available-tools` · **Tested commit:** `0b0980f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`list-available-tools` lists the server's tools and accepts an optional `category` filter. Any `category` value, including unknown ones, is inserted unchanged into the first line of the reply. The reply is plain MCP text, so this only matters if a client renders tool output as Markdown or HTML. Low severity.

## Details
`src/tools/metadata.ts:94-137` (tested commit):

```ts
handler: async (args: { category?: string }) => {
    ...
    if (args.category) {
        if (args.category === 'database') { ... }
        else if (args.category === 'metadata') { ... }
    }
    ...
    return { content: [{ type: 'text',
        text: `Available tools${args.category ? ` (category: ${args.category})` : ''}:\n\n${formatForClaude(toolsInfo)}` }] };
}
```

`category` is `z.string().optional()`. Only `database` and `metadata` have a meaning; any other value falls through to the full list and is still echoed in the header.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No Firebird server is needed.
2. Install and build: `git clone https://github.com/PuroDelphi/mcpFirebird.git && cd mcpFirebird && git checkout 0b0980f && npm install && npm run build`
3. Call the tool with:

   ```json
   {"category": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["dist/cli.js", "--database", "/tmp/tofu-none.fdb"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("list-available-tools",
                   {"category": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply starting with `Available tools (category: <b>tofu-poc</b>):`.

## Expected behavior
`category` is limited to the known values (`z.enum(['database', 'metadata'])`), so unknown text is rejected and never echoed.

## Actual behavior
From the fuzzing run (trimmed):

```
Available tools (category: {{q):

[
  {
    "name": "execute-query",
    ...
```

## Impact
The LLM chooses `category`, and prompt injection can steer it. The echoed value goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity.

## Suggested fix
Change the schema to `category: z.enum(['database', 'metadata']).optional()`. That also gives clients a correct schema for the filter.

## Status on the default branch
Still present at `bf1b3bf` (2026-09-29). The handler starts at `src/tools/metadata.ts:95`. The only change in this file is a response-size wrapper added at the end of `setupMetadataTools`.

## Prior reports
None found. Searched all 25 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok (60 s); repo24-b 251904 / 251904 (4200 s); e2-0922 2048 / 2048 (300 s).
- Evidence (verbatim, trimmed):
  - `{'category': '{{q'}` -> `Available tools (category: {{q):\n\n[ ... full tool list ... ]`
  - `{'category': '{{qr'}` -> `Available tools (category: {{qr): ...`
  - `{'category': '{{{{{{{{{{{{{{{#yr\x7f\x7f\x7f\x7f\x7f\x7fm'}` -> echoed with the DEL bytes.
- Hand-check hints: weak. Only `{{` was echoed into a plain-text header. The echo is real (`metadata.ts:123`). The `<b>` payload is my substitution and was not run. The `z.enum` change is a cheap, clean fix, so this may be acceptable as a small hardening issue, not as an XSS report.
</details>
