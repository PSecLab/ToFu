# Missing output encoding in `reason_beam`: `query` is echoed raw into the tool reply

**Repository:** `AzDeltaQQ/Mcp-Reasoning-Server` · **Tool:** `reason_beam` · **Tested commit:** `7131e73`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`reason_beam` is the `/reason-beam` command wrapper. It builds three placeholder "thoughts" around the caller's `query` and returns them as JSON. The `query` is copied into the reply five times (as `originalPrompt`, twice in the first thought, once in each later thought) with no encoding. `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `&` alone, so markup comes back intact. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/tools/reasoning-wrapper.ts:77-91` at the tested commit (`dist/tools/reasoning-wrapper.js` is the same):

```ts
let currentThought = `Beam Search Reasoning (Step 1/${totalThoughts}): Initial analysis of the problem "${query}":\n\n` +
                     `Let me explore multiple approaches to this problem. ${query}\n\n` +
                     `[This would be the initial Beam Search-based reasoning]`;
...
  const nextThought = `Beam Search Reasoning (Step ${thoughtNumber}/${totalThoughts}): ` +
                     `Considering 3 alternative paths from "${currentThought.slice(0, 50)}...", ` +
                     `the most promising direction is...\n\n` +
                     `[This would be the next step of Beam Search reasoning for: ${query}]`;
```

The result is serialized at lines 107-114 with `originalPrompt: query` and `allThoughts`. `query` is `z.string()` (line 71) with no length or content check.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No credentials or network access are needed.
2. Install and build as the README describes: `git clone https://github.com/AzDeltaQQ/Mcp-Reasoning-Server.git && cd Mcp-Reasoning-Server && npm install && npm run build`. The server is `node dist/index.js`.
3. Call the tool with:

   ```json
   {"query": "<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("reason_beam", {"query": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `originalPrompt` and all three `allThoughts` entries. Each contains the markup exactly as sent.

## Expected behavior
Values copied from the arguments are encoded so they cannot be read as markup if the reply is rendered, or are not echoed back at all.

## Actual behavior
The query is returned verbatim, five times. From the fuzzing run (trimmed):

```
"originalPrompt": "e{{{{{",
"allThoughts": [
  "Beam Search Reasoning (Step 1/3): Initial analysis of the problem \"e{{{{{\":\n\nLet me explore multiple approaches to this problem. e{{{{{\n\n[This would be the initial Beam Search-based reasoning]",
  "... [This would be the next step of Beam Search reasoning for: e{{{{{]",
  "... [This would be the next step of Beam Search reasoning for: e{{{{{]"
],
```

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in content the model reads can steer them. The reply goes back to the same client. If that client renders tool results as HTML or Markdown, injected markup would render in the user's view. If the client shows tool output as plain text, which is the common case, there is no effect. The tool reads no files and makes no requests.

## Suggested fix
Do not repeat `query` in the reply, since the caller already has it. If it is kept, escape markup characters in the serialized JSON, for example `JSON.stringify(obj, null, 2).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")`. The result is still valid JSON and decodes to the same strings.

## Status on the default branch
Still present at `7131e73` (2025-03-19). This is the tested commit; the default branch has no later commits.

## Prior reports
None found. Searched the 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. Neither item is about output handling: #1 is a Glama Dockerfile request and #2 adds a listing badge.
- Documentation: README.md: "This is a simulated reasoning server" (Limitations section; says the tools return placeholder responses, nothing about encoding of echoed input)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx` 3,072 executions / 3,072 successful (60 s); `repo24-b` 267,776 / 267,776 (4,200 s).
- Evidence (verbatim, trimmed): `{'query': '111111111111111111111/{{{{{{{'}`, `{'query': 'e{{{{{'}`, `{'query': 'e{{{{{{{{{'}` -> each value appears unchanged in `originalPrompt` and in the three `allThoughts` strings. Token matched: `{{` only.
- Hand-check hints: weak. Stub tool; ToFu only saw `{{` reflected, which has no meaning in this output. That `<`/`>` survive is inferred from the code (`JSON.stringify` does not escape them), not from a log. Same pattern as the other seven flagged tools in this repo; file at most one combined issue.
</details>
