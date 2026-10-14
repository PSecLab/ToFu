# Missing output encoding in `r1_reasoning`: `prompt` is echoed raw into the tool reply

**Repository:** `AzDeltaQQ/Mcp-Reasoning-Server` · **Tool:** `r1_reasoning` · **Tested commit:** `7131e73`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`r1_reasoning` is a placeholder tool that returns a canned "analysis" as JSON. It copies the caller's `prompt` into that JSON twice: once as `originalPrompt` and once (first 100 characters) inside the `reasoning` text. `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `&` alone, so markup such as `<script>` comes back intact. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/tools/reasoning-tools.ts:156-174` at the tested commit (`dist/tools/reasoning-tools.js` is the same):

```ts
const reasoning = `R1 Reasoning Analysis:\n\n` +
                  `For the prompt: "${prompt.slice(0, 100)}...", the analysis is:\n\n` +
                  `1. Initial problem parsing: [Simulated R1 analysis]\n` +
                  ...
return {
  content: [{
    type: "text",
    text: JSON.stringify({
      strategy: "r1_transformer",
      originalPrompt: prompt,
      reasoning: reasoning,
      complete: true
    }, null, 2)
  }]
};
```

`prompt` is `z.string()` (line 143) with only a non-empty check (lines 148-150). Nothing encodes it before it goes into the reply.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No credentials or network access are needed.
2. Install and build as the README describes: `git clone https://github.com/AzDeltaQQ/Mcp-Reasoning-Server.git && cd Mcp-Reasoning-Server && npm install && npm run build`. The server is `node dist/index.js`.
3. Call the tool with:

   ```json
   {"prompt": "<img src=x onerror=alert(1)>"}
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
               result = await session.call_tool("r1_reasoning", {"prompt": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `originalPrompt` and the `For the prompt: ...` line in `reasoning`. Both contain the markup exactly as sent.

## Expected behavior
Values copied from the arguments are encoded so they cannot be read as markup if the reply is rendered, or are not echoed back at all.

## Actual behavior
The prompt is returned verbatim inside the JSON text. From the fuzzing run (trimmed):

```
"strategy": "r1_transformer",
"originalPrompt": "<script>window.location='file:///etc/passwd'</script>",
"reasoning": "R1 Reasoning Analysis:\n\nFor the prompt: \"<script>window.location='file:///etc/passwd'</script>...\", the analysis is: ...
```

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in content the model reads can steer them. The reply goes back to the same client. If that client renders tool results as HTML or Markdown, injected markup would render in the user's view. If the client shows tool output as plain text, which is the common case, there is no effect. The tool reads no files and makes no requests.

## Suggested fix
Do not echo `prompt` back, since the caller already has it. If it is kept, escape markup characters in the serialized JSON, for example `JSON.stringify(obj, null, 2).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")`. The result is still valid JSON and decodes to the same strings.

## Status on the default branch
Still present at `7131e73` (2025-03-19). This is the tested commit; the default branch has no later commits.

## Prior reports
None found. Searched the 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. Neither item is about output handling: #1 is a Glama Dockerfile request and #2 adds a listing badge.
- Documentation: README.md: "This is a simulated reasoning server" (Limitations section; says the tools return placeholder responses, nothing about encoding of echoed input)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx` 3,584 executions / 2,175 successful (60 s budget); `repo24-b` 272,896 / 153,287 (4,200 s).
- Evidence (verbatim, trimmed): corpus-sbx input `{'prompt': "<script>window.location='file:///etc/passwd'</script>"}` -> output text `"originalPrompt": "<script>window.location='file:///etc/passwd'</script>"` (tokens matched `<script`, `</script>`). repo24-b rows: `{'prompt': '"pr${"'}` (matched `${`) and `{'prompt': '{{{{{{{{{{'}` (matched `{{`).
- Hand-check hints: weak. The `<script>` row shows real markup reflected unescaped, but only inside a JSON string in an MCP `text` block from a stub tool. Exploitable only in a client that renders tool output as HTML. Same pattern as the other seven flagged tools in this repo; file at most one combined issue.
</details>
