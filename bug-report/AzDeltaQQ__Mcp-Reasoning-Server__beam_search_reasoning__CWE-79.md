# Missing output encoding in `beam_search_reasoning`: `prompt` and `thought` are echoed raw into the tool reply

**Repository:** `AzDeltaQQ/Mcp-Reasoning-Server` · **Tool:** `beam_search_reasoning` · **Tested commit:** `7131e73`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`beam_search_reasoning` is a placeholder tool that returns a JSON summary of the step it was given. It copies the caller's `prompt` and `thought` into that JSON unchanged, and also puts the first 50 characters of `thought` into the generated `nextThought` sentence. `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `&` alone, so any markup in the arguments comes back intact. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/tools/reasoning-tools.ts:104-121` at the tested commit (comments trimmed; `dist/tools/reasoning-tools.js` is the same):

```ts
if (nextThoughtNeeded) {
  nextThought = `Beam Search Reasoning (Step ${thoughtNumber + 1}/${totalThoughts}): ` +
                `Considering ${beamWidth} alternative paths from "${thought.slice(0, 50)}...", ` +
                `the most promising direction is... ` +
                `[This would be actual Beam Search-based reasoning content]`;
}
return {
  content: [{
    type: "text",
    text: JSON.stringify({
      strategy: "beam_search",
      originalPrompt: prompt,
      currentThought: thought,
```

`prompt` and `thought` are `z.string()` (lines 80-81) with only a non-empty check (lines 90-96). Nothing encodes them before they go into the reply.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No credentials or network access are needed.
2. Install and build as the README describes: `git clone https://github.com/AzDeltaQQ/Mcp-Reasoning-Server.git && cd Mcp-Reasoning-Server && npm install && npm run build`. The server is `node dist/index.js`.
3. Call the tool with:

   ```json
   {"prompt": "<img src=x onerror=alert(1)>", "thought": "<b>tofu-poc</b>", "thoughtNumber": 1, "totalThoughts": 2, "nextThoughtNeeded": true, "beamWidth": 3}
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
               result = await session.call_tool("beam_search_reasoning", {
                   "prompt": "<img src=x onerror=alert(1)>",
                   "thought": "<b>tofu-poc</b>",
                   "thoughtNumber": 1,
                   "totalThoughts": 2,
                   "nextThoughtNeeded": True,
                   "beamWidth": 3,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe `originalPrompt`, `currentThought` and `nextThought` in the reply text. All three contain the markup exactly as sent.

## Expected behavior
Values copied from the arguments are encoded so they cannot be read as markup if the reply is rendered, or are not echoed back at all.

## Actual behavior
The arguments are returned verbatim inside the JSON text. From the fuzzing run (trimmed):

```
"originalPrompt": "\"propt\": \"/etcl byte injection\", \"thoughtNumber\": 1, {{{{{{{{{{{{{{{{{{{{{{...
"currentThought": "...",
"nextThought": "Beam Search Reasoning (Step 2/1): Considering 1 alternative paths from \"...\", the most promising direction is... [This would be actual Beam Search-based reasoning content]",
```

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in content the model reads can steer them. The reply goes back to the same client. If that client renders tool results as HTML or Markdown, injected markup would render in the user's view. If the client shows tool output as plain text, which is the common case, there is no effect. The tool reads no files and makes no requests.

## Suggested fix
Do not echo `prompt` and `thought` back, since the caller already has them. If they are kept, escape markup characters in the serialized JSON, for example `JSON.stringify(obj, null, 2).replace(/</g, "\\u003c").replace(/>/g, "\\u003e").replace(/&/g, "\\u0026")`. The result is still valid JSON and decodes to the same strings.

## Status on the default branch
Still present at `7131e73` (2025-03-19). This is the tested commit; the default branch has no later commits.

## Prior reports
None found. Searched the 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. Neither item is about output handling: #1 is a Glama Dockerfile request and #2 adds a listing badge.
- Documentation: README.md: "This is a simulated reasoning server" (Limitations section; says the tools return placeholder responses, nothing about encoding of echoed input)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `repo24-b`, 285,184 executions, 13,126 successful, 4,200 s budget.
- Evidence (verbatim, trimmed): input `{'prompt': '"propt": "/etcl byte injection", "thoughtNumber": 1, {{{{{{{{...{{"totalThoughts": 1, "nextThoughtNeeded": true, ', 'thought': '<5 CJK chars>', 'thoughtNumber': 1, 'totalThoughts': 1, 'nextThoughtNeeded': True, 'beamWidth': 1}` -> output text `"originalPrompt": "\"propt\": \"/etcl byte injection\", ... {{{{{{...` with `"complete": true`. Token matched: `{{` only. All 3 evidence rows are `{{` reflections; none contains `<`.
- Hand-check hints: weak. The tool is a stub that echoes its arguments into a JSON string inside an MCP `text` block. ToFu only saw template braces `{{` reflected, which have no meaning in this output. I inferred from the code (not from a log) that `<`/`>` survive too: `JSON.stringify` does not escape them. Low severity at most. Eight tools in this repo were flagged for the same pattern (`mcts_reasoning`, `beam_search_reasoning`, `r1_reasoning`, `hybrid_reasoning`, `reason_mcts`, `reason_beam`, `reason_r1`, `reason_hybrid`). If anything is filed, make it one combined issue.
</details>
