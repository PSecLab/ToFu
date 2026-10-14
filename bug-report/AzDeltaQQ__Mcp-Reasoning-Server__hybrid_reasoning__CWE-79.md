# Missing output encoding in `hybrid_reasoning`: `prompt` and `thought` are echoed raw into the tool reply

**Repository:** `AzDeltaQQ/Mcp-Reasoning-Server` · **Tool:** `hybrid_reasoning` · **Tested commit:** `7131e73`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`hybrid_reasoning` is a placeholder tool that returns a JSON summary of the step it was given. It copies the caller's `prompt` and `thought` into that JSON unchanged, and also puts the first 50 characters of `thought` into the generated `nextThought` sentence. `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `&` alone, so any markup in the arguments comes back intact. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/tools/reasoning-tools.ts:216-232` at the tested commit (comments trimmed; `dist/tools/reasoning-tools.js` is the same):

```ts
if (nextThoughtNeeded) {
  nextThought = `Hybrid Reasoning (Step ${thoughtNumber + 1}/${totalThoughts}): ` +
                `Combining transformer analysis with ${numSimulations} MCTS simulations on "${thought.slice(0, 50)}...", ` +
                `the enhanced analysis suggests... ` +
                `[This would be actual Hybrid Transformer+MCTS reasoning content]`;
}
return {
  content: [{
    type: "text",
    text: JSON.stringify({
      strategy: "hybrid_transformer_mcts",
      originalPrompt: prompt,
      currentThought: thought,
```

`prompt` and `thought` are `z.string()` (lines 192-193) with only a non-empty check (lines 202-208). Nothing encodes them before they go into the reply.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No credentials or network access are needed.
2. Install and build as the README describes: `git clone https://github.com/AzDeltaQQ/Mcp-Reasoning-Server.git && cd Mcp-Reasoning-Server && npm install && npm run build`. The server is `node dist/index.js`.
3. Call the tool with:

   ```json
   {"prompt": "<img src=x onerror=alert(1)>", "thought": "<b>tofu-poc</b>", "thoughtNumber": 1, "totalThoughts": 2, "nextThoughtNeeded": true, "numSimulations": 50}
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
               result = await session.call_tool("hybrid_reasoning", {
                   "prompt": "<img src=x onerror=alert(1)>",
                   "thought": "<b>tofu-poc</b>",
                   "thoughtNumber": 1,
                   "totalThoughts": 2,
                   "nextThoughtNeeded": True,
                   "numSimulations": 50,
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
"originalPrompt": "File ile",
"currentThought": "{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ughtNee",
"nextThought": "Hybrid Reasoning (Step 2/1): Combining transformer analysis with 50 MCTS simulations on \"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ug...\", the enhanced analysis suggests... [This would be actual Hybrid Transformer+MCTS reasoning content]",
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

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output`, plus `check_invalid_json` (a "silent bug" flag because the input looked like broken JSON and the tool still succeeded; not a separate finding).
- Campaigns and executions: `repo24-b`, 287,232 executions, 14,958 successful, 4,200 s budget.
- Evidence (verbatim, trimmed): input `{'prompt': 'File ile', 'thought': '{{{{...{{ughtNee', 'thoughtNumber': 1, 'totalThoughts': 1, 'nextThoughtNeeded': True, 'numSimulations': 50}` -> output text `"currentThought": "{{{{...{{ughtNee"` and `nextThought` containing `on \"{{{{...{{ug...\"`. Token matched: `{{` only, in all 3 evidence rows.
- Hand-check hints: weak. Stub tool that echoes its arguments into a JSON string inside an MCP `text` block. ToFu only saw `{{` reflected, which has no meaning here. That `<`/`>` survive is inferred from the code (`JSON.stringify` does not escape them), not from a log. Same pattern as the other seven flagged tools in this repo; file at most one combined issue.
</details>
