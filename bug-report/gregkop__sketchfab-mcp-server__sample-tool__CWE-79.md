# Missing output encoding in `sample-tool`: leftover demo tool echoes its input verbatim

**Repository:** `gregkop/sketchfab-mcp-server` · **Tool:** `sample-tool` · **Tested commit:** `e5969ef`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
The server still registers a template tool named `sample-tool` ("A sample tool for demonstration purposes"). It returns `Processed: <input>` with the caller's input copied verbatim. It has no Sketchfab function, and any markup or template syntax in `input` comes back unescaped. Clients see it next to the real tools, and the model can call it.

## Details
`index.ts:255-276` at `e5969ef`:

```ts
// Define a sample tool
server.tool(
  "sample-tool",
  "A sample tool for demonstration purposes",
  {
    input: z.string().describe("Input parameter for the sample tool"),
  },
  async ({ input }) => {
    // Process the input
    const output = `Processed: ${input}`;
```

The input is not escaped or limited. The README does not list this tool.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No Sketchfab API key is needed for this tool.
2. Install and start the server:
   ```
   git clone https://github.com/gregkop/sketchfab-mcp-server.git
   cd sketchfab-mcp-server && git checkout e5969ef8588d0a47a8c5a0341903f3efacb74b3b
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"input": "<b>tofu-poc</b>{{7*7}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("sample-tool", {"input": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Processed: <b>tofu-poc</b>{{7*7}}`.

## Expected behavior
A production server should not expose the template tool. If it stays, it should not reflect markup verbatim.

## Actual behavior
The input is echoed unchanged. From the fuzzing run:

```
Processed: {{{{{{{{{{{{{{{{{{{{{{{{{{{
```

## Impact
Low. The LLM chooses tool arguments, and prompt injection can steer them, so a steered call can make the server return arbitrary text or markup with this server's name attached. This matters only in clients that render tool results as HTML or Markdown. The tool does nothing useful, so it only adds attack surface and noise to the tool list.

## Suggested fix
Remove the `sample-tool` registration (`index.ts:255-276`).

## Status on the default branch
Still present at `e5969ef` (2025-03-09). The tested commit is the head of the default branch.

## Prior reports
None found. Searched the 1 issue and all 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. README.md documents only the three `sketchfab-*` tools and does not mention `sample-tool`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,042 ok (60 s).
- Evidence (verbatim, trimmed):
  - input `{'input': '{{{{{{{{{{{{{{{{{{{{{{{{{{{'}` -> `{'content': [{'type': 'text', 'text': 'Processed: {{{{{{{{{{{{{{{{{{{{{{{{{{{'}]}`.
  - input `{'input': '\x10{{{{'}` -> `'Processed: \x10{{{{'`.
- Hand-check hints: weak. It is an echo tool by design, the output is plain text, and only `{{` was observed. The useful message is "remove the leftover template tool". Fold it into the `sketchfab-download` issue rather than filing it separately. Side observation, not verified at runtime: `main()` writes `console.log(...)` to stdout (`index.ts:588-595`) on a stdio transport. Those lines are not JSON-RPC and may produce client-side parse warnings.
</details>
