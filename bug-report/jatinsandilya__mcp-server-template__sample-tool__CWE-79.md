# Missing output encoding in `sample-tool`: `input` is returned raw, and the template passes the pattern on

**Repository:** `jatinsandilya/mcp-server-template` · **Tool:** `sample-tool` · **Tested commit:** `4d739a1`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`sample-tool` is the example tool in this starter template. It returns `Processed: ` followed by its `input` argument, unchanged, so markup such as `<script>` comes back as given. For an example tool this is expected and low severity on its own. The point for the template is that every server built from it starts with a handler that reflects caller input without encoding, and nothing in the template says so.

## Details
`index.ts:12-32` registers the tool. The handler, `index.ts:16-27` (tested commit):

```ts
    input: z.string().describe("Input parameter for the sample tool"),
  },
  async ({ input }) => {
    // Process the input
    const output = `Processed: ${input}`;

    // Return the result
    return {
      content: [
        {
          type: "text",
          text: output,
```

`input` is interpolated into the reply at line 20 with no escaping or validation. The README's "Development" section tells users to replace this handler with their own logic, so the pattern is what new servers start from.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No accounts or env vars.
2. Install and build as the README describes:

   ```bash
   git clone https://github.com/jatinsandilya/mcp-server-template.git
   cd mcp-server-template && git checkout 4d739a1
   pnpm install && pnpm run build
   ```
3. Call the tool from the repository root with:

   ```json
   {"input": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("sample-tool", {"input": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply text `Processed: <b>tofu-poc</b>`, with the markup unchanged.

## Expected behavior
For a demo tool, echoing is acceptable. A template should still show the safe pattern: either not reflect raw input, or encode it, or carry a short comment that tool output reaching a rendering client must not contain unescaped caller input.

## Actual behavior
From the fuzzing run:

```
input:  {"input": "<script>alert('xss')</script>"}
output: Processed: <script>alert('xss')</script>
```

## Impact
The LLM chooses `input`, and prompt injection can steer it. The text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup into the chat view; in a plain-text client it has no effect. For this repository the practical risk is low. The larger effect is that servers derived from the template inherit the habit.

## Suggested fix
- Change the sample so it does not reflect raw input (for example return `input.length`), or escape it before returning, and add a one-line comment explaining why.
- Unrelated, same file: `index.ts:37` uses `console.log("MCP Server running on stdio")`. With the stdio transport, stdout carries the JSON-RPC stream, so this line should go to `console.error` instead.

## Status on the default branch
Still present at `4d739a1` (2025-05-05). The default branch head is the tested commit.

## Prior reports
None found. Searched all 0 issues and 5 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- Documentation: README.md: "The template includes a sample tool implementation in `index.ts`", with a skeleton that says "Implement your tool's logic here". It gives no guidance on escaping or validating input and no warning about reflecting it.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'input': "<script>alert('xss')</script>"}` -> `Processed: <script>alert('xss')</script>`
  - `{'input': '{"i&{{"i&n'}` -> `Processed: {"i&{{"i&n`
  - `{'input': '{{"i&{{"i&n'}` -> `Processed: {{"i&{{"i&n`
- Hand-check hints: weak, expected behavior. This is an echo tool in a starter template; reflecting input is its function and the output is plain MCP text. Filing it as XSS would likely be closed. The only defensible angle is template hygiene. The `console.log` on stdout at `index.ts:37` is a real, non-security bug (verified in code); I did not test how specific clients react to that stray line, and the fuzzer's client tolerated it (3072/3072 calls succeeded). Recommend not filing as CWE-79; if anything, file the stdout line as a small separate issue.
</details>
