# Missing output encoding in `greet`: `name` is echoed raw into the greeting reply

**Repository:** `lucasmontano/mcp-montano-server` · **Tool:** `greet` · **Tested commit:** `b9a7585`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`greet` returns `Hey, <name>! Nice to meet you!` with the caller's `name` inserted unchanged. There is no format check and no encoding, so any markup or template-looking text in `name` comes back intact. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/index.ts:14-24` at the tested commit (`build/index.js` is the compiled form):

```ts
server.tool(
  "greet",
  {
    name: z.string().describe("The name of the person to greet"),
  },
  async ({ name }: { name: string }) => {
    return {
      content: [{ type: "text", text: `Hey, ${name}! Nice to meet you!` }],
    };
  }
);
```

`name` is `z.string()` with no further constraint and is interpolated directly into the reply.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials or network access needed.
2. Install and build as the README describes: `git clone git@github.com:lucasmontano/mcp-montano-server.git && cd mcp-montano-server && npm install && npm run build`. The server is `node build/index.js` (stdio transport by default).
3. Call the tool with:

   ```json
   {"name": "<img src=x onerror=alert(1)>"}
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
               result = await session.call_tool("greet", {"name": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the reply `Hey, <img src=x onerror=alert(1)>! Nice to meet you!`, with the markup unchanged.

## Expected behavior
`name` is escaped before being placed in the reply.

## Actual behavior
The value is returned verbatim. From the fuzzing run:

```
Hey, ${7*7}! Nice to meet you!
Hey, <script>alert(1)</script>! Nice to meet you!
Hey, "na{{"na/{"! Nice to meet you!
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. The reply returns to the same client. In a client that renders tool output as HTML or Markdown, injected markup in `name` (for example the `<script>alert(1)</script>` the fuzzer sent) would render in the user's view. In a plain-text client there is no effect. The `${7*7}` input is returned literally, so there is no server-side template evaluation. The tool reads no files and makes no requests.

## Suggested fix
Escape HTML/Markdown special characters in `name` before interpolating it into the greeting.

## Status on the default branch
Still present at `b9a7585` (2025-03-18). This is the tested commit and the current default-branch head; the tool is unchanged.

## Prior reports
None found. Searched all 1 issue and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The issue and PRs are directory listings, a Smithery deployment PR and third-party scan badges reporting no findings. The README says nothing about output encoding or untrusted input.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116). Triggered: `check_log_injection`, `check_reflected_output`. (The `<script>` row is tagged `check_log_injection` in the evidence, but the server does no logging of `name`; the reflection into the reply is the actual finding.)
- Campaigns and executions: `corpus-sbx`, 3,584 executions, 3,584 successful, 60 s budget.
- Evidence (verbatim, trimmed): `{'name': '${7*7}'}` -> `Hey, ${7*7}! Nice to meet you!` (matched `${`); `{'name': '<script>alert(1)</script>'}` -> `Hey, <script>alert(1)</script>! Nice to meet you!` (matched `<script`, `</script>`); `{'name': '"na{{"na/{"'}` -> `Hey, "na{{"na/{"! Nice to meet you!` (matched `{{`).
- Hand-check hints: real reflection, low severity. Direct unescaped echo of a caller string, including a real `<script>` payload, into an MCP `text` block. Cleanest example in this group. Still exploitable only in a client that renders tool output as HTML/Markdown; `${7*7}` is not evaluated, so there is no template-injection angle.
</details>
