# Missing output encoding in `echo`: the message is returned raw (by design) and also written raw to stderr

**Repository:** `PuroDelphi/mcpFirebird` · **Tool:** `echo` · **Tested commit:** `0b0980f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`echo` is a compatibility test tool that returns its `message` argument unchanged. Markup such as `<script>` comes back as given. That is the tool's stated purpose and the reply is plain MCP text, so on its own this is low severity. The question for maintainers is whether a test-only tool should ship in the default tool list.

## Details
`src/tools/simple.ts:18-36` (tested commit):

```ts
tools.set('echo', {
    name: 'echo',
    description: 'Echoes back the input message',
    inputSchema: z.object({ message: z.string().describe('The message to echo back') }),
    handler: async (args: { message: string }) => {
        logger.info(`Echo tool called with message: ${args.message}`);
        return { content: [{ type: "text", text: args.message }] };
    }
});
```

The tool is registered unconditionally by `setupSimpleTools()` in `src/server/mcp-server.ts:133`, `src/server/create-server.ts:63` and `src/http-entry.ts:164`. The same handler also writes the message to stderr through `logger.info` (`src/utils/logger.ts:99`), with no CR/LF neutralization.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No Firebird server is needed.
2. Install and build: `git clone https://github.com/PuroDelphi/mcpFirebird.git && cd mcpFirebird && git checkout 0b0980f && npm install && npm run build`
3. Call the tool with:

   ```json
   {"message": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("echo", {"message": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `<b>tofu-poc</b>` returned unchanged in the reply text.

## Expected behavior
Either the test tool is not exposed by default, or (if it stays) this is accepted as intended behavior.

## Actual behavior
From the fuzzing run:

```
input:  {"message": "<script>alert('xss')</script>"}
output: <script>alert('xss')</script>
```

## Impact
The LLM chooses `message`, and prompt injection can steer it. The text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup into the chat view; in a plain-text client there is no effect. Low severity.

## Suggested fix
Register `echo` only in a debug or test mode (for example behind an environment flag), since it adds no database function. If it stays, no encoding change is needed for the reply. For the stderr log line, replace `\r` and `\n` in `args.message` before logging.

## Status on the default branch
Still present at `bf1b3bf` (2026-09-29). `src/tools/simple.ts` is unchanged since the tested commit.

## Prior reports
- No related issue or pull request among all 25 issues and 9 pull requests (fetched 2026-10-01).
- Documentation: docs/tools.md: "Echoes back the input message." (listed under "Utility Tools"; returning the message unchanged is the documented purpose of the tool)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2048 exec / 2048 ok (60 s); repo24-b 239616 / 239616 (4200 s); e2-0922 2048 / 2048 (300 s).
- Evidence (verbatim, trimmed):
  - `{'message': '{{7*7}}'}` -> `{{7*7}}`
  - `{'message': "<script>alert('xss')</script>"}` -> `<script>alert('xss')</script>`
  - `{'message': 'ssage": "{{7*7}}"}}'}` -> `ssage": "{{7*7}}"}}`
- Hand-check hints: weak, expected behavior. An echo tool echoing is its function, so filing this as XSS would likely be rejected. The only useful angles are (a) a test tool exposed in production builds and (b) the raw `logger.info` of the message to stderr at `simple.ts:25` (a CWE-117 angle ToFu did not flag for this tool; not run). Recommend not filing as CWE-79.
</details>
