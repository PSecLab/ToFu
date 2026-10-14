# Missing output encoding in `setLayerExpression`: `propertyName` is echoed raw in the reply

**Repository:** `Dakkshin/after-effects-mcp` · **Tool:** `setLayerExpression` · **Tested commit:** `88d5fbf`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`setLayerExpression` queues a command for the After Effects bridge panel to set an expression on a layer property. The confirmation text quotes the caller's `propertyName` inside double quotes with no escaping. Markup, quotes and newlines in the name come back unchanged. This matters only if a client renders tool output as HTML or Markdown, so the severity is low.

## Details
`src/index.ts:485-506` (tested commit):

```ts
server.tool(
  "setLayerExpression",
  "Set or remove an expression for a specific layer property.",
  {
    ...LayerIdentifierSchema,
    propertyName: z.string().describe("Name of the property to apply the expression to (e.g., 'Position', 'Scale', 'Rotation', 'Opacity')."),
    expressionString: z.string().describe("The JavaScript expression string. ...")
  },
  async (parameters) => {
      writeCommandFile("setLayerExpression", parameters);
      return { content: [{ type: "text",
            text: `Command to set expression for "${parameters.propertyName}" on layer ${parameters.layerIndex} in comp ${parameters.compIndex} has been queued.\n` + ...
```

`propertyName` is any string. The tool echoes it before After Effects ever sees it, so the reflection happens even when After Effects is not running.

## Steps to reproduce
1. Prerequisites: Node.js 18+. After Effects is not needed to see the echo. Note that the call writes `~/Documents/ae-mcp-bridge/ae_command.json`.
2. Install and build as the README describes: `git clone https://github.com/Dakkshin/after-effects-mcp && cd after-effects-mcp && npm install && npm run build`
3. Call the tool with:

   ```json
   {"compIndex": 1, "layerIndex": 1, "propertyName": "<img src=x onerror=alert(1)>", "expressionString": ""}
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
               result = await session.call_tool("setLayerExpression", {
                   "compIndex": 1, "layerIndex": 1,
                   "propertyName": "<img src=x onerror=alert(1)>",
                   "expressionString": "",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Command to set expression for "<img src=x onerror=alert(1)>" on layer 1 in comp 1 has been queued.` with the tag intact.

## Expected behavior
`propertyName` is checked against the known property names (or a safe character set) and anything else is rejected. Otherwise the echoed value is escaped.

## Actual behavior
The value is returned verbatim, including unbalanced quotes. From the fuzzing run:

```
input:  {'compIndex': 1953654128, 'layerIndex': 1835093625, 'propertyName': '": "", "expressionS{{"compIndex": 1, "layerIndex": 1, "prope"compIndex": 1, ', 'expressionString': '...'}
output: Command to set expression for "": "", "expressionS{{"compIndex": 1, "layerIndex": 1, "prope"compIndex": 1, " on layer 1835093625 in comp 1953654128 has been queued.
```

## Impact
The LLM chooses `propertyName` and can be steered by prompt injection. The attacker only gets a string reflected into the same conversation; it is a problem only in a client that renders tool output as HTML or Markdown. We found no such rendering path in this repository.

## Suggested fix
Validate `propertyName` with a zod enum or regex (for example `/^[A-Za-z0-9 _-]{1,64}$/`) in the tool schema, or escape it before building the reply. The same applies to the other confirmation messages that echo caller strings.

## Status on the default branch
Still present at `88d5fbf` (2026-04-01). The tested commit is the current default branch head.

## Prior reports
- #38 "fix: 6 bridge/scripting bugs found via live AE testing" (PR, open 2026-08-21): ran `setLayerExpression` live as part of its testing, but none of its six fixes touches this tool's reply. Does not fix this.
- Documentation: README.md lists `setLayerExpression` as "Add/remove expressions from properties", with no note on escaping or untrusted input.
- No issue or PR reports unescaped tool replies. Searched all 11 issues and 31 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2048 exec / 1617 ok (60 s budget).
- Evidence (verbatim, trimmed): two near-identical calls (`layerIndex` vs `layerMndex` in the string), output as in "Actual behavior". `expressionString` was a CJK-looking byte-mutation string.
- Hand-check hints: weak. The echo is real and confirmed in source (`src/index.ts:502`), but only `{{` and quotes were reflected, into a plain-text MCP reply; the `<img>` payload is my substitution. The fuzzer also showed that `compIndex`/`layerIndex` accept any positive integer, which is harmless. The more relevant property of this tool, `expressionString` being evaluated by After Effects' expression engine, is the tool's purpose and not a finding.
</details>
