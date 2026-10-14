# Missing output encoding in `delete_nodes`: `nodeNames` is echoed verbatim in `actionTaken`

**Repository:** `CheMiguel23/MemoryMesh` · **Tool:** `delete_nodes` · **Tested commit:** `531580d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`delete_nodes` deletes nodes by name and reports `Deleted nodes: <names>`. The caller's `nodeNames` value is copied into the `structuredContent.actionTaken` string with no encoding or quoting. MemoryMesh does not store this value and does not render `actionTaken` anywhere, so the risk is limited to MCP clients that display the summary as Markdown or HTML. This is a low-severity hardening issue.

## Details
`src/integration/tools/handlers/GraphToolHandler.ts:41-45`:

```ts
                case "delete_nodes":
                    await this.knowledgeGraphManager.deleteNodes(args.nodeNames);
                    return formatToolResponse({
                        actionTaken: `Deleted nodes: ${args.nodeNames.join(', ')}`
                    });
```

The string goes into `structuredContent.actionTaken` via `formatToolResponse` (`src/shared/utils/responseFormatter.ts:43-45`). The message is also returned when no node with that name existed: `deleteNodes` (`src/application/managers/NodeManager.ts:78-100`) filters silently and does not report a miss. The result has no `content` text block (`data` is undefined), so the echo is only in `structuredContent.actionTaken`. `MemoryViewer.html` reads only `memory.json`, and this tool does not write the echoed value there.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No accounts or env vars.
2. Install and build as the README describes, then let the client start it:
   `git clone https://github.com/CheMiguel23/memorymesh.git && cd memorymesh && npm install && npm run build`
   The server command is `node /ABSOLUTE/PATH/TO/memorymesh/dist/index.js`. Data goes to `dist/data/memory.json`.
3. Call the tool:

   ```json
   {"nodeNames": ["<img src=x onerror=alert('tofu-poc')>"]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/ABSOLUTE/PATH/TO/memorymesh/dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("delete_nodes", {"nodeNames": ["<img src=x onerror=alert('tofu-poc')>"]})
               print(result)

   asyncio.run(main())
   ```
4. Observe: `structuredContent.actionTaken` contains `<img src=x onerror=alert('tofu-poc')>` unchanged. A client that renders this field as HTML or Markdown would display or interpret the markup.

## Expected behavior
Echoed input is quoted or encoded (for example with `JSON.stringify(value)`), or left out of the human-readable summary.

## Actual behavior
The value is copied as-is. Excerpt from the fuzzing run (Python repr):

```
input   nodeNames   : ['"{{"n"nod']
output  content     : []
output  actionTaken : 'Deleted nodes: "{{"n"nod'
```

The fuzzer flagged `{{`, which MemoryMesh does not evaluate. The same path carries HTML, as the reproduction shows.

## Impact
Low. The LLM supplies `nodeNames`, and prompt injection can steer it, but the echo only returns the caller's own input to the caller. It matters only if a client renders `actionTaken` as rich text, and I found no such renderer in this repository.

## Suggested fix
Quote the value with `JSON.stringify(...)` when building the message, or drop the input from `actionTaken`, since the structured result already identifies what was done. Clients that render tool output should escape it on their side.

## Status on the default branch
Still present at `531580d` (2026-01-17). The default branch head is the tested commit.

## Prior reports
None found. Searched all 9 issues and 47 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 calls / 2502 succeeded (60 s budget); repo24-b 292864 calls / 286072 succeeded (4200 s budget); e2-0922 2048 calls / 2005 succeeded (300 s budget).
- Evidence (verbatim, trimmed, non-ASCII shown as escapes):
  - [corpus-sbx] input: `{'nodeNames': ['"{{"n"nod']}`
    output: `{'content': [], 'structuredContent': {'timestamp': '2026-09-26T18:31:43.076Z', 'actionTaken': 'Deleted nodes: "{{"n"nod'}, 'isError': False}`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
  - [corpus-sbx] input: `{'nodeNames': ['"{{":n"nod']}`
    output: `{'content': [], 'structuredContent': {'timestamp': '2026-09-26T18:31:43.097Z', 'actionTaken': 'Deleted nodes: "{{":n"nod'}, 'isError': False}`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
- Hand-check hints: weak. Only `{{` was echoed, into a plain-text field (`actionTaken`) of the JSON tool result. The value is not persisted and not rendered by `MemoryViewer.html`, and there is no rendering context for it in the repo. Probably not worth filing on its own; at most mention it in a combined MemoryMesh output-encoding issue.
</details>
