# Missing output encoding in `search_nodes`: `query` is echoed verbatim in `actionTaken`

**Repository:** `CheMiguel23/MemoryMesh` · **Tool:** `search_nodes` · **Tested commit:** `531580d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`search_nodes` searches node names, types and metadata and reports `Searched nodes with query: "<query>" ...`. The caller's `query` value is copied into the `structuredContent.actionTaken` string with no encoding or quoting. MemoryMesh does not store this value and does not render `actionTaken` anywhere, so the risk is limited to MCP clients that display the summary as Markdown or HTML. This is a low-severity hardening issue.

## Details
`src/integration/tools/handlers/SearchToolHandler.ts:24-33`:

```ts
                case "search_nodes": {
                    const searchResults = await this.knowledgeGraphManager.searchNodes(args.query);
                    const isEmpty = searchResults.nodes.length === 0;
                    return formatToolResponse({
                        data: searchResults,
                        actionTaken: isEmpty
                            ? `Searched nodes with query: "${args.query}" - no matching nodes found`
                            : `Searched nodes with query: "${args.query}" - found ${searchResults.nodes.length} nodes`
                    });
```

The string goes into `structuredContent.actionTaken` via `formatToolResponse` (`src/shared/utils/responseFormatter.ts:43-45`). The query is wrapped in `"` without escaping, so a `"` in the query ends the quoted part early. `MemoryViewer.html` reads only `memory.json`, and this tool does not write the echoed value there.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No accounts or env vars.
2. Install and build as the README describes, then let the client start it:
   `git clone https://github.com/CheMiguel23/memorymesh.git && cd memorymesh && npm install && npm run build`
   The server command is `node /ABSOLUTE/PATH/TO/memorymesh/dist/index.js`. Data goes to `dist/data/memory.json`.
3. Call the tool:

   ```json
   {"query": "<img src=x onerror=alert('tofu-poc')>"}
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
               result = await session.call_tool("search_nodes", {"query": "<img src=x onerror=alert('tofu-poc')>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: `structuredContent.actionTaken` contains `<img src=x onerror=alert('tofu-poc')>` unchanged. A client that renders this field as HTML or Markdown would display or interpret the markup.

## Expected behavior
Echoed input is quoted or encoded (for example with `JSON.stringify(value)`), or left out of the human-readable summary.

## Actual behavior
The value is copied as-is. Excerpt from the fuzzing run (Python repr):

```
input   query       : "'{{'yuue ue"
output  actionTaken : 'Searched nodes with query: "\'{{\'yuue ue" - no matching nodes found'
```

The fuzzer flagged `{{`, which MemoryMesh does not evaluate. The same path carries HTML, as the reproduction shows.

## Impact
Low. The LLM supplies `query`, and prompt injection can steer it, but the echo only returns the caller's own input to the caller. It matters only if a client renders `actionTaken` as rich text, and I found no such renderer in this repository.

## Suggested fix
Quote the value with `JSON.stringify(...)` when building the message, or drop the input from `actionTaken`, since the structured result already identifies what was done. Clients that render tool output should escape it on their side.

## Status on the default branch
Still present at `531580d` (2026-01-17). The default branch head is the tested commit.

## Prior reports
None found. Searched all 9 issues and 47 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 calls / 2560 succeeded (60 s budget); repo24-b 310784 calls / 310784 succeeded (4200 s budget); e2-0922 2048 calls / 2048 succeeded (300 s budget).
- Evidence (verbatim, trimmed, non-ASCII shown as escapes):
  - [corpus-sbx] input: `{'query': "'{{'yuue ue"}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [],\n  "edges": []\n}'}], 'structuredContent': {'timestamp': '2026-09-26T18:32:44.922Z', 'data': {'nodes': [], 'edges': []}, 'actionTaken': 'Searched nodes with query: "\'{{\'yuue ue" - no matching nodes found'}, 'isError': False}`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
  - [corpus-sbx] input: `{'query': "'{{'yuu'{{'"}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [],\n  "edges": []\n}'}], 'structuredContent': {'timestamp': '2026-09-26T18:32:44.942Z', 'data': {'nodes': [], 'edges': []}, 'actionTaken': 'Searched nodes with query: "\'{{\'yuu\'{{\'" - no matching nodes found'}, 'isError': False}`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
- Hand-check hints: weak. Only `{{` was echoed, into a plain-text field (`actionTaken`) of the JSON tool result. The value is not persisted and not rendered by `MemoryViewer.html`, and there is no rendering context for it in the repo. Probably not worth filing on its own; at most mention it in a combined MemoryMesh output-encoding issue.
</details>
