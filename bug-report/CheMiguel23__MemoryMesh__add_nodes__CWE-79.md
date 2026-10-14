# Stored XSS from `add_nodes`: node metadata is rendered as HTML by `MemoryViewer.html`

**Repository:** `CheMiguel23/MemoryMesh` · **Tool:** `add_nodes` · **Tested commit:** `531580d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`add_nodes` adds nodes with a `name`, a `nodeType` and a `metadata` string array to the knowledge graph. The strings are saved to `memory.json` and echoed back exactly as given. The bundled `MemoryViewer.html`, which the README recommends for inspecting `memory.json`, inserts each metadata string with `innerHTML`, so markup stored through `add_nodes` runs as script when the memory file is opened in the viewer.

## Details
`src/integration/tools/handlers/GraphToolHandler.ts:13-18` passes `args.nodes` to `NodeManager.addNodes` (`src/application/managers/NodeManager.ts:16-38`). The only checks are `GraphValidator.validateNodeProperties` (`src/core/graph/GraphValidator.ts:46-56`: `name` and `nodeType` present, `metadata` is an array) and a duplicate-name check. The node is written to `dist/data/memory.json` by `saveGraph` (`src/infrastructure/storage/JsonLineStorage.ts:103-118`) and returned in the result.

`MemoryViewer.html:529-537` splits each metadata string at the first `:` and renders both parts as HTML:

```js
parsedMetadata.forEach(({ key, value }) => {
    const item = document.createElement('div');
    item.className = 'metadata-item';
    if (key) {
        item.innerHTML = `<span class="metadata-key">${key}:</span> <span class="metadata-value">${value}</span>`;
    } else {
        item.innerHTML = `<span class="metadata-value">${value}</span>`;
    }
```

The name and node type columns use `textContent` (`MemoryViewer.html:724` and `:763`) and are safe. Edge lists are built with `innerHTML` from `edge.edgeType` and `edge.to` (`MemoryViewer.html:744-747`). `update_nodes`, `add_metadata` and the schema tools (`add_artifact`, `add_currency`, `add_faction`, `add_inventory`, `add_location`, `add_npc`, `add_player_character`, `add_quest`, `add_skills`, `add_transportation`) write to the same metadata array.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No accounts or env vars. A Chromium-based browser for the viewer (it uses `showOpenFilePicker`). Start from an empty `dist/data/memory.json`, or pick a node name that does not exist yet.
2. Install and build as the README describes, then let the client start it:
   `git clone https://github.com/CheMiguel23/memorymesh.git && cd memorymesh && npm install && npm run build`
   The server command is `node /ABSOLUTE/PATH/TO/memorymesh/dist/index.js`. Data goes to `dist/data/memory.json`.
3. Call the tool:

   ```json
   {"nodes": [{"name": "tofu-poc-node", "nodeType": "test", "metadata": ["note: <img src=x onerror=alert('tofu-poc')>"]}]}
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
               result = await session.call_tool("add_nodes", {"nodes": [{"name": "tofu-poc-node", "nodeType": "test", "metadata": ["note: <img src=x onerror=alert('tofu-poc')>"]}]})
               print(result)

   asyncio.run(main())
   ```
4. Observe:
   - The result echoes `note: <img src=x onerror=alert('tofu-poc')>` unchanged in `content[0].text` and `structuredContent.data.nodes[0].metadata`, and `dist/data/memory.json` contains it.
   - Open `MemoryViewer.html` from the repository root in Chrome or Edge, click "Select Memory File" and choose `dist/data/memory.json`. An alert with `tofu-poc` appears when the table is built (the `<img>` is created by `innerHTML`, so it loads even before "Show Metadata" is clicked).

## Expected behavior
Stored values are shown as text. The viewer inserts metadata (and edge fields) with `textContent`, or escapes `& < > " '` before using `innerHTML`.

## Actual behavior
The metadata is stored and echoed byte for byte, and the viewer parses it as HTML. Excerpt from the fuzzing run (Python repr, trimmed):

```
input   nodes[0].metadata      : ["<script>alert('xss')</script>", "SELECT * FROM users WHERE '1'='1'"]
output  data.nodes[0].metadata : ["<script>alert('xss')</script>", "SELECT * FROM users WHERE '1'='1'"]
output  actionTaken            : 'Added nodes to knowledge graph'
```

A `<script>` element inserted through `innerHTML` does not execute, which is why the reproduction uses an `<img onerror>` payload.

## Impact
The LLM writes the metadata, often from conversation text or documents, and prompt injection in that content can make it store markup. The script runs when the user opens the memory file in `MemoryViewer.html`, in that page's context: it can change what the viewer shows and read the loaded graph, and it can make requests from the page. The viewer opens the file in read mode, so the script cannot write `memory.json` through the existing handle. MCP clients that show the tool result as plain text are not affected. Severity is low to moderate and depends on users opening the viewer.

## Suggested fix
- In `MemoryViewer.html`, build metadata items with `createElement` + `textContent` (lines 534 and 536), and do the same for the edge items (lines 744-747), or escape `key`, `value`, `edge.edgeType` and `edge.to` first.

## Status on the default branch
Still present at `531580d` (2026-01-17). The default branch head is the tested commit.

## Prior reports
None found. Searched all 9 issues and 47 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 calls / 627 succeeded (60 s budget); repo24-b 20480 calls / 2888 succeeded (4200 s budget); e2-0922 2048 calls / 265 succeeded (300 s budget).
- Evidence (verbatim, trimmed, non-ASCII shown as escapes):
  - [corpus-sbx] input: `{'nodes': [{'name': 'sensitive_error_leak', 'nodeType': 'error', 'metadata': ["<script>alert('xss')</script>", "SELECT * FROM users WHERE '1'='1'"]}]}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [\n    {\n      "name": "sensitive_error_leak",\n      "nodeType": "error",\n      "metadata": [\n        "<script>alert(\'xss\')</script>",\n        "SELECT * FROM users WHERE \'1\'=\'1\'"\n      ]\n    }\n  ]\n}'}], 'structuredContent': {'timest ...[trimmed]`
    ToFu: reflected token(s) ['<script', '</script>']; sanitizers ['check_reflected_output']
  - [corpus-sbx] input: `{'nodes': [{'name': '"nodOOOOes\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00": [{"{{""\x00\x00\x00\x00\x00\x00es": [{e": "', 'nodeType': '\U00107365', 'metadata': []}]}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [\n    {\n      "name": "\\"nodOOOOes\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000\\": [{\\"{{\\"\\"\\u0000\\u0000\\u0000\\u0000\\u0000\\u0000es\\": [{e\\": \\ ...[trimmed]`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
- Hand-check hints: real, low to moderate, by code reading. ToFu saw `<script>` (and `{{` in other samples) echoed into the JSON tool result, which by itself is plain text for most MCP clients. The real sink is `MemoryViewer.html:534/536` (`innerHTML` of stored metadata), found by reading the code; ToFu did not exercise it, and I did not open the viewer in a browser. The claim that `onerror` fires before "Show Metadata" is clicked follows from `<img>` loading on `innerHTML` parse; confirm in a browser. Same root cause as the `add_*` schema-tool drafts: consider one combined issue against the viewer.
</details>
