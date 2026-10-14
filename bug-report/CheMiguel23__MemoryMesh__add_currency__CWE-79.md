# Stored XSS from `add_currency`: currency fields are rendered as HTML by `MemoryViewer.html`

**Repository:** `CheMiguel23/MemoryMesh` · **Tool:** `add_currency` · **Tested commit:** `531580d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`add_currency` is generated from `src/data/schemas/currency.schema.json` ("Represents a type of currency in the game world."). Every field of the `currency` object is turned into a `"field: value"` metadata string, saved to `memory.json` and echoed back, with no output encoding. The bundled `MemoryViewer.html`, which the README recommends for inspecting `memory.json`, inserts those metadata strings with `innerHTML`. Markup stored through `add_currency` therefore runs as script when the memory file is opened in the viewer.

## Details
`src/integration/tools/DynamicSchemaToolRegistry.ts:166-220` reads `args.currency`, checks only that the object exists and `name` is a string, calls `createSchemaNode`, stores the node with `addNodes` and returns it with `actionTaken` set to `Created ${schemaName}: ${nodeData.name}`. `createSchemaNode` builds each entry with `formatMetadataEntry`, `src/core/schema/SchemaProcessor.ts:29-34`:

```ts
function formatMetadataEntry(field: string, value: string | string[] | unknown): string {
    if (Array.isArray(value)) {
        return `${field}: ${value.join(', ')}`;
    }
    return `${field}: ${String(value)}`;
}
```

The node is written to `dist/data/memory.json` by `saveGraph` (`src/infrastructure/storage/JsonLineStorage.ts:103-118`). `MemoryViewer.html:529-537` then renders every entry as HTML:

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

The name column uses `textContent` (`MemoryViewer.html:724`), but `name` is also stored as the `name: ...` metadata entry, so it reaches the same sink as the other fields. Edge lists are built with `innerHTML` from `edge.edgeType` and `edge.to` as well (`MemoryViewer.html:744-747`). The other add tools (`add_artifact`, `add_faction`, `add_inventory`, `add_location`, `add_npc`, `add_player_character`, `add_quest`, `add_skills`, `add_transportation`, `add_nodes`) and `update_*` / `add_metadata` write to the same metadata array.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No accounts or env vars. A Chromium-based browser for the viewer (it uses `showOpenFilePicker`). Start from an empty `dist/data/memory.json`, or pick a name that does not exist yet (duplicates are rejected).
2. Install and build as the README describes, then let the client start it:
   `git clone https://github.com/CheMiguel23/memorymesh.git && cd memorymesh && npm install && npm run build`
   The server command is `node /ABSOLUTE/PATH/TO/memorymesh/dist/index.js`. Data goes to `dist/data/memory.json`.
3. Call the tool. The harmless payload is in `currency.description`:

   ```json
   {"currency": {"name": "tofu-poc-currency", "description": "<img src=x onerror=alert('tofu-poc')>", "owner": [], "quantity": "1"}}
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
               result = await session.call_tool("add_currency", {"currency": {"name": "tofu-poc-currency", "description": "<img src=x onerror=alert('tofu-poc')>", "owner": [], "quantity": "1"}})
               print(result)

   asyncio.run(main())
   ```
4. Observe:
   - The result echoes the markup unchanged in `content[0].text` and `structuredContent.data.nodes[0].metadata`, and `dist/data/memory.json` now contains it.
   - Open `MemoryViewer.html` from the repository root in Chrome or Edge, click "Select Memory File" and choose `dist/data/memory.json`. An alert with `tofu-poc` appears when the table is built (the `<img>` is created by `innerHTML`, so it loads even before "Show Metadata" is clicked).

## Expected behavior
Stored values are shown as text. The viewer inserts metadata (and edge fields) with `textContent`, or escapes `& < > " '` before using `innerHTML`.

## Actual behavior
The value is stored and echoed byte for byte, and the viewer parses it as HTML. Excerpt from the fuzzing run (Python repr, trimmed):

```
input   currency.name : 'nccur\x06{{zc'
output  metadata[0]   : 'name: nccur\x06{{zc'
output  actionTaken   : 'Created currency: nccur\x06{{zc'
```

The fuzzer flagged template braces (`{{` / `${`), which MemoryMesh does not evaluate. The same path carries HTML, as the reproduction shows.

## Impact
The LLM fills in the `currency` fields, often from role-play text, player messages or documents, and prompt injection in that content can make it store markup. The script runs when the user opens the memory file in `MemoryViewer.html`, in that page's context: it can change what the viewer shows and read the loaded graph, and it can make requests from the page. The viewer opens the file in read mode, so the script cannot write `memory.json` through the existing handle. MCP clients that show the tool result as plain text are not affected. Severity is low to moderate and depends on users opening the viewer.

## Suggested fix
- In `MemoryViewer.html`, build metadata items with `createElement` + `textContent` (lines 534 and 536), and do the same for the edge items (lines 744-747), or escape `key`, `value`, `edge.edgeType` and `edge.to` first.
- Optionally, reject control characters in `name`, since names act as identifiers.

## Status on the default branch
Still present at `531580d` (2026-01-17). The default branch head is the tested commit.

## Prior reports
None found. Searched all 9 issues and 47 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2048 calls / 1554 succeeded (60 s budget); repo24-b 8192 calls / 4957 succeeded (4200 s budget); e2-0922 2048 calls / 1265 succeeded (300 s budget).
- Evidence (verbatim, trimmed, non-ASCII shown as escapes):
  - [corpus-sbx] input: `{'currency': {'name': 'nccur\x06{{zc', 'description': '', 'owner': [], 'quantity': ''}}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [\n    {\n      "type": "node",\n      "name": "nccur\\u0006{{zc",\n      "nodeType": "currency",\n      "metadata": [\n        "name: nccur\\u0006{{zc",\n        "quantity: ",\n        "description: ",\n        "owner: "\n      ]\n    }\n  ],\n   ...[trimmed]`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
  - [corpus-sbx] input: `{'currency': {'name': 'eyz"\x06{{"cu{"c', 'description': '', 'owner': [], 'quantity': ''}}`
    output: `{'content': [{'type': 'text', 'text': '{\n  "nodes": [\n    {\n      "type": "node",\n      "name": "eyz\\"\\u0006{{\\"cu{\\"c",\n      "nodeType": "currency",\n      "metadata": [\n        "name: eyz\\"\\u0006{{\\"cu{\\"c",\n        "quantity: ",\n        "description: ",\n        "owner: "\n       ...[trimmed]`
    ToFu: reflected token(s) ['{{']; sanitizers ['check_reflected_output']
- Hand-check hints: real, low to moderate, by code reading. ToFu's own signal is weak: it saw input tokens (`{{` / `${`) echoed into the JSON tool result, which is plain text for most MCP clients and is not a template anywhere in MemoryMesh. The real sink is `MemoryViewer.html:534/536` (`innerHTML` of stored metadata), found by reading the code; ToFu did not exercise it, and I did not open the viewer in a browser. The claim that `onerror` fires before "Show Metadata" is clicked follows from `<img>` loading on `innerHTML` parse; confirm in a browser. Same root cause as the drafts for `add_artifact`, `add_faction`, `add_inventory`, `add_location`, `add_npc`, `add_player_character`, `add_quest`, `add_skills`, `add_transportation`, `add_nodes`: consider filing one combined issue against the viewer. Relationship fields (for example `owner`, `currentLocation`) are passed as `[]` where required, as in the fuzzing inputs, to avoid creating edges to nodes that do not exist (`addEdges` rejects those).
</details>
