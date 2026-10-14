# Missing output encoding in `create_workflow` (legacy stdio entry): node fields are echoed back verbatim in the returned JSON (low impact)

**Repository:** `makafeli/n8n-workflow-builder` · **Tool:** `create_workflow` · **Tested commit:** `411c0a7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
In the legacy stdio entry points (`dist/index.js` and `src/index.cjs`), `create_workflow` builds a workflow object from the caller's `nodes` and `connections` and returns it as JSON. It sends nothing to n8n. Node `type`, `name` and `parameters` come back unchanged inside JSON strings, so markup or `{{` sequences in them appear verbatim in the tool result. `JSON.stringify` escapes quotes and control characters, so this only matters if a client renders the returned text as HTML or Markdown without escaping it. The packaged server (`build/server.cjs`, built from `src/server.ts`) has a different `create_workflow` that posts to the n8n API.

## Details
`dist/index.js:130-145` (the same logic is in `src/index.cjs:360-377`):

```js
const { nodes, connections } = args;
for (const node of nodes) {
    builder.addNode(node.type, node.name, node.parameters || {});
}
for (const conn of connections || []) {
    builder.connectNodes(conn.source, conn.target, conn.sourceOutput, conn.targetInput);
}
return {
    content: [{
            type: 'text',
            text: JSON.stringify(builder.exportWorkflow(), null, 2)
        }]
};
```

`isWorkflowSpec` (`dist/index.js:117-128`) checks only that `type` and `name` are strings. `addNode` (`dist/index.js:20-30`) stores them as given. The output is plain `text` content holding JSON.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No n8n instance is needed for this entry point.
2. Install as the README describes (`git clone https://github.com/makafeli/n8n-workflow-builder.git && cd n8n-workflow-builder && npm install`). Then run the legacy entry directly with `node dist/index.js`.
3. Call the tool:
   ```json
   {"nodes": [{"type": "n8n-nodes-base.noOp", "name": "<b>tofu-poc</b> {{ $json.x }}", "parameters": {}}]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["/path/to/n8n-workflow-builder/dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_workflow", {
                   "nodes": [{"type": "n8n-nodes-base.noOp",
                              "name": "<b>tofu-poc</b> {{ $json.x }}",
                              "parameters": {}}]
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the returned JSON contains `"name": "<b>tofu-poc</b> {{ $json.x }}"` unchanged.

## Expected behavior
Echoing the caller's workflow back as JSON is reasonable for a builder. If the output may be shown in a rendering client, HTML-significant characters should be escaped, or the content should be marked as JSON or code so clients do not render it.

## Actual behavior
Input strings appear verbatim in the returned JSON. From the fuzzing run (trimmed):

```
"type": "\"nodes\": [{{\"nodes\": [{\"type\": \"sensitiveError\", \"name\": \"leakNode\", ...",
```

ToFu's only payload token found in the output was `{{`.

## Impact
The arguments come from the LLM. The tool returns the caller's own input, formatted as JSON, to the same caller. No other user or system receives it. Negligible to low, and only for clients that render tool text as HTML or Markdown.

## Suggested fix
- Optional: return the workflow as an embedded resource with `mimeType: "application/json"`, or wrap it in a fenced code block, so clients show it as data.
- Consider removing or clearly deprecating the legacy `dist/index.js` and `src/index.cjs` entry points, since the published binary uses `src/server.ts`.

## Status on the default branch
Still present at `411c0a7` (2026-03-19). The tested commit is the current default branch head. Both legacy files are still in the repository.

## Prior reports
None found. Searched all 15 issues and 11 pull requests (fetched 2026-10-01) and the README and the other top-level docs (GETTING_STARTED, TROUBLESHOOTING, COMPARISON, USE_CASES, RELEASE_SETUP, SMITHERY_DEPLOYMENT) on the default branch. #2 "Couldn't get it to work." (issue, closed 2025-01-29) shows the legacy `nodes`/`connections` form of `create_workflow` but is a connection error. The README documents `create_workflow` only with a `workflow` object (the packaged `src/server.ts` version), not the legacy entry points. The one open security report, #28 "[Vulnerability] Arbitrary Local Text File Read via `update_node_from_file` ..." (issue, open 2026-05-25), is about a different tool.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2421 ok (60 s); e2-0922 2048 exec / 1972 ok (300 s).
- Evidence (verbatim, trimmed):
  - `{'nodes': [{'type': '"nodes": [{{"nodes": [{"type": "sensitiveError", "name": "leakNode", "paramdters": {"throw', 'name': '', 'parameters': {}}, ...], 'connections': []}` -> JSON echo with the `type` string intact, positions `x: 100, 300, ...`, `"connections": {"main": []}`
  - `{'nodes': [{'type': '"nodes": [{"type":g]sensitiveError", ... "parameters": {{"node"t', 'name': '\U00106f72', ...}, ...]}` -> same echo
  - `{'nodes': [{'type': '"nodes": [{"type}}], "connections": [{{"input": ["/etc/passwd\\u0000"get": "s\x13\x1a>\x1blockNode"', ...}, ...]}` -> same echo, control chars JSON-escaped (`\u0013`, `\u001b`)
- Hand-check hints: weak. Only `{{` (also n8n's normal expression syntax) was echoed, inside JSON strings in plain-text content, back to the caller who sent it. The tool schema in the evidence (top-level `nodes`/`connections`, output with builder positions) matches the legacy `dist/index.js` / `src/index.cjs`, not the npm `bin` (`build/server.cjs` from `src/server.ts:97-127`, which takes a `workflow` object and posts it to n8n). I could not tell from the evidence which of the two legacy files the harness launched; they behave the same for this tool. I recommend not filing. The reproduction above was derived from the code and has not been run.
</details>
