# Missing output encoding in `create_element`: custom `id` is accepted as free text and echoed back

**Repository:** `yctimlin/mcp_excalidraw` · **Tool:** `create_element` · **Tested commit:** `713706e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create_element` adds an element to the Excalidraw canvas and returns the stored element as JSON. The optional custom `id` is any string, with no format check, and is stored and echoed back unchanged. The echo is inside `JSON.stringify` output in a plain-text MCP reply, so this is only a concern if a client renders tool output as HTML or Markdown. Low severity.

## Details
`src/core/mcp-dispatch.ts:132-157` (tested commit):

```ts
case 'create_element': {
  const params = ElementSchema.parse(args);          // id: z.string().optional()  (line 50)
  ...
  const excalidrawElement = prepareElement(params);   // id = customId || generateId()
  const canvasElement = await createElementOnCanvas(excalidrawElement);
  ...
  return { content: [{ type: 'text',
    text: `Element created successfully!\n\n${JSON.stringify(canvasElement, null, 2)}\n\n✅ Synced to canvas` }] };
}
```

`prepareElement` (`src/core/normalize.ts:57-70`) keeps the caller's `id` as is. JSON encoding escapes quotes and control characters but not `<`, `>` or `${`.

A related point: the same `id` is later placed unencoded into canvas API URLs for update and delete (`src/core/canvas-client.ts:42` and `:51`, `${EXPRESS_SERVER_URL}/api/elements/${data.id}`), so an `id` containing `/`, `?` or `#` would address a different canvas route.

## Steps to reproduce
1. Prerequisites: Node.js 18+. The MCP server auto-starts the canvas on `http://127.0.0.1:3000`.
2. Start the server as the README describes: `npx -y mcp-excalidraw-server` (or from source: `npm ci && npm run build && node dist/index.js`).
3. Call the tool with:

   ```json
   {"id": "<img src=x onerror=alert(1)>", "type": "rectangle", "x": 0, "y": 0, "width": 10, "height": 10}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-excalidraw-server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_element", {
                   "id": "<img src=x onerror=alert(1)>", "type": "rectangle",
                   "x": 0, "y": 0, "width": 10, "height": 10,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the `id` returned unchanged in the `"id"` field of the reply.

## Expected behavior
Custom IDs are restricted to a safe character set (for example `^[A-Za-z0-9_-]{1,64}$`) and rejected otherwise.

## Actual behavior
The value is stored and echoed. From the fuzzing run:

```
Element created successfully!

{
  "id": "${\": 10 : 2{\".10 \"{.\".i",
  "type": "rectangle",
  ...
}

✅ Synced to canvas
```

## Impact
The LLM chooses `id`, and prompt injection can steer it. The echo goes back to the same LLM and user as JSON text. In a client that renders tool output as HTML it could inject markup into the chat view; in a plain-text client there is no effect. The Excalidraw canvas does not display element IDs, so we found no rendering sink there. Low severity.

## Suggested fix
Validate custom IDs in `ElementSchema` (`id: z.string().regex(/^[A-Za-z0-9_-]{1,64}$/).optional()`), apply the same rule to `startElementId`/`endElementId`, and `encodeURIComponent(data.id)` when building canvas API URLs.

## Status on the default branch
Still present at `713706e` (2026-09-08). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports this. Searched all 48 issues and 61 pull requests (fetched 2026-10-01); none asks for custom `id` validation or URL-encoding of `id` in canvas API paths.
- #74 "security: authentication, path traversal, prompt injection, and hardening fixes" (PR, open 2026-04-16): audit-driven hardening PR (API token, CORS, CSP, `validateElement()` on `import_scene` and `/api/elements/sync`); it does not restrict custom IDs in `create_element` and is not merged (`src/server.ts` on the default branch still has `app.use(cors())`).
- #39 "Security audit: 7 vulnerabilities (2 critical, 3 high, 2 medium)" (issue, open 2026-02-08): the readable part of the body (first 4000 characters) covers unauthenticated endpoints and wildcard CORS, not element IDs.
- #34 "Fix: Batch endpoint now respects element IDs from MCP server" (PR, closed 2026-01-24): made the batch endpoint keep caller IDs (`params.id || generateId()`); functional sync fix, no validation added.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 1536 exec / 1529 ok (60 s budget). Not seen in e2-0922.
- Evidence (verbatim, trimmed):
  - input `{'id': '${": 10 : 2{".10 "{.".i', 'type': 'rectangle', 'x': 0.0, ...}` -> `Element created successfully!\n\n{\n  "id": "${\\": 10 : 2{\\".10 \\"{.\\".i", ...`
  - Two more variants of the same `${` id, same result.
- Hand-check hints: weak. Only the `${` token was echoed, inside JSON (quotes were escaped), in a plain-text MCP reply. The `<img>` payload in the repro is my substitution and was not run. No HTML sink for element IDs found in `frontend/src` (no `innerHTML`/`dangerouslySetInnerHTML`). The unencoded `id` in canvas URL paths is real per source but not exercised by ToFu. Probably file only as an ID-validation hardening note, if at all.
</details>
