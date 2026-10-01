# Missing output encoding in `delete_json_doc`: `id` is echoed raw in the confirmation message

**Repository:** `fireproof-storage/mcp-database-server` · **Tool:** `delete_json_doc` · **Tested commit:** `605dbb7`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`delete_json_doc` deletes a document from the Fireproof `json_docs` database and replies `Deleted document with ID: <id>`, with the caller's `id` inserted verbatim. The ID is not validated or escaped, so markup or control characters in it come back unchanged. This only matters if a client renders tool output as HTML or Markdown, but the fix is small.

## Details
`src/index.ts:120-132`:

```ts
case "delete_json_doc": {
  const id = String(request.params.arguments?.id);
  if (!id) {
    throw new Error("ID is required");
  }

  await db.del(id);
  return {
    content: [{
      type: "text",
      text: `Deleted document with ID: ${id}`
    }]
  };
}
```

There is no check on the ID's format and no encoding of the echoed value. Two related details: `String(undefined)` is the string `"undefined"`, so the `!id` guard never fires when `id` is missing; and the reply says "Deleted" whether or not a document with that ID existed.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. The server keeps its data in a local Fireproof database named `json_docs`; use an ID that does not exist there so nothing real is deleted.
2. Install and build as the README describes: `npm install` (the `prepare` script runs `tsc`; the README's `npm build` should be `npm run build`). Start it with `node build/index.js`.
3. Call the tool with `{"id": "<b>tofu-poc</b>"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("delete_json_doc", {"id": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
   Run the script from the repository root so `build/index.js` resolves.
4. Observe: the result text is `Deleted document with ID: <b>tofu-poc</b>`, markup unchanged.

## Expected behavior
The tool rejects IDs that do not match the expected format, or neutralises the echoed value (for example by returning it JSON-encoded), and reports whether a document was actually deleted.

## Actual behavior
The ID is echoed verbatim. Logged output from fuzzing:

```
Deleted document with ID: "{{"id"
```

## Impact
The `id` argument is chosen by the model and can be steered by prompt injection, and the echoed text goes back to the client. In clients that show tool results as plain text nothing happens. A client or UI that renders tool output as HTML or Markdown without escaping would render the caller's markup. Severity is low; this is a hardening issue in a demo server.

## Suggested fix
Validate the ID before use (for example `typeof id === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(id)`, matching the IDs Fireproof generates), fix the missing-argument check by testing the raw argument before `String(...)`, and return the ID JSON-encoded, for example `Deleted document with ID: ${JSON.stringify(id)}`. The same pattern applies to `load_json_doc` and `query_json_docs`.

## Status on the default branch
Still present at `605dbb7` (2024-12-19). The default branch has no commits after the tested one.

## Prior reports
- No issue or pull request covers this. Searched all 1 issue and 4 pull requests (fetched 2026-10-01).
- Documentation: README.md: "This is a simple example of how to use a Fireproof database in a Model Context Protocol server" (the repository presents itself as a demo; nothing documents or warns about echoing IDs or output encoding).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` (token `{{`), `check_invalid_json`.
- Campaigns and executions: corpus-sbx 1536 exec / 297 success.
- Evidence (verbatim, trimmed):
  - `{'id': '"{{"id"'}` -> `Deleted document with ID: "{{"id"`
  - `{'id': '{{{{{{{{{{{{{{{'}` -> `Deleted document with ID: {{{{{{{{{{{{{{{`
  - `{'id': '{{{{{{{{{{'}` -> `Deleted document with ID: {{{{{{{{{{`
- Hand-check hints: weak. Only template braces `{{` were echoed, into a plain-text confirmation; no HTML/Markdown rendering context exists in this server. The `<b>tofu-poc</b>` reproduction follows directly from `src/index.ts:130` but was not run. The regex in the fix assumes Fireproof IDs are URL-safe strings; I did not check Fireproof's ID alphabet, and callers can also choose their own `_id` via `save_json_doc`, so the maintainer may prefer encoding over a strict allow-list. The `String(undefined)` guard bug and the "Deleted" message for missing documents are real but minor side findings.
</details>
