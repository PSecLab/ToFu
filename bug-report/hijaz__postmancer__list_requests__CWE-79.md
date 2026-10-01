# Missing output encoding in `list_requests`: `collection_name` and stored request names are echoed raw

**Repository:** `hijaz/postmancer` · **Tool:** `list_requests` · **Tested commit:** `d71f38e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`list_requests` lists the saved requests in a collection. The caller's `collection_name` is copied verbatim into the tool result, both in the "not found" error and in the header of a successful listing. Stored request names and descriptions are printed the same way. Nothing is escaped, so markup or template syntax supplied by a caller comes back unchanged.

## Details
`src/index.ts:194-202` at `d71f38e`:

```ts
    else if (name === "list_requests") {
      const { collection_name } = ListRequestsSchema.parse(args);
      const requests = await collectionService.listRequests(collection_name);
      let output = `Requests in collection '${collection_name}':\n\n`;
```

If the collection file does not exist, `getCollection` in `src/collection-service.ts:61-62` throws ``new CollectionError(`Collection '${name}' not found`)`` with the raw name, and the shared handler at `src/index.ts:364-371` returns ``text: `Error: ${err.message}` ``. On success, `src/index.ts:207-212` appends `request.name` and `request.description` as stored by `save_request`, also unescaped. `sanitizeStorageName` (`src/storage.ts:55-59`) only protects the file path.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts or API keys. Use a throwaway storage directory: `mkdir -p /tmp/tofu-poc-postmancer`.
2. Install and start the server:
   ```
   git clone https://github.com/hijaz/postmancer.git
   cd postmancer && git checkout d71f38e14421a3ff5fa65b335f164c1a0b002d5b
   npm install && npm run build
   COLLECTIONS_PATH=/tmp/tofu-poc-postmancer node dist/src/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"collection_name": "<b>tofu-poc</b>{{7*7}}"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["dist/src/index.js"],
           env={**os.environ, "COLLECTIONS_PATH": "/tmp/tofu-poc-postmancer"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("list_requests", {"collection_name": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Error: Collection '<b>tofu-poc</b>{{7*7}}' not found`.

## Expected behavior
Collection and request names should be escaped before they are placed in the result, or the error should use a fixed message that does not repeat the input.

## Actual behavior
The name is reflected verbatim. From the fuzzing run:

```
Error: Collection 'n{{{{{{{{{{{{{{{{{{{{{{{{' not found
```

Another logged input carried NUL bytes and a quote, and those were echoed back unchanged as well.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. The stored path is slightly more relevant than the error: a request name or description saved earlier through `save_request` is printed by every later `list_requests` call. This only matters in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Escape names and descriptions before building result strings (`<`, `>`, `&`, quotes), and strip control characters such as NUL. Using fixed error messages in `getCollection` and in the error handler at `src/index.ts:364-371` would remove the reflection from the error path.

## Status on the default branch
Still present at `d71f38e` (2025-08-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); repo24-b 272,896 exec / 272,896 ok (4,200 s).
- Evidence (verbatim, trimmed): input `{'collection_name': 'n{{{{{{{{{{{{{{{{{{{{{{{{'}` -> `{'content': [{'type': 'text', 'text': "Error: Collection 'n{{{{{{{{{{{{{{{{{{{{{{{{' not found"}]}`. Two other inputs with `"collec\x00\x00...{{{{` came back verbatim, NUL bytes included.
- Hand-check hints: weak. Only `{{` was reflected, into a plain-text MCP error. Postmancer's own `{{var}}` substitution does not run on this output. The `<b>` reproduction and the stored-name path (`src/index.ts:207-212`) are derived from the code, not from a logged run. Same root cause as the other four postmancer drafts; consider one combined issue.
</details>
