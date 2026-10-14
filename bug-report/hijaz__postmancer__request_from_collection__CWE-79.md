# Missing output encoding in `request_from_collection`: `collection_name` and `request_name` are echoed raw

**Repository:** `hijaz/postmancer` · **Tool:** `request_from_collection` · **Tested commit:** `d71f38e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`request_from_collection` loads a saved request and either shows it or runs it. The caller's `collection_name` and `request_name` are copied verbatim into the tool result: in the "not found" errors and in the header of a successful result. Nothing is escaped, so markup or template syntax supplied by the caller comes back unchanged.

## Details
`src/index.ts:254-268` at `d71f38e`:

```ts
    else if (name === "request_from_collection") {
      const { collection_name, request_name, environment_name, execute } = RequestFromCollectionSchema.parse(args);
      const request = await collectionService.getRequest(collection_name, request_name);
      if (!execute) {
        const requestJSON = JSON.stringify(request, null, 2);
        return {
          content: [{
              type: "text",
              text: `Request '${request_name}' from collection '${collection_name}':\n\n${requestJSON}`
```

`getRequest` calls `getCollection`, which throws ``new CollectionError(`Collection '${name}' not found`)`` (`src/collection-service.ts:61-62`). A missing request throws ``Request '${requestName}' not found in collection '${collectionName}'`` (`src/collection-service.ts:184-185`). The shared handler at `src/index.ts:364-371` returns ``text: `Error: ${err.message}` ``. The executed path at `src/index.ts:295` builds the same header. `sanitizeStorageName` (`src/storage.ts:55-59`) only protects the file path.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts or API keys. Use a throwaway storage directory: `mkdir -p /tmp/tofu-poc-postmancer`.
2. Install and start the server:
   ```
   git clone https://github.com/hijaz/postmancer.git
   cd postmancer && git checkout d71f38e14421a3ff5fa65b335f164c1a0b002d5b
   npm install && npm run build
   COLLECTIONS_PATH=/tmp/tofu-poc-postmancer node dist/src/index.js
   ```
3. Call the tool with these arguments. `execute` is `false`, so no HTTP request is sent:
   ```json
   {"collection_name": "<b>tofu-poc</b>{{7*7}}", "request_name": "tofu-poc", "execute": false}
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
               result = await session.call_tool("request_from_collection", {
                   "collection_name": "<b>tofu-poc</b>{{7*7}}",
                   "request_name": "tofu-poc",
                   "execute": False})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Error: Collection '<b>tofu-poc</b>{{7*7}}' not found`.

## Expected behavior
Collection and request names should be escaped before they are placed in the result, or the errors should use fixed messages that do not repeat the input.

## Actual behavior
The name is reflected verbatim. From the fuzzing run (input trimmed):

```
Error: Collection '{{"colle[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[' not found
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls either name controls part of the result text. This only matters in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Escape `collection_name` and `request_name` (`<`, `>`, `&`, quotes, control characters) before they go into result strings, or drop them from the error messages in `src/collection-service.ts`. A single escaping helper applied in the error handler at `src/index.ts:364-371` and in the success headers would cover all postmancer tools that echo names.

## Status on the default branch
Still present at `d71f38e` (2025-08-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); repo24-b 282,624 exec / 282,624 ok and 216,576 exec / 216,576 ok (4,200 s each).
- Evidence (verbatim, trimmed): input `{'collection_name': '{{"colle[[[[...[[[', 'request_name': '[[[[...[[[ction', 'environment_name': '', 'execute': False}` -> `{'content': [{'type': 'text', 'text': 'Error: Collection \'{{"colle[[[[...[[[\' not found'}]}`. Two more inputs of the same shape gave the same kind of output.
- Hand-check hints: weak. Only `{{` was reflected, into a plain-text MCP error. Postmancer's `{{var}}` substitution (`src/storage.ts:230-240`) runs on the saved request's URL, headers, body and query params when `environment_name` is set, not on the names echoed here, so the braces are inert. The `<b>` reproduction is derived from the code. Unrelated to this class and not checked further: with `execute: true` and an environment, decrypted secret variables are substituted into the outgoing request (`src/environment-service.ts:324-350`), which is by design but worth a look. Same root cause as the other four postmancer drafts; consider one combined issue.
</details>
