# Missing output encoding in `save_request`: request and collection names are echoed raw and stored for later listings

**Repository:** `hijaz/postmancer` · **Tool:** `save_request` · **Tested commit:** `d71f38e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`save_request` stores an HTTP request under a name in a collection. The success message copies `request_name` and `collection_name` verbatim into the tool result, and validation errors echo the rejected value (for example an invalid `request.method`). The raw name and description are also saved and printed again by `list_requests` and `list_collections`. Nothing is escaped, so markup, template syntax or control characters from the caller come back unchanged.

## Details
`src/index.ts:226-249` at `d71f38e`:

```ts
    else if (name === "save_request") {
      const { collection_name, request_name, request, description } = SaveRequestSchema.parse(args);
      ...
      await collectionService.saveRequest(collection_name, request_name, request, description);
      return {
        content: [{
            type: "text",
            text: `Successfully saved request '${request_name}' to collection '${collection_name}'.`
```

On a schema failure, `src/index.ts:374-383` joins the Zod messages into ``text: `Validation error: ${validationErrors}` ``. Zod's enum message includes the received value. `collectionService.saveRequest` (`src/collection-service.ts:147-153`) stores `requestName` and `description` as given, and `src/index.ts:207-212` prints them in `list_requests`. `sanitizeStorageName` (`src/storage.ts:55-59`) is applied to the file path only.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. No accounts or API keys. Use a throwaway storage directory: `mkdir -p /tmp/tofu-poc-postmancer`.
2. Install and start the server:
   ```
   git clone https://github.com/hijaz/postmancer.git
   cd postmancer && git checkout d71f38e14421a3ff5fa65b335f164c1a0b002d5b
   npm install && npm run build
   COLLECTIONS_PATH=/tmp/tofu-poc-postmancer node dist/src/index.js
   ```
3. Call the tool with these arguments. The request is only saved, not sent:
   ```json
   {"collection_name": "tofu-poc", "request_name": "<b>tofu-poc</b>{{7*7}}", "request": {"url": "http://127.0.0.1:8099/tofu-poc", "method": "GET"}, "description": "tofu-poc"}
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
               result = await session.call_tool("save_request", {
                   "collection_name": "tofu-poc",
                   "request_name": "<b>tofu-poc</b>{{7*7}}",
                   "request": {"url": "http://127.0.0.1:8099/tofu-poc", "method": "GET"},
                   "description": "tofu-poc"})
               print(result)
               print(await session.call_tool("list_requests", {"collection_name": "tofu-poc"}))

   asyncio.run(main())
   ```
4. What to observe: the first result is `Successfully saved request '<b>tofu-poc</b>{{7*7}}' to collection 'tofu-poc'.` and the `list_requests` result contains `- <b>tofu-poc</b>{{7*7}}: tofu-poc`. Sending `"method": "<b>tofu-poc</b>"` instead returns `Validation error: request.method: Invalid enum value. Expected 'GET' | ... , received '<b>tofu-poc</b>'`.

## Expected behavior
Names, descriptions and rejected values should be escaped before they are placed in a result, and control characters should be stripped or rejected at input.

## Actual behavior
Input is reflected verbatim. From the fuzzing runs (trimmed):

```
Validation error: request.method: Invalid enum value. Expected 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS', received 'G{{{{{{{{...{{{{ET'
```

```
Successfully saved request '{{{{{{{{...{{{{SRF tes' to collection '"col\x1bl\x1c\x0b\x0fon_nme": ...'.
```

The second excerpt also shows an ESC byte (`\x1b`) and other control characters returned unchanged.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. Because the name and description are stored, a value injected once is printed by every later `list_requests` call. This only matters in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is cosmetic, so severity is low.

## Suggested fix
Validate names at input (for example restrict `collection_name` and `request_name` to a safe character set and length, which `sanitizeStorageName` already implies for file names), and escape names, descriptions and Zod error values before placing them in result strings.

## Status on the default branch
Still present at `d71f38e` (2025-08-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: repo24-b, three runs: 254,464 exec / 254,412 ok; 187,904 / 187,886; 139,264 / 138,339 (4,200 s each).
- Evidence (verbatim, trimmed): (1) input with `request.method: 'G{{{{...{{{ET'` -> `Validation error: request.method: Invalid enum value. Expected 'GET' | ... received 'G{{{{...{{{ET'`. (2) input `{'collection_name': '"col\x1bl\x1c\x0b\x0fon_nme": ... "S{{{{{', 'request_name': '{{{{...{{{SRF tes', 'request': {'url': 'htt://8.01:8500', 'method': 'GET', ...}, 'description': ''}` -> `Successfully saved request '{{{{...SRF tes' to collection '"col\x1bl\x1c\x0b\x0fon_nme": ...'.`
- Hand-check hints: weak. Only `{{` was reflected, into plain-text MCP results. The `<b>` payload, the stored echo through `list_requests` and the enum-error variant with `<b>` are derived from the code, not from a logged run. The ESC byte echo could matter for clients that print results to a terminal, but that is a different weakness (CWE-150) and was not tested. The fuzzer's inputs mention SSRF, but `save_request` does not send the request. Side note, not a security finding: distinct collection names that sanitize to the same file name (e.g. `a/b` and `a_b`) share one file. Same root cause as the other four postmancer drafts; consider one combined issue.
</details>
