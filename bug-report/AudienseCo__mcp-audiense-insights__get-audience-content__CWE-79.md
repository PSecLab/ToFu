# Missing output encoding in `get-audience-content`: `audience_content_id` is echoed raw in the error message

**Repository:** `AudienseCo/mcp-audiense-insights` · **Tool:** `get-audience-content` · **Tested commit:** `f18ffa6`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get-audience-content` fetches content-engagement data for an Audiense audience ID. When the lookup fails (missing credentials, a network error, a non-2xx response or an unknown ID), the tool returns `No content found for audience <id>.` with the caller's ID inserted unchanged. Markup or control characters in the ID come back as-is. The same ID is also placed into the API URL path without encoding. Both issues are low impact, but they are easy to fix.

## Details
`src/index.ts:279-291`:

```ts
    async ({ audience_content_id }) => {
        const data = await getAudienceContent(audience_content_id);

        if (!data) {
            return {
                content: [
                    {
                        type: "text",
                        text: `No content found for audience ${audience_content_id}.`,
                    },
                ],
            };
        }
```

The schema only requires a string (`src/index.ts:277`). `getAudienceContent` builds the request path as `` `/audience_content/${audience_content_id}` `` (`src/audienseClient.ts:256`). `makeAudienseRequest` sends it with the server's bearer token (`src/audienseClient.ts:53-80`). Any failure on that path returns `null`, which leads to the echo above.

## Steps to reproduce
1. Prerequisites: Node.js. Audiense credentials (`AUDIENSE_CLIENT_ID`, `AUDIENSE_CLIENT_SECRET`) are optional for this check. Without them the token request fails and the tool takes the error branch, which is the code path shown above.
2. Start the server as the README describes: `npx -y mcp-audiense-insights`. To test the tested commit, run `npm install && npm run build` in a checkout at `f18ffa6`, then `node build/index.js`.
3. Call the tool:

   ```json
   {"audience_content_id": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-audiense-insights"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get-audience-content", {"audience_content_id": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `No content found for audience <b>tofu-poc</b>.` with the markup unchanged.

## Expected behavior
The tool validates the ID format before using it, encodes it in the URL path, and does not echo raw markup or control characters in its messages.

## Actual behavior
The ID is echoed verbatim. From the fuzzing run:

```
input:  {'audience_content_id': '{{{{{{'}
output: No content found for audience {{{{{{.
```

## Impact
The model chooses the argument, and prompt injection in untrusted content can steer it. The echoed text is a plain-text MCP result. It matters only if a client renders tool output as HTML-enabled Markdown. Whoever controls the argument can already influence the model directly, so the gain is small. The unencoded URL path is a slightly larger concern: an ID such as `../reports/intelligence` would make the server request a different Audiense endpoint, on the same host and with the same token. Low severity.

## Suggested fix
- Validate `audience_content_id` against the expected ID format in the zod schema (for example `z.string().regex(/^[A-Za-z0-9_-]+$/)`, adjusted to Audiense's real ID format).
- Encode the ID in the path: `` `/audience_content/${encodeURIComponent(audience_content_id)}` ``. Apply the same change to the other `/.../${id}` paths in `src/audienseClient.ts`.
- If the error text may be rendered, return the ID JSON-encoded, or leave it out of the message.

## Status on the default branch
Still present at `f18ffa6` (2025-06-16). The tested commit is the current head of the default branch.

## Prior reports
None found. The repository has no issues; searched all 5 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The pull requests cover deployment, badges, npx support and tests; none touches the error messages or the ID handling. The README's "Security Considerations" section only covers keeping API credentials secret.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). `check_reflected_output` fired on `{{`. `check_invalid_json` also fired (not relevant).
- Campaigns and executions: `corpus-sbx`, 1024 executions, 1024 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'audience_content_id': '{{{{{{'}`, output `{'content': [{'type': 'text', 'text': 'No content found for audience {{{{{{.'}]}`
  - input `{'audience_content_id': '{{{{;{'}`, output `No content found for audience {{{{;{.`
- Hand-check hints: **weak**. Only `{{` was echoed, into a plain-text error message. No rendering context is involved. The fuzz run almost certainly had no Audiense credentials, so every call took the error branch. The unencoded ID in the URL path (`src/audienseClient.ts:256`, and `:94` for report IDs) is the more useful observation. It is CWE-22/CWE-918-adjacent but limited to the fixed host `https://api.audiense.com/v1`. That comes from code reading only. I did not check whether node-fetch normalizes `..` in the path; the WHATWG URL parser it uses should.
</details>
