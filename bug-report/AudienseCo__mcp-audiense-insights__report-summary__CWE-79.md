# Missing output encoding in `report-summary`: `report_id` is echoed raw in the error message

**Repository:** `AudienseCo/mcp-audiense-insights` · **Tool:** `report-summary` · **Tested commit:** `f18ffa6`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`report-summary` builds a summary of an Audiense intelligence report. When the report lookup fails (missing credentials, a network error, a non-2xx response or an unknown ID), the tool returns `Failed to generate summary for report ID: <id>.` with the caller's ID inserted unchanged. Markup and control characters in the ID come back as-is. The same ID is also placed into the API URL path without encoding. Both issues are low impact.

## Details
`src/index.ts:364-375`:

```ts
    async ({ report_id }) => {
        const data = await generateReportSummary(report_id);

        if (!data) {
            return {
                content: [
                    {
                        type: "text",
                        text: `Failed to generate summary for report ID: ${report_id}.`,
                    },
                ],
            };
        }
```

`generateReportSummary` returns `null` when `getReportInfo` fails (`src/reportSummary.ts:98-103`). `getReportInfo` builds the path as `` `/reports/intelligence/${report_id}` `` (`src/audienseClient.ts:94`), with no encoding. The schema only requires a string (`src/index.ts:362`).

## Steps to reproduce
1. Prerequisites: Node.js. Audiense credentials (`AUDIENSE_CLIENT_ID`, `AUDIENSE_CLIENT_SECRET`) are optional for this check. Without them the token request fails and the tool takes the error branch shown above.
2. Start the server as the README describes: `npx -y mcp-audiense-insights`. To test the tested commit, run `npm install && npm run build` in a checkout at `f18ffa6`, then `node build/index.js`.
3. Call the tool:

   ```json
   {"report_id": "<b>tofu-poc</b>"}
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
               result = await session.call_tool("report-summary", {"report_id": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. The returned text is `Failed to generate summary for report ID: <b>tofu-poc</b>.` with the markup unchanged.

## Expected behavior
The tool validates the report ID format, encodes it in the URL path, and does not echo raw markup or control characters in its messages.

## Actual behavior
The ID is echoed verbatim, including NUL bytes. From the fuzzing run:

```
input:  {'report_id': '{{{{{{{{{{{{{{\x00\x00\x00\x00\x00\x00\x00{{'}
output: Failed to generate summary for report ID: {{{{{{{{{{{{{{\x00\x00\x00\x00\x00\x00\x00{{.
```

## Impact
The model chooses the argument, and prompt injection in untrusted content can steer it. The echoed text is a plain-text MCP result. It matters only if a client renders tool output as HTML-enabled Markdown. The unencoded URL path lets an ID like `../../audience_content/<id>` reach a different Audiense endpoint, on the same host and with the same token. Low severity.

## Suggested fix
- Validate `report_id` in the zod schema against the real Audiense report ID format.
- Encode it in the path: `` `/reports/intelligence/${encodeURIComponent(report_id)}` ``. Do the same for the other ID-based paths in `src/audienseClient.ts`.
- If the error text may be rendered, return the ID JSON-encoded, or leave it out of the message.

## Status on the default branch
Still present at `f18ffa6` (2025-06-16). The tested commit is the current head of the default branch.

## Prior reports
None found. The repository has no issues; searched all 5 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The pull requests cover deployment, badges, npx support and tests; none touches the error messages or the ID handling. The README's "Security Considerations" section only covers keeping API credentials secret.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{`.
- Campaigns and executions: `corpus-sbx`, 1024 executions, 1024 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - input `{'report_id': '{{{{{{{{{{{{{{{{'}`, output `{'content': [{'type': 'text', 'text': 'Failed to generate summary for report ID: {{{{{{{{{{{{{{{{.'}]}`
  - input `{'report_id': '{{{{{{{{{{{{{{\x00\x00\x00\x00\x00\x00\x00{{'}`, output `Failed to generate summary for report ID: {{{{{{{{{{{{{{\x00\x00\x00\x00\x00\x00\x00{{.`
- Hand-check hints: **weak**. Only `{{` and NUL bytes were echoed, into a plain-text error message. The fuzz run almost certainly had no Audiense credentials, so every call hit the error branch. The unencoded path segment (`src/audienseClient.ts:94`) is the more useful point, but it is limited to the fixed API host. That comes from code reading only. Consider merging with the `get-audience-content` draft into one issue: same pattern, same fix.
</details>
