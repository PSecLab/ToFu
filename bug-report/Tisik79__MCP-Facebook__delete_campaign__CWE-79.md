# Missing output encoding in `delete_campaign`: `campaignId` is echoed raw into the tool reply

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `delete_campaign` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`delete_campaign` deletes a campaign by ID and reports the result. The caller's `campaignId` is inserted verbatim into the reply text on both the success and the error path, with no format check and no encoding. The reply is plain MCP text, so this only matters if a client renders tool output as Markdown or HTML. Low severity.

## Details
`src/index.ts:233-244` (tested commit):

```ts
server.tool(
  'delete_campaign',
  { campaignId: z.string().describe('ID kampaně k odstranění') },
  async ({ campaignId }) => {
    const result = await campaignTools.deleteCampaign(campaignId);
    return {
      content: [{ type: 'text', text: result.success
        ? `Kampaň (ID: ${campaignId}) byla úspěšně odstraněna!\n\n${result.message || ''}`
        : `Chyba při odstraňování kampaně (ID: ${campaignId}): ${result.message}` }]
    };
  }
);
```

`campaignId` is any string (`z.string()`), not a numeric Graph ID. It is passed to `new Campaign(campaignId).delete([])` in `src/tools/campaign-tools.ts:276-295` and interpolated into the reply. The same pattern appears in `update_campaign` just above.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No account is needed: the error path echoes the ID too.
2. Install and build: `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
3. Call the tool with:

   ```json
   {"campaignId": "<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("delete_campaign",
                   {"campaignId": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the markup returned unchanged inside `(ID: ...)` in the reply text.

## Expected behavior
The tool rejects IDs that are not numeric Graph IDs before calling the SDK, or at least escapes the value before putting it in the reply.

## Actual behavior
The value is echoed as given. From the fuzzing run (no account connected):

```
Chyba při odstraňování kampaně (ID: {{{{{{{{{{{{{{{): Chyba při odstraňování kampaně: Campaign does not yet have an
        associated api object. ...
```

## Impact
The LLM chooses `campaignId`, and prompt injection can steer it. The echoed value returns to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup or links into the chat view. In a plain-text client there is no effect. Low severity.

## Suggested fix
Validate `campaignId` with `z.string().regex(/^\d+$/)` (Graph object IDs are numeric) for this and the other ID parameters. If free text must be echoed, escape it for the rendering context.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok (60 s budget). Not seen in e2-0922.
- Evidence (verbatim, trimmed):
  - `{'campaignId': '{{{{{{{{{{{{{{{'}` -> `Chyba při odstraňování kampaně (ID: {{{{{{{{{{{{{{{): ... Campaign does not yet have an associated api object ...`
  - `{'campaignId': '{{{{{{{{{{{\x7f\x7f{{'}` -> same, echoed with the DEL bytes.
  - `{'campaignId': '{{{{{{\x00\x00\x00\x00{\x7f\x7f{{'}` -> same, echoed with NUL bytes.
- Hand-check hints: weak. Only `{{` template braces were echoed, into a plain-text MCP reply. The echo itself is real (confirmed at `src/index.ts:239-242`); the `<img>` payload in the repro is my substitution and was not run. No known client renders this reply as HTML. Probably fold into a general "validate Graph IDs" hardening note rather than file as XSS.
</details>
