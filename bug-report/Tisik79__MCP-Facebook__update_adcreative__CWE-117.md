# CR/LF not neutralized in `update_adcreative`: `name` accepts line breaks and `creative_id` is not validated

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `update_adcreative` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`update_adcreative` renames an ad creative or changes its status. `name` is accepted with embedded `\r`/`\n` and sent to the Graph API and echoed in the reply unchanged. `creative_id` is any string and is placed unencoded into the Graph API URL path. We did not find a logger that receives these values, so the log-injection impact is not demonstrated; this is missing input validation.

## Details
`src/tools/ad-tools.ts:137-170` (tested commit):

```ts
if (!creativeId) throw new Error('Chybí creative_id.');
const params: any = {};
if (updates.name) params.name = updates.name;
if (updates.status) params.status = updates.status;
...
const token = getActiveToken();
if (!token) throw new Error('Chybí access token (přihlas se k Facebooku).');

const body = new URLSearchParams({ ...params, access_token: token });
const res = await fetch(`https://graph.facebook.com/${GRAPH_VERSION}/${creativeId}`, { method: 'POST', body });
...
return { success: true, creativeId, message: `Kreativa ${creativeId} upravena. Název: "${v.name}", status: ${v.status}.` };
```

The schema in `src/index.ts:1099-1110` declares `creative_id`, `name` and `status` as plain `z.string()`. `status` is documented as `ACTIVE`/`DELETED` but is not restricted to those values. Because `creative_id` is not encoded, a value containing `/`, `?` or `#` changes which Graph endpoint receives the authenticated POST (the host stays `graph.facebook.com`).

## Steps to reproduce
1. Prerequisites: Node.js 18+, a connected account with an ad creative (`node dist/index.js login`). Without a token the call stops at `getActiveToken()`.
2. Install and build: `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
3. Call the tool with (replace the ID with one of your creatives):

   ```json
   {"creative_id": "1234567890", "name": "test\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("update_adcreative",
                   {"creative_id": "1234567890", "name": "test\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the name is not rejected locally and is sent to Meta with the line break. Check stderr: no log line with the name is expected.

## Expected behavior
`name` is rejected or stripped of control characters, `status` is limited to the allowed enum, and `creative_id` must be a numeric Graph ID.

## Actual behavior
All values are accepted. In the fuzzing run without a token:

```
Chyba: Chyba při úpravě kreativy: Chybí access token (přihlas se k Facebooku).
```

## Impact
The LLM chooses these arguments, and prompt injection can steer it. Without a log sink the direct effect is a creative with a multi-line name in the user's own account and a raw line break in the reply. The unencoded `creative_id` is the more useful hardening point, since it lets a steered call POST `name`/`status` with the user's token to a different Graph path. Low severity overall.

## Suggested fix
- `creative_id: z.string().regex(/^\d+$/)` (or `encodeURIComponent` it in the URL).
- `status: z.enum(['ACTIVE', 'PAUSED', 'DELETED', 'ARCHIVED'])` per the Graph API docs.
- Strip or reject `[\x00-\x1f\x7f]` in `name`.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); triggered `check_log_injection`, `check_invalid_json`.
- Campaigns and executions: corpus-sbx 2048 exec / 2048 ok; e2-0922 1536 exec / 1536 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'creative_id': 'log_injection', 'name': 'test\nCRITICAL: system failure', 'status': 'DELETED'}` -> `Chyba: Chyba při úpravě kreativy: Chybí access token (přihlas se k Facebooku).`
  - `{'creative_id': '\x7f\x7f\x7f\x01\x00\x00M\x04]\r\x1e{enat\x7f\x7fid', 'name': '', 'status': ''}` -> `Chyba: ... Nebyly zadány žádné změny (name / status)...`
- Hand-check hints: weak, likely a false positive for log injection. `check_log_injection` fires on any CR/LF in the input when no exception is raised; every evidence call was rejected (missing token, or no changes). No `console.*` or file write receives `name` or `creative_id` in `updateAdCreative` or `formatFbError`. The unencoded `creative_id` in the Graph path is real per source but was not exercised. The allowed `status` values in the fix are from my knowledge of the Graph API, not verified against current Meta docs.
</details>
