# CR/LF not neutralized in `mcp_kanban_comment_manager`: `id` accepts line breaks (flagged as CWE-117; no log sink found)

**Repository:** `bradrisse/kanban-mcp` · **Tool:** `mcp_kanban_comment_manager` · **Tested commit:** `4aead19`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`mcp_kanban_comment_manager` lists, creates, reads, updates and deletes Planka card comments. Our fuzzer sent `get_all` calls whose `id` contained carriage returns and flagged them because the tool returned without error. `get_all` never reads `id`, and the comment code path has no logging, so the log-injection impact is not demonstrated. The finding reduces to missing format validation of `id` and `cardId`, which are also placed into Planka API paths without URL encoding.

## Details
`index.ts:671-676` and `operations/comments.ts:130-132, 159-162` (tested commit):

```ts
// index.ts
      case "get_all":
        if (!args.cardId)
          throw new Error("cardId is required for get_all action");
        result = await comments.getComments(args.cardId);
        break;
// operations/comments.ts
export async function getComments(cardId: string) {
    try {
        const response = await plankaRequest(`/api/cards/${cardId}/actions`);
        ...
    } catch (error) {
        // If all else fails, return an empty array
        return [];
    }
}
```

There is no `console.*` call or file write in `index.ts:657-713` or in `operations/comments.ts`. `getComments` also swallows every error, including a missing Planka configuration, and returns `[]`, which is why the fuzzed calls looked successful. `id` and `cardId` are only checked for presence. They are interpolated into request paths (`operations/comments.ts:104, 132, 299, 325`) without `encodeURIComponent`.

## Steps to reproduce
1. Prerequisites: Node.js 18+, a running Planka instance (the README's `npm run up` starts one with Docker), and `PLANKA_BASE_URL`, `PLANKA_AGENT_EMAIL`, `PLANKA_AGENT_PASSWORD` for an agent account. Without Planka the call still returns `[]`.
2. Install and build: `git clone https://github.com/bradrisse/kanban-mcp.git && cd kanban-mcp && npm install && npm run build`, then the server is `node dist/index.js`.
3. Call the tool with (use a real card id from your board):

   ```json
   {"action": "get_all", "id": "comment\r\nFAKE-LOG-ENTRY", "cardId": "<card id>"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       env = {**os.environ, "PLANKA_BASE_URL": "http://localhost:3333",
              "PLANKA_AGENT_EMAIL": "<agent email>", "PLANKA_AGENT_PASSWORD": "<agent password>"}
       server = StdioServerParameters(command="node", args=["dist/index.js"], env=env)
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("mcp_kanban_comment_manager", {"action": "get_all", "id": "comment\r\nFAKE-LOG-ENTRY", "cardId": "<card id>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the value is not rejected and that the result is the card's comments (or `[]`). Check the server's stderr: no line containing `FAKE-LOG-ENTRY` is expected.

## Expected behavior
`id` and `cardId` are validated against Planka's ID format and rejected otherwise. Errors from Planka are reported rather than turned into an empty list.

## Actual behavior
The value is accepted and ignored. In the fuzzing run, without Planka credentials, the tool returned:

```
[]
```

The value never reached a log in that run.

## Impact
The LLM chooses the arguments, and prompt injection can steer it. With no logger on this path, line breaks in `id` have no effect. The unencoded path interpolation is the more relevant gap: a crafted `cardId` such as `../boards/<id>` is normalized by the URL parser and sends the agent's authenticated request to a different Planka API path than intended. Low severity, limited to what the agent account can already do.

## Suggested fix
Validate `id` and `cardId` with a strict pattern in the tool schema (for example `z.string().regex(/^\d+$/)` if Planka IDs are always numeric strings), and build request paths with `encodeURIComponent()`. Return an error from `getComments` instead of `[]` when the request fails.

## Status on the default branch
Still present at `4aead19` (2025-03-25). The tested commit is the current default branch head.

## Prior reports
- #10 "Fix: Planka v2 (2.x) API route compatibility" (PR, open 2026-06-20): rewrites the comment routes this draft cites (`GET /api/cards/:id/actions` becomes `GET /api/cards/:id/comments`, and the update/delete routes change too). Its body says nothing about validating or URL-encoding `id`/`cardId`, or about the error swallowing in `getComments`. Not a fix; line numbers here would shift if it merges.
- Documentation: none relevant. README.md and wiki/*.md say nothing about ID validation, logging of tool input, or untrusted input.

Searched all 4 issues and 6 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only ("Silent Bug Alert": input flagged, tool did not raise).
- Campaigns and executions: corpus-sbx 3584 exec / 619 ok (60 s); repo24-b 263168 exec / 11720 ok (4200 s).
- Evidence (verbatim, trimmed):
  - `{'action': 'get_all', 'id': '"action": "create", "id": "com\r\r\r\r\r\r\r\r\rment5", "cardId": "card999", ', 'cardId': '整瑸㨢∠潛橢ɥȂ瑣传橢', 'text': ''}` -> `[]`
  - two more near-identical inputs (`mco\r...`, `mco~\r...`) -> `[]`
- Hand-check hints: weak, false positive for CWE-117. `check_log_injection` fires on `\r`/`\n` in the input when the tool does not raise; it does not look for a log sink. `get_all` ignores `id`; the comment path has no logging; `getComments` swallows the auth error and returns `[]`. The `../` path-normalization claim follows from WHATWG URL parsing in `plankaRequest` (`common/utils.ts:112`), not run. The repo also commits a `.env` at the root with Planka and Postgres settings (values not reviewed). Probably not worth filing as log injection.
</details>
