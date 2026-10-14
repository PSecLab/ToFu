# CR/LF not neutralized in `get_recent_submissions`: `username` accepts line breaks

**Repository:** `jinzcdev/leetcode-mcp-server` · **Tool:** `get_recent_submissions` · **Tested commit:** `126115f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_recent_submissions` (global site only) looks up a user's recent submissions through `leetcode-query` and returns `{"username": ..., "submissions": ...}`. The `username` argument is accepted with embedded `\r`, `\n` and other control characters, then sent upstream and echoed back. We could not find a logger in this repository that receives `username`. The server's only logger is pino, which writes JSON and so escapes CR/LF. The log-injection impact is not demonstrated, and the finding reduces to missing input validation.

## Details
`src/mcp/tools/user-tools.ts:44-78` (tested commit):

```ts
this.server.tool(
    "get_recent_submissions",
    "...",
    {
        username: z.string().describe("LeetCode username whose public recent submissions to fetch"),
        limit: z.number().optional().default(10).describe("...")
    },
    async ({ username, limit }) => {
        try {
            const data = await this.leetcodeService.fetchUserRecentSubmissions(username, limit);
            return { content: [{ type: "text",
                text: JSON.stringify({ username, submissions: data }) }] };
```

`fetchUserRecentSubmissions` (`src/leetcode/leetcode-global-service.ts:95-100`) passes `username` straight to `leetCodeApi.recent_submissions()`. The logger in `src/utils/logger.ts` is pino with JSON output. Its call sites (`src/index.ts`, `src/transport/streamable-http.ts`, the `similarQuestions` parse errors in the services) never receive tool arguments.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No LeetCode account is needed.
2. Start the server: `npx -y @jinzcdev/leetcode-mcp-server --site global` (or from a checkout: `npm install && npm run build && node build/index.js --site global`).
3. Call the tool with:

   ```json
   {"username": "tofu\r\nFAKE-LOG-ENTRY", "limit": 5}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@jinzcdev/leetcode-mcp-server", "--site", "global"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_recent_submissions", {"username": "tofu\r\nFAKE-LOG-ENTRY", "limit": 5})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the call succeeds and the reply contains the username JSON-escaped (`"tofu\r\nFAKE-LOG-ENTRY"`). No log line with the username is expected on stdout or stderr.

## Expected behavior
A username containing control characters is rejected, since it cannot be a valid LeetCode username.

## Actual behavior
The value is accepted and sent upstream. From the fuzzing run:

```
input:  {'username': 'testuser\nInjectedLogEntry', 'limit': 5}
output: {"username":"testuser\\nInjectedLogEntry","submissions":[]}
```

## Impact
The LLM chooses `username`, and prompt injection can steer it. With no log sink on this path, an attacker gains nothing beyond an odd upstream query and an escaped echo in the reply. Low severity.

## Suggested fix
Validate `username` with a conservative pattern (for example `z.string().regex(/^[A-Za-z0-9_-]+$/)`, adjusted to LeetCode's actual username rules). Apply the same check to the other `username` parameters in `user-tools.ts` and `contest-tools.ts`.

## Status on the default branch
Still present at `126115f` (2026-07-12). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'username': 'testuser\nInjectedLogEntry', 'limit': 5}` -> `{"username":"testuser\\nInjectedLogEntry","submissions":[]}`
  - `{'username': '"ucername": "/eername": \\u0000", "limit"F\n\x0c', 'limit': 0.0}` -> `{"username":"...\\n\\f","submissions":[]}`
  - `{'username': '"us)\r0}ername": "%s%s%\x08Z\x0cZ\x0c]]E 200000)', 'limit': 0.0}` -> `{"username":"...\\r0}...","submissions":[]}`
- Hand-check hints: weak, likely a false positive. `check_log_injection` fires on CR/LF in the input when the tool does not raise; it does not confirm a log sink. I found no logger receiving `username` in this repo, and pino's JSON output escapes CR/LF anyway. I could not check the `leetcode-query` dependency (not vendored, no node_modules); verify it does not log the username if this is filed. Only one execution per campaign. Probably not worth filing on its own.
</details>
