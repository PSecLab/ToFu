# CR/LF not neutralized in `get_user_contest_ranking`: `username` accepts line breaks

**Repository:** `jinzcdev/leetcode-mcp-server` · **Tool:** `get_user_contest_ranking` · **Tested commit:** `126115f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_user_contest_ranking` returns a user's contest rating and history via `leetcode-query`. The `username` argument is accepted with embedded `\r`, `\n` and other control characters, then sent upstream and echoed back in the reply. We could not find a logger in this repository that receives `username`. The only logger is pino, whose JSON output escapes CR/LF. The log-injection impact is not demonstrated, and the finding reduces to missing input validation.

## Details
`src/mcp/tools/contest-tools.ts:13-47` (tested commit):

```ts
this.server.tool(
    "get_user_contest_ranking",
    "...",
    {
        username: z.string().describe("LeetCode username whose contest ranking to fetch"),
        attended: z.boolean().optional().default(true).describe("...")
    },
    async ({ username, attended = true }) => {
        try {
            const data = await this.leetcodeService.fetchUserContestRanking(username, attended);
            return { content: [{ type: "text",
                text: JSON.stringify({ username, contestRanking: data }) }] };
```

`fetchUserContestRanking` (`src/leetcode/leetcode-global-service.ts:154-166`) passes `username` to `leetCodeApi.user_contest_info()`. The logger in `src/utils/logger.ts` is pino with JSON output. None of its call sites (`src/index.ts`, `src/transport/streamable-http.ts`, the `similarQuestions` parse errors) receive tool arguments.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No LeetCode account is needed.
2. Start the server: `npx -y @jinzcdev/leetcode-mcp-server --site global` (or from a checkout: `npm install && npm run build && node build/index.js --site global`).
3. Call the tool with:

   ```json
   {"username": "tofu\r\nFAKE-LOG-ENTRY", "attended": true}
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
               result = await session.call_tool("get_user_contest_ranking", {"username": "tofu\r\nFAKE-LOG-ENTRY", "attended": True})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the call succeeds with an empty ranking and the username JSON-escaped in the reply. No log line with the username is expected.

## Expected behavior
A username containing control characters is rejected before the upstream request.

## Actual behavior
The value is accepted. From the fuzzing run:

```
input:  {'username': 'admin\nINFO: User logged in', 'attended': True}
output: {"username":"admin\\nINFO: User logged in","contestRanking":{"userContestRanking":null,"userContestRankingHistory":[]}}
```

## Impact
The LLM chooses `username`, and prompt injection can steer it. With no log sink on this path, an attacker gains nothing beyond an odd upstream query and an escaped echo. Low severity.

## Suggested fix
Validate `username` with a conservative pattern (for example `z.string().regex(/^[A-Za-z0-9_-]+$/)`, adjusted to LeetCode's actual username rules), shared across all tools that take a username.

## Status on the default branch
Still present at `126115f` (2026-07-12). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'username': 'admin\nINFO: User logged in', 'attended': True}` -> `{"username":"admin\\nINFO: User logged in","contestRanking":{"userContestRanking":null,...}}`
  - `{'username': '"usernam\x1b]E_]\x0f\r~toty_Ip', 'attended': False}` -> `{"username":"\\"usernam\\u001b]E_]\\u000f\\r~toty_Ip",...}`
- Hand-check hints: weak, likely a false positive. Same pattern as `get_recent_submissions`: no logger receives `username`, pino escapes CR/LF, and the oracle does not look for a sink. `leetcode-query` not available locally to check for logging. Fold into one input-validation issue if anything.
</details>
