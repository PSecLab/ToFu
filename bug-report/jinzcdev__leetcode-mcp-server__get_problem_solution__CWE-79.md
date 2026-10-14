# Missing output encoding in `get_problem_solution`: `topicId` is echoed back unvalidated

**Repository:** `jinzcdev/leetcode-mcp-server` · **Tool:** `get_problem_solution` · **Tested commit:** `126115f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
On the global site, `get_problem_solution` fetches a community solution article by `topicId` and returns `{"topicId": ..., "solution": ...}` as MCP text. The caller's `topicId` is accepted as any string and copied into the reply unchanged. LeetCode topic IDs are numeric, so markup or template syntax in this field is never legitimate. The reply is JSON in a plain `text` content item, so this only matters for an MCP client that renders tool text as HTML or Markdown. We rate it low severity.

## Details
`src/mcp/tools/solution-tools.ts:103-129` (tested commit):

```ts
this.server.tool(
    "get_problem_solution",
    "...",
    { topicId: z.string().describe("Solution topicId from list_problem_solutions response") },
    async ({ topicId }) => {
        try {
            const data = await this.leetcodeService.fetchSolutionArticleDetail(topicId);
            return {
                content: [{ type: "text",
                    text: JSON.stringify({ topicId, solution: data }) }]
            };
```

`topicId` has no format check. It goes to LeetCode as a GraphQL variable (`src/leetcode/leetcode-global-service.ts:356-367`), which is safe. It then comes back in the reply through `JSON.stringify`. That escapes quotes and control characters but leaves `<`, `>`, `&` and `{{` as they are. The CN variant (`slug`, lines 247-273) has the same shape.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No LeetCode account or session cookie is needed.
2. Start the server as the README describes: `npx -y @jinzcdev/leetcode-mcp-server --site global`. To test the exact commit, build from a checkout instead: `npm install && npm run build && node build/index.js --site global`.
3. Call the tool with:

   ```json
   {"topicId": "<b>tofu-poc</b>{{7*7}}"}
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
               result = await session.call_tool("get_problem_solution", {"topicId": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the reply text contains the markup unchanged, for example `{"topicId":"<b>tofu-poc</b>{{7*7}}","solution":null}`.

## Expected behavior
A `topicId` that is not a numeric ID is rejected before the request. Caller input is not echoed back, or it is encoded for the context where the reply is shown.

## Actual behavior
Any string is accepted and reflected. From the fuzzing run:

```
input:  {'topicId': '{{0{'}
output: {"topicId":"{{0{","solution":null}
```

## Impact
The LLM chooses `topicId`, and prompt injection in content it reads can steer that choice. The server returns the value only to the same client that sent it. It stores nothing and serves no other user. Harm needs a client that renders tool output as HTML, which is uncommon. Low severity, mainly a hardening issue.

## Suggested fix
Validate the ID, for example `topicId: z.string().regex(/^\d+$/)` on the global tool and a slug pattern on the CN `slug` tool. Optionally stop echoing the input field in the reply.

## Status on the default branch
Still present at `126115f` (2026-07-12). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output`, `check_invalid_json`.
- Campaigns and executions: corpus-sbx, 1 exec / 1 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'topicId': '{{'}` -> `{"topicId":"{{","solution":null}`
  - `{'topicId': '{{0{'}` -> `{"topicId":"{{0{","solution":null}`
  - `{'topicId': '"topisId"{{etc/pasDwd'}` -> `{"topicId":"\\"topisId\\"{{etc/pasDwd","solution":null}`
- Hand-check hints: weak. Only `{{` was echoed, into a JSON string inside a plain-text MCP content item. There is no HTML context in the server. `check_invalid_json` is a silent-bug alert on odd input, not a separate finding. The `<b>` payload in the repro is my substitution; I did not run it, but `JSON.stringify` does not escape `<`/`>`, so the echo should match. Probably not worth filing on its own; could be folded into one input-validation issue with the other leetcode drafts.
</details>
