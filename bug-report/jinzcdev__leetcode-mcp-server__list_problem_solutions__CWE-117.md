# CR/LF not neutralized in `list_problem_solutions`: `userInput` and `questionSlug` accept line breaks

**Repository:** `jinzcdev/leetcode-mcp-server` · **Tool:** `list_problem_solutions` · **Tested commit:** `126115f`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`list_problem_solutions` lists community solution articles for a problem. Both `questionSlug` and the keyword filter `userInput` are accepted with embedded `\r`, `\n` and other control characters and are sent upstream as GraphQL variables. We could not find a logger in this repository that receives either value. The only logger is pino, whose JSON output escapes CR/LF. The log-injection impact is not demonstrated, and the finding reduces to missing input validation.

## Details
`src/mcp/tools/solution-tools.ts:13-85` registers the tool. Its handler builds an options object and calls `fetchQuestionSolutionArticles` (`src/leetcode/leetcode-global-service.ts:298-348`):

```ts
const variables: any = {
    questionSlug,
    first: options?.limit || 5,
    skip: options?.skip || 0,
    orderBy: options?.orderBy || "HOT",
    userInput: options?.userInput,
    tagSlugs: options?.tagSlugs ?? []
};
return await this.leetCodeApi.graphql({ query: SOLUTION_ARTICLES_QUERY, variables })
```

The values are passed as GraphQL variables, which is safe for the query. `questionSlug` is also interpolated without encoding into `articleUrl` at line 339 (`https://leetcode.com/problems/${questionSlug}/solutions/...`). That only happens when LeetCode returns articles, so the slug must name a real problem. Neither value reaches `logger` (`src/utils/logger.ts`).

## Steps to reproduce
1. Prerequisites: Node.js 18+. No LeetCode account is needed.
2. Start the server: `npx -y @jinzcdev/leetcode-mcp-server --site global` (or from a checkout: `npm install && npm run build && node build/index.js --site global`).
3. Call the tool with:

   ```json
   {"questionSlug": "two-sum", "limit": 1, "userInput": "tofu\r\nFAKE-LOG-ENTRY"}
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
               result = await session.call_tool("list_problem_solutions", {"questionSlug": "two-sum", "limit": 1, "userInput": "tofu\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the call succeeds. No log line containing `FAKE-LOG-ENTRY` is expected on stdout or stderr.

## Expected behavior
`questionSlug` is validated as a slug (`[a-z0-9-]+`), and control characters in `userInput` are stripped or rejected.

## Actual behavior
Both values are accepted. From the fuzzing run:

```
input:  {'questionSlug': '\n\x04]\x0e\x1a', 'limit': 0.0, 'skip': 0.0, 'orderBy': 'HOT', 'userInput': '', 'tagSlugs': []}
output: {"questionSlug":"\\n\\u0004]\\u000e\\u001a","solutionArticles":{"totalNum":0,"hasNextPage":false,"articles":[]}}
```

## Impact
The LLM chooses these arguments, and prompt injection can steer them. With no log sink on this path, an attacker gains nothing beyond an odd upstream search. Low severity.

## Suggested fix
Add `.regex(/^[a-z0-9-]+$/)` to `questionSlug`. Strip `[\x00-\x1f\x7f]` from `userInput`. Build `articleUrl` with `encodeURIComponent(questionSlug)`.

## Status on the default branch
Still present at `126115f` (2026-07-12). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'questionSlug': 'two-sum', 'limit': 10, 'skip': 0, 'orderBy': 'HOT', 'userInput': 'test\nCRLF_injection', 'tagSlugs': []}` -> `{"questionSlug":"two-sum","solutionArticles":{"totalNum":933,"hasNextPage":true,"articles":[...]}}`
  - `{'questionSlug': 'twz-sum', ..., 'userInput': 'test\nCRLF_injection', ...}` -> `{"questionSlug":"twz-sum","solutionArticles":{"totalNum":0,...,"articles":[]}}`
  - `{'questionSlug': '\n\x04]\x0e\x1a', ...}` -> `{"questionSlug":"\\n\\u0004]\\u000e\\u001a",...}`
- Hand-check hints: weak, likely a false positive. No logger receives these values; pino escapes CR/LF; the oracle does not check for a sink. The unencoded `questionSlug` in `articleUrl` is a minor separate point (needs a real slug to produce articles, so control chars cannot reach it in practice). `leetcode-query` not checked (not available locally). Fold into one input-validation issue at most.
</details>
