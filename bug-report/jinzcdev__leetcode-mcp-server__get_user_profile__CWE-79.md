# Missing output encoding in `get_user_profile`: `username` is echoed back unvalidated

**Repository:** `jinzcdev/leetcode-mcp-server` · **Tool:** `get_user_profile` · **Tested commit:** `126115f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_user_profile` looks up a public LeetCode profile and returns `{"username": ..., "profile": ...}` as MCP text. The `username` argument accepts any string, including markup, template braces and control characters such as DEL (`\x7f`), and it is copied into the reply unchanged. The reply is JSON in a plain `text` content item, so this only matters for a client that renders tool text as HTML or Markdown. We rate it low severity.

## Details
`src/mcp/tools/user-tools.ts:14-39` (tested commit). The tool is registered for both sites:

```ts
this.server.tool(
    "get_user_profile",
    "...",
    { username: z.string().describe("LeetCode username (case-sensitive). ...") },
    async ({ username }) => {
        const data = await this.leetcodeService.fetchUserProfile(username);
        return {
            content: [{ type: "text",
                text: JSON.stringify({ username: username, profile: data }) }]
        };
    }
);
```

`username` has no format check. `JSON.stringify` escapes quotes and C0 control characters but leaves `<`, `>`, `&`, `{{` and `\x7f` as they are. This handler also has no `try`/`catch`, unlike the other user tools, so upstream errors surface as protocol errors.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No LeetCode account is needed.
2. Start the server: `npx -y @jinzcdev/leetcode-mcp-server --site global` (or from a checkout: `npm install && npm run build && node build/index.js --site global`).
3. Call the tool with:

   ```json
   {"username": "<b>tofu-poc</b>{{7*7}}"}
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
               result = await session.call_tool("get_user_profile", {"username": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the reply begins with `{"username":"<b>tofu-poc</b>{{7*7}}","profile":{...}}`, with the markup unchanged.

## Expected behavior
A username that does not match LeetCode's username format is rejected before the request. Caller input is not echoed back, or it is encoded for the place where it is shown.

## Actual behavior
Any string is accepted and reflected. From the fuzzing run (DEL bytes shown as `\x7f`):

```
input:  {'username': '\x7f\x7f\x7f\x7f\x7f\x7f\x7f{{"username"gg: "'}
output: {"username":"\x7f\x7f\x7f\x7f\x7f\x7f\x7f{{\\"username\\"gg: \\"","profile":{"allQuestionsCount":[...],"matchedUser":null,"recentSubmissionList":[]}}
```

## Impact
The LLM chooses `username`, and prompt injection can steer it. The value is reflected only to the same client, with no storage and no other viewers. Harm needs a client that renders tool output as HTML. Low severity, mainly hardening.

## Suggested fix
Validate `username` (for example `z.string().regex(/^[A-Za-z0-9_-]+$/)`, adjusted to LeetCode's actual rules). Optionally drop the echoed field, since `profile.username` already carries the canonical name when the user exists.

## Status on the default branch
Still present at `126115f` (2026-07-12). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 7 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` only.
- Campaigns and executions: corpus-sbx, 1 exec / 1 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'username': '\x7f...\x7f{{"username"gg: "'}` -> `{"username":"\x7f...\x7f{{\\"username\\"gg: \\"","profile":{...,"matchedUser":null,...}}`
  - `{'username': '\x7f...\x7f{{`````"username"gg: "'}` -> same shape
  - `{'username': '\x7f...\x7f{{"`````username"gg: "'}` -> same shape
- Hand-check hints: weak. Only `{{` was echoed, into a JSON string in a plain-text content item. No HTML context exists in the server. The `<b>` payload is my substitution and was not run. The missing try/catch in this handler is a small separate robustness point. Probably not worth filing alone.
</details>
