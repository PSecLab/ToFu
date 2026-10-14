# Missing output encoding in `manage_accounts`: any `email` value is echoed raw into the Markdown "Session context" footer

**Repository:** `aaronsb/google-workspace-mcp` · **Tool:** `manage_accounts` · **Tested commit:** `ccdf507`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
When a tool call carries a string `email` argument, the dispatcher appends a Markdown "Session context" footer to the reply, and that footer contains the `email` value verbatim. The value is not checked against the configured accounts or against an email format, so any string works, including on operations that never use `email` (for example `manage_accounts` with `operation: "capabilities"`). Markup or Markdown links in `email` therefore end up inside a block that looks like server-generated status. Low severity: it only matters in a client that renders tool output as Markdown or HTML.

## Details
`src/server/handler.ts:95-107` at the tested commit:

```ts
const email = typeof params.email === 'string' ? params.email : undefined;
if (email) {
  await tracker.ensureBaseline(email, currentEpoch);
}
const result = await handler(params);
if (email) {
  tracker.refresh(email, currentEpoch);
  const ctx = await sessionContext(toolName, email, tracker);
  if (ctx) result.text += ctx;
}
```

`src/server/session/context.ts:65`:

```ts
return `\n\n---\n**Session context** (${email}):\n${lines.join('\n')}`;
```

`ensureBaseline` (`src/server/session/tracker.ts:110-130`) runs three Google calls through `Promise.allSettled` and stores the session with `initialized: true` even when all three fail, which they do for an address with no stored credential. So `sessionContext` emits the footer for any string. The `capabilities` branch of `handleAccounts` (`src/server/handlers/accounts.ts:270-319`) never reads `email`, yet the footer is still added.

## Steps to reproduce
1. Prerequisites: Node.js 22.12 or later (`engines` in `package.json`). No Google account or OAuth client is needed for this call.
2. Build the tested commit from source: `git clone https://github.com/aaronsb/google-workspace-mcp.git && cd google-workspace-mcp && git checkout ccdf507 && npm ci && npm run build`. The README's published form is `npx -y @aaronsb/google-workspace-mcp`. Point `XDG_CONFIG_HOME` and `XDG_DATA_HOME` at a temp directory so the run does not touch real config.
3. Call the tool with:

   ```json
   {"operation": "capabilities", "email": "<img src=x onerror=alert(1)> [tofu-poc](http://127.0.0.1:9/)"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["build/index.js"],
           env={"XDG_CONFIG_HOME": "/tmp/tofu-gws/config", "XDG_DATA_HOME": "/tmp/tofu-gws/data"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("manage_accounts", {
                   "operation": "capabilities",
                   "email": "<img src=x onerror=alert(1)> [tofu-poc](http://127.0.0.1:9/)",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the end of the reply text. From the code, it should be:

   ```
   ---
   **Session context** (<img src=x onerror=alert(1)> [tofu-poc](http://127.0.0.1:9/)):
   - No new unread emails since session start (0 unread, 0 today)
   - No more events today
   ```

## Expected behavior
`email` is only used when it names a configured account, and anything interpolated into the Markdown reply is escaped. An `email` on an operation that does not use it should not change the output.

## Actual behavior
The caller's string is placed into the footer unchanged. The fuzzing run's reply began with the normal capabilities text (`## Server Version ... **@aaronsb/google-workspace-mcp** v4.5.1 ...`) and the reflection was flagged further down; the stored excerpt is cut off before the footer, so the footer text above comes from the code, not from the log.

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in content the model reads (an email body, a shared doc) can steer them. In a client that renders tool output as Markdown or HTML, the injected value renders inside the server's own "Session context" block, so links or markup can look like trusted status from the server. In a plain-text client there is no effect. No data is read or sent because of this. A side effect is that each distinct `email` string adds an entry to the tracker's in-memory `sessions` map that is never removed.

## Suggested fix
Before calling `ensureBaseline` and `sessionContext`, check that `email` is one of the configured accounts (`listAccounts()`), and skip the footer otherwise. Escape Markdown and HTML special characters (`\`, `*`, `_`, `[`, `]`, `(`, `)`, `<`, `>`, `` ` ``) in any account string interpolated into reply text.

## Status on the default branch
Still present at `14c25e6` (2026-10-01). `src/server/handler.ts`, `src/server/session/context.ts` and `src/server/session/tracker.ts` are unchanged between `ccdf507` and `14c25e6`.

## Prior reports
- #86 "Session-aware ambient context: inject live activity hints into tool responses" (issue, closed 2026-03-31) and #87 "feat(session): ambient context injection into tool responses" (PR, closed 2026-03-31): the design and the PR that added the `**Session context** (<email>)` footer. Neither discusses validating or escaping `email`. Not a report of this problem.
- Documentation: SECURITY.md: "**DO NOT** open a public issue on GitHub" (security reports go by email to aaronsb@gmail.com).
- No issue or PR reports the unescaped `email` or the footer on unconfigured accounts. Searched all 63 issues and 129 pull requests (fetched 2026-10-01) and the README, SECURITY.md and docs/ on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx`, 1,024 executions, 819 successful, 60 s budget.
- Evidence (verbatim, trimmed): input `{'operation': 'capabilities', 'email': '"opera{{{{...{{tion": "remove"3 "email": "user', 'category': 'personal', 'description': '<astral-plane chars>\x00\x00', 'services': '', 'access': 'read', 'confirmWriteAccess': False}` -> output `## Server Version\n\n**@aaronsb/google-workspace-mcp** v4.5.1\n\n## Services (8 services, 101 operations) ... ## Safety Policies (1 active)\n\n- **account-access**: Refuse ` (stored excerpt truncated at 1,500 chars). Token matched: `{{`.
- Hand-check hints: weak. The only path from `email` to the `capabilities` reply is the session-context footer (handler.ts:95-107 -> context.ts:65); I traced that in code but could not see it in the stored evidence because the output excerpt is truncated. Confirm against the full log or by running step 3. ToFu matched only `{{`; the `<img>` and Markdown-link behavior is inferred from code. The reply is Markdown, which makes this a little more plausible than a plain-text echo, but it still reflects the caller's own argument back to the same client.
</details>
