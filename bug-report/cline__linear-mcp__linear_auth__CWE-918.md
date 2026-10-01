# `linear_auth` accepts any string as `redirectUri` (reported as SSRF; the server never requests it)

**Repository:** `cline/linear-mcp` · **Tool:** `linear_auth` · **Tested commit:** `023ac90`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF) (as flagged by the fuzzer; not confirmed)

## Summary
`linear_auth` starts the Linear OAuth flow. It takes `clientId`, `clientSecret` and `redirectUri` as tool arguments and returns an authorization link to `https://linear.app/oauth/authorize`. Our fuzzer flagged it as SSRF because values such as `http://localhost:8080`, `../../../../etc/passwd` and a string with a NUL byte were accepted. Reading the code, the server never makes a request to `redirectUri`. It only URL-encodes the value into the link it returns, and the later token exchange goes to a fixed host. So this is not SSRF. What remains is missing validation, plus OAuth client settings that come from the model instead of from server configuration.

## Details
`src/auth.ts:59-69` builds the link with `URLSearchParams`, which encodes every value:

```ts
    const params = new URLSearchParams({
      client_id: this.config.clientId,
      redirect_uri: this.config.redirectUri,
      response_type: 'code',
      scope: 'read,write,issues:create,offline_access',
      actor: 'application', // Enable OAuth Actor Authorization
      state: this.generateState(),
      access_type: 'offline',
    });

    return `${LinearAuth.OAUTH_AUTH_URL}/authorize?${params.toString()}`;
```

`OAUTH_AUTH_URL` and `OAUTH_TOKEN_URL` are constants (`src/auth.ts:43-44`). The only `fetch` calls in the file (`:90`, `:138`) go to `https://api.linear.app/oauth/token`. `redirectUri` is sent there as a form field. The handler (`src/features/auth/handlers/auth.handler.ts:18-37`) only checks that the three arguments are present.

Two related observations:
- `clientSecret` is a tool argument (`src/core/types/tool.types.ts:17-20`), so the OAuth client secret passes through the model context and any client-side logs.
- `generateState()` (`src/auth.ts:220-222`) uses `Math.random()`, and the value is never stored or checked in `handleCallback`.

## Steps to reproduce
1. Prerequisites: Node.js. No Linear account or `LINEAR_API_KEY` is needed for `linear_auth`. Start a local listener so you can see whether the server connects to it:

   ```sh
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install and start the server as the README describes: `npm install && npm run build`, then `node build/index.js`.
3. Call the tool:

   ```json
   {"clientId": "tofu-client", "clientSecret": "tofu-secret", "redirectUri": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/linear-mcp/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("linear_auth", {"clientId": "tofu-client", "clientSecret": "tofu-secret", "redirectUri": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Expected from the code: the listener logs no request. The tool returns `Please visit the following URL to authorize the application:` followed by a `https://linear.app/oauth/authorize?...` link containing `redirect_uri=http%3A%2F%2F127.0.0.1%3A8099%2Ftofu-poc`.

## Expected behavior
`redirectUri` is a well-formed `http(s)` URL, ideally taken from server configuration rather than from a tool argument.

## Actual behavior
Any string is accepted and encoded into the link. No server-side request is made to it. From the fuzzing run:

```
input:  {'clientId': 'admin', 'clientSecret': 'hunter2', 'redirectUri': 'http://localhost:8080'}
output: Please visit the following URL to authorize the application:
        https://linear.app/oauth/authorize?client_id=admin&redirect_uri=http%3A%2F%2Flocalhost%3A8080&response_type=code&scope=read%2Cwrite%2Cissues%3Acreate%2Coffline_access&actor=application&state=vr2ksrj799q&access_type=offline
```

## Impact
No SSRF. Because `clientId` and `redirectUri` both come from the model, a prompt-injected model could show the user an authorization link for an OAuth app of the attacker's choosing. The user would still see Linear's consent screen for that app. Linear's server should reject a `redirect_uri` that is not registered for the client; I did not verify that. Low severity.

## Suggested fix
- Read the OAuth client ID, client secret and redirect URI from environment variables (as is already done for `LINEAR_API_KEY`) instead of tool arguments. If they stay as arguments, at least check that `redirectUri` parses as an `http:` or `https:` URL.
- Generate `state` with `crypto.randomBytes`, keep it, and require it to match in `linear_auth_callback`.

## Status on the default branch
Still present at `023ac90` (2025-08-09). The tested commit is the current head of the default branch.

## Prior reports
- #34 "Weak OAuth state generation uses Math.random() (CWE-330) — fixed in PR #33" (issue, open 2026-08-31): reports the `generateState()` side note in this draft (`src/auth.ts:220-222`). It does not cover `redirectUri` or the unchecked `state` in the callback.
- #33 "fix(auth): use CSPRNG for OAuth state (weak Math.random -> randomUUID)" (PR, open 2026-08-31): replaces `Math.random()` with `crypto.randomUUID()`; not merged, and it does not validate `redirectUri` or store and check `state`.
- #24 "Cline authentication of oAuth API" (issue, open 2025-06-27): problems with the generated authorization link (unused `offline_access` scope and `access_type`, expired `state`); not about `redirectUri` validation.
- Documentation: README.md: "OAuth Flow (Alternative) ***NOT IMPLEMENTED***" (the README marks the OAuth flow as unimplemented and describes the client ID, secret and redirect URI as `.env` settings, `LINEAR_REDIRECT_URI=http://localhost:3000/callback`, not tool arguments)
- Documentation: todo.md: "Add state parameter validation" (open TODO item matching the unchecked `state` noted here)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: the `redirectUri` point is not reported; the `Math.random()` state side note is already #34 with fix PR #33 (both open, not merged). Drop that bullet or cite #34 if filing.
- ToFu class / sanitizers: ssrf (CWE-918). Only `check_strict_url_security_contract` fired: an input-side URL contract check ("Validation Bypass Alert": the malformed or internal URL was accepted). No outbound request to the URL was observed or exists in the code.
- Campaigns and executions: `recover-pc`, 3584 executions, 848 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'clientId': 'client123', 'clientSecret': 'secret', 'redirectUri': '/etc/passwd\x00'}` -> link with `redirect_uri=%2Fetc%2Fpasswd%00`
  - `{'clientId': 'admin', 'clientSecret': 'hunter2', 'redirectUri': 'http://localhost:8080'}` -> link with `redirect_uri=http%3A%2F%2Flocalhost%3A8080`
  - `{'clientId': 'client123', 'clientSecret': 'secret', 'redirectUri': '../../../../etc/passwd'}` -> link with `redirect_uri=..%2F..%2F..%2F..%2Fetc%2Fpasswd`
- Hand-check hints: **weak, false positive** for SSRF. The value only goes into an encoded query parameter of a fixed-host link and a form field to a fixed host. The remaining points (secret as a tool argument, unchecked `state`) are OAuth hygiene, not SSRF. An unverified idea for a human: if the server already runs with `LINEAR_API_KEY`, a model-driven `linear_auth` + `linear_auth_callback` pair could swap the server's Linear client to tokens for another account (`src/auth.ts:111-113`). I did not trace whether that is practical. Recommend filing only as a small hardening issue, or dropping. Steps not executed (read-only review).
</details>
