# Log injection in `create-repository`: CR/LF in `org` reaches the debug request log unescaped

**Repository:** `containerelic/github-enterprise-mcp` · **Tool:** `create-repository` · **Tested commit:** `86c8752`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`create-repository` creates a repository for the user or an organization. With `DEBUG=true` (used in the README's Docker examples), the API client logs every request line with `console.log`, including the request path built from the caller's `org`. `org` is not validated or encoded, so a value with `\r\n` writes extra, attacker-chosen lines into the server output. The other text fields (`name`, `description`, templates) are logged through `JSON.stringify` and are neutralized.

## Details
`server/index.ts:1007-1011` (tested commit) passes `org` straight to the API layer:

```ts
if (org) {
  repository = await context.repository.createOrganizationRepository(org, options);
} else {
  repository = await context.repository.createRepository(options);
}
```

`api/repos/repository.ts:66-68` builds the path with plain interpolation: `` this.client.post(`orgs/${org}/repos`, options) ``. `buildApiUrl` (`utils/config.ts:87-102`) concatenates it onto the base URL as a string, and `utils/client.ts:69-74` logs it:

```ts
if (this.config.debug) {
  console.log(`[GitHub API] ${method} ${urlWithParams}`);
  console.log(`[GitHub API] Base URL: ${this.config.baseUrl}`);
  if (data) console.log(`[GitHub API] Request body: ${JSON.stringify(data)}`);
}
```

The request line is logged raw; only the body is JSON-encoded. The `org` schema is `z.string().optional()` (`server/index.ts:982`). In stdio mode `console.log` writes to stdout, which is also the MCP JSON-RPC channel.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No real GitHub account is needed: the log line is printed before the request is sent. Use a closed local port as the API URL so nothing leaves the machine.
2. Install and build as the README describes (the README clones `ddukbg/github-enterprise-mcp`; this fork is `containerelic/github-enterprise-mcp`): `git clone https://github.com/containerelic/github-enterprise-mcp.git && cd github-enterprise-mcp && npm install && npm run build`.
3. Call the tool through a wrapper that copies the server's stdout to a file:

   ```json
   {"name": "tofu-poc", "org": "acme\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       env = dict(os.environ, DEBUG="true", GITHUB_TOKEN="dummy",
                  GITHUB_ENTERPRISE_URL="http://127.0.0.1:9/api/v3")
       server = StdioServerParameters(command="sh",
           args=["-c", "node dist/index.js | tee /tmp/tofu-poc.txt"], env=env)
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create-repository",
                   {"name": "tofu-poc", "org": "acme\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Open `/tmp/tofu-poc.txt`. Expect `[GitHub API] POST http://127.0.0.1:9/api/v3/orgs/acme` followed by a separate line `FAKE-LOG-ENTRY/repos`. The tool itself returns a network error.

## Expected behavior
`org` (and the other owner/repo path parameters) are validated against GitHub's name rules and URL-encoded before use, and log output escapes control characters.

## Actual behavior
The `org` value is written into the log line as is. The fuzzing run did not exercise this field (all evidence calls used `org: ''`); its CR/LF payloads were in `description` and `name`, which only reach the JSON-encoded body log or no log at all with `DEBUG` unset:

```
{'name': 'log-injection-repo', 'description': 'Normal description\nInjected log line: ERROR: something failed', ...}
-> Error creating repository: GitHub API authentication error: Invalid or expired token.
```

## Impact
The LLM chooses `org`, and prompt injection can steer it. With debug logging on, an attacker can forge lines in the server's output. In stdio mode that output is the JSON-RPC stream to the client, so injected lines are read by the MCP client as protocol data. The same unencoded `org` also changes which API path receives the authenticated POST (for example with `/`, `?` or `#`). Only deployments with `DEBUG=true` are affected by the log part. Low.

## Suggested fix
- Validate `org` with `z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$/)` and `encodeURIComponent` all path segments in `api/*`.
- Send debug logs to stderr (`console.error`) so they never mix with the stdio transport, and escape control characters in logged URLs (for example `JSON.stringify(urlWithParams)`).

## Status on the default branch
Still present at `86c8752` (2025-09-14). The tested commit is the current default branch head.

## Prior reports
- Where to file: every issue and PR URL returned for `containerelic/github-enterprise-mcp` points to `ddukbg/github-enterprise-mcp`, so the GitHub API resolves this name to `ddukbg/github-enterprise-mcp` (renamed or transferred). The README clones that repository too. File there.
- #16 "Client error for command Unexpected token 'D', "Detected G"... is not valid JSON in cursor" (issue, closed 2025-12-30): the server's `console.log` startup lines go to stdout and break the stdio JSON-RPC stream in Cursor. Same sink as this draft's stdout point (debug request lines also use `console.log`), but it is not about `org` or log injection. Closed with no linked PR, and the default branch has no commit after `86c8752` (2025-09-14), so it did not change this code.
- Documentation: README.md: "`--debug`: Enable debug logging" (the Docker examples set `DEBUG=true`; nothing says the debug output is unescaped or written to stdout).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 1024 exec / 1013 ok; e2-0922 512 exec / 509 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'name': 'log-injection-repo', 'description': 'Normal description\nInjected log line: ERROR: something failed', 'private': False, ..., 'org': ''}` -> `Error creating repository: GitHub API authentication error: Invalid or expired token.`
  - `{'name': 'e"1:(^\repo-with', 'description': '', ..., 'org': ''}` -> `Error creating repository: GitHub API error: 429 Request failed with status code 429`
  - Third input had CR in `gitignore_template`, `org: ''` -> 429 error.
- Hand-check hints: weak. The evidence is a false positive: the flagged CR/LF fields go into the request body, which is logged via `JSON.stringify` (escaped) and only when `DEBUG=true`. The raw sink I found is `org` in the logged URL, by source reading; ToFu never put CR/LF in `org`. Not run. The fuzzing harness apparently had a live (expired) token and reached a GitHub endpoint (401/429 replies). Side note, not filed here: `index.ts` prints startup logs with `console.log` to stdout in stdio mode unconditionally, so the Python client in the repro may log JSON parse errors for those lines; check it still completes the call. The repo is a fork (README and package name point to `ddukbg/github-enterprise-mcp`); check whether the upstream has the same code and where to file.
</details>
