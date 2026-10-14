# SSRF in `get-stats-summary`: caller-supplied `siteUrl` is requested with the WordPress credentials attached

**Repository:** `prathammanocha/wordpress-mcp-server` · **Tool:** `get-stats-summary` · **Tested commit:** `904dbe2`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`get-stats-summary` takes a `siteUrl` argument and makes an authenticated HTTP request to it through the shared `makeWPRequest` helper. `siteUrl` is validated only by `z.string().url()`, so any URL-shaped value is accepted, including loopback, private-range and link-local hosts. The server sends the request to that host and includes the caller-supplied WordPress `username`/`password` as an HTTP Basic auth header. A caller who controls `siteUrl` can make the server reach internal hosts and can cause the credentials to be sent to an attacker-named host.

## Details
The flagged argument is `siteUrl`, declared at `src/index.ts:1172` with only `z.string().url()`. The `get-stats-summary` handler passes it unchanged into `makeWPRequest` at `src/index.ts:1179` (endpoint `sites/${siteId}/stats/summary`, method `GET`). `makeWPRequest` (`src/index.ts:158-194`) builds the request URL by string concatenation and attaches the caller's username and password as an HTTP Basic auth header:

```ts
// src/index.ts:173-185 (makeWPRequest)
const authString = Buffer.from(`${auth.username}:${auth.password}`).toString('base64');
const response = await axios({
  method,
  url: `${siteUrl}/wp-json/wp/v2/${endpoint}`,
  headers: {
    'Authorization': `Basic ${authString}`,
    'Content-Type': 'application/json',
  },
  data: data,
  params: params
});
```

There is no allowlist, no host check, and no scheme restriction beyond what `z.string().url()` enforces. `z.string().url()` accepts loopback and link-local hosts and even non-http schemes (a `file://` siteUrl reached `axios` in the logs). `axios` also follows HTTP redirects by default, so even an accepted host can redirect the request inward.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No live WordPress backend is required to observe the SSRF: the server dispatches the outbound request (and the credentials) before any WordPress response is needed.
2. Start a local listener to stand in for the host named by `siteUrl`:

   ```bash
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
3. Install, build and prepare to run the server as the README describes:

   ```bash
   npm install
   npm run build
   # server entry point: node build/index.js
   ```
4. Call `get-stats-summary` over MCP with `siteUrl` pointed at the listener. Arguments (JSON):

   ```json
{
  "siteUrl": "http://127.0.0.1:8099",
  "username": "demo",
  "password": "demo-app-password",
  "siteId": 0
}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get-stats-summary", {"siteUrl": "http://127.0.0.1:8099", "username": "demo", "password": "demo-app-password", "siteId": 0})
               print(result)

   asyncio.run(main())
   ```
5. Observe the listener log. It records an incoming `GET` request to `/wp-json/wp/v2/sites/${siteId}/stats/summary` from the server, carrying an `Authorization: Basic ...` header derived from the `username`/`password` you passed. This shows the server connected to the host named in `siteUrl` and forwarded the credentials. Only the local `127.0.0.1:8099` listener is involved.

## Expected behavior
The server should reject `siteUrl` values whose host resolves to loopback, private (RFC 1918) or link-local addresses, restrict the scheme to `http`/`https`, and prefer an operator-configured allowlist of permitted hosts. Credentials should never be sent to a host that has not passed those checks.

## Actual behavior
The server issues the request to whatever host `siteUrl` names and sends the Basic auth header built from the supplied `username`/`password`. In fuzzing, with `siteUrl` set to a loopback address and nothing listening on that port, the tool returned:

```
Error retrieving stats summary: connect ECONNREFUSED 127.0.0.1:8080
```

The error names the caller-supplied loopback host and port, which shows the request was dispatched there. With a listener running on that port (the reproduction above), the connection succeeds and the request, including the `Authorization: Basic` header, is received by the listener.

## Impact
In MCP, tool arguments are chosen by the LLM and can be steered by prompt injection from untrusted content the model reads. A per-call `siteUrl` is a reasonable design for a multi-site client, but nothing constrains it to a legitimate WordPress host. A caller who can influence the arguments can (1) make the server issue requests to hosts it should not reach, including loopback, private-range and link-local addresses, using it as a request relay to probe or reach internal services; and (2) cause the WordPress `username` and application password supplied in the same call to be sent, as an HTTP Basic credential, to that attacker-named host. Point (2) holds even if per-call `siteUrl` is considered intended: the credentials travel to whatever host is named, so a wrong or malicious `siteUrl` discloses them. Default redirect-following widens (1), since even an allowed host can redirect the request inward.

## Suggested fix
Before issuing the request in `makeWPRequest`, parse `siteUrl` and enforce: scheme in `{http, https}` only; resolve the hostname and reject the request if any resolved address is loopback, private, link-local or otherwise non-public; and prefer an operator-configured allowlist of permitted hosts over per-call free-form URLs. Set `maxRedirects: 0`, or re-validate the destination on each redirect via a `beforeRedirect` hook, so an allowed host cannot bounce the request to an internal one. Attach the Basic auth header only after the destination has passed these checks.

## Status on the default branch
Still present at `904dbe2` (2025-05-15). The repository's default branch (`origin/latest`) points at the same commit that was tested; `git diff 904dbe2 origin/latest -- src/index.ts` is empty and `makeWPRequest` is unchanged.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 3 pull requests (fetched 2026-10-01); none mentions `siteUrl`, `makeWPRequest`, SSRF, host validation or credential forwarding.
- #3 "Add MseeP.ai badge" (PR, closed 2025-05-14; its badge is on the README): third-party badge PR whose body reports an automated scan score of 100/100 with no findings listed; it does not mention `siteUrl` or SSRF and is not a fix.
- Documentation: README.md: "`siteUrl` (required): Your WordPress site URL" (per-call `siteUrl` is the documented design; nothing says it must be trusted or restricted).
- Documentation: README.md, "Security Considerations": "Always use HTTPS URLs for your WordPress site" (advice to the user only; no warning that a caller-chosen `siteUrl` receives the Basic auth credentials, and no allowlist setting exists).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918). Sanitizers that fired for `get-stats-summary`: `check_url_alternative_ip_representations`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: campaign `recover-pc`, 3584 executions / 855 successes (60s budget).
- Evidence (verbatim, trimmed) from campaign `recover-pc`:
  - input: `{'siteUrl': 'http://localhost:8080', 'username': 'user', 'password': 'pass', 'siteId': 0}`
    output: `Error retrieving stats summary: connect ECONNREFUSED 127.0.0.1:8080`
    sanitizers: `['check_url_structure_and_parsing', 'check_url_ssrf_ip_ranges']`
  - input: `{'siteUrl': 'file:///etc/passwd', 'username': 'fileuser', 'password': 'filepass', 'siteId': 100}`
    output: `Error retrieving stats summary: protocol mismatch`
    sanitizers: `['check_url_structure_and_parsing', 'check_url_hostname_canonicalization', 'check_url_ssrf_ip_ranges']`

  Passwords shown are synthetic fuzzer-generated values, not repo secrets. The fuzz outputs are connection errors because no listener was up on the target port during fuzzing; they prove the request was dispatched to the caller-named host, not a completed read. The PoC with a live listener completes the round trip.
- Hand-check hints: Real. `siteUrl` reaches `axios` in `makeWPRequest` (`src/index.ts:176-185`) with no host or scheme restriction, and the caller's `username`/`password` are attached as a Basic auth header. The only validation is `z.string().url()` at `src/index.ts:1172`. Confirmed by reading the code at the tested commit (HEAD == `904dbe2`); not executed. All 13 tools in this group reach the same sink.
- Combined issue: recommend filing all 13 `wordpress-mcp-server` CWE-918 items (create-category, create-comment, create-post, create-user, delete-user, get-category, get-clicks, get-comments, get-country-views, get-post, get-stats-summary, list-categories, update-category) as ONE issue. They are one root cause in the shared `makeWPRequest` helper and affect all 29 tools that accept `siteUrl`; separate issues would be 13 copies of the same report.
</details>
