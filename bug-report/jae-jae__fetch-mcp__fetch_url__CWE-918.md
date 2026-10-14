# SSRF in `fetch_url`: `url` can point the headless browser at loopback and private-network services

**Repository:** `jae-jae/fetch-mcp` · **Tool:** `fetch_url` · **Tested commit:** `8754aff`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`fetch_url` opens a caller-supplied URL in a headless Chromium (Playwright) and returns the page content. The only check on the URL is that its scheme is `http:` or `https:`. Loopback, private and link-local destinations are not blocked, and neither are alternate spellings of them that the browser normalizes (for example octal IPv4). The server can therefore be used to reach services that are only reachable from the machine it runs on, and to return their responses to the caller.

## Details
`src/tools/fetchUrl.ts:79-87` takes the URL and validates only its protocol:

```ts
export async function fetchUrl(args: any) {
  const url = String(args?.url || "");
  if (!url) {
    logger.error(`URL parameter missing`);
    throw new Error("URL parameter is required");
  }

  // Validate URL protocol for security (only allow HTTP and HTTPS)
  validateUrlProtocol(url);
```

`validateUrlProtocol` (`src/utils/urlValidator.ts:25-56`) parses the URL and checks `parsedUrl.protocol` against `["http:", "https:"]`. It never looks at the host. The URL then goes straight to `page.goto(url, ...)` in `src/services/webContentProcessor.ts:26`. Because this is a real browser, redirects and any requests made by the loaded page are not checked either. The existing `context.route("**/*", ...)` hook in `src/services/browserService.ts:119` only filters by resource type. `fetch_urls` (`src/tools/fetchUrls.ts:88`) has the same gap.

## Steps to reproduce
1. Prerequisites: Node.js and npm, plus Playwright's Chromium (installed by `npm run install-browser`). Python 3 is used for the local listener.
2. Install and build as the README's development section describes, and start a local listener in an empty temporary directory:

   ```bash
   git clone https://github.com/jae-jae/fetch-mcp.git
   cd fetch-mcp
   npm install
   npm run install-browser
   npm run build

   # in a second terminal
   mkdir -p /tmp/tofu-ssrf/tofu-poc && cd /tmp/tofu-ssrf
   echo "<p>tofu-poc local-only content</p>" > tofu-poc/index.html
   python3 -m http.server 8099 --bind 127.0.0.1
   ```

   `tofu-poc` is a directory with an `index.html`, so `http.server` serves it as HTML. A file without an extension would be sent as `application/octet-stream`, which Chromium treats as a download; the GET would still show up in the log.
3. Call the tool with these arguments:

   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc", "extractContent": false}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/fetch-mcp/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "fetch_url", {"url": "http://127.0.0.1:8099/tofu-poc", "extractContent": False}
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe: the `http.server` terminal logs `GET /tofu-poc` from `127.0.0.1` (answered with a 301 to `/tofu-poc/`, which the browser follows), and the tool result contains `tofu-poc local-only content`. Stop the listener with Ctrl-C and remove `/tmp/tofu-ssrf` afterwards.

## Expected behavior
By default the tool should refuse URLs whose host resolves to a loopback, private, link-local or otherwise non-public address, and it should apply the same rule to redirects and to requests the page makes. Users who need to fetch local services could opt in with an explicit flag.

## Actual behavior
The request is made and the response is returned to the caller. In the fuzzing run, every loopback URL ToFu tried (plain, IPv6 and octal-encoded forms) passed validation and reached `page.goto`. Chromium answered `net::ERR_CONNECTION_REFUSED` only because nothing was listening in the sandbox. For the octal form, the browser had already rewritten the host to the normal loopback address:

```
Title: Error
URL: http://0177.0.0.1:8080
Content:

<error>Failed to retrieve web page content: page.goto: net::ERR_CONNECTION_REFUSED at http://127.0.0.1:8080/
```

## Impact
In MCP, the `url` argument is chosen by the LLM, and the pages this tool fetches are untrusted content that can carry prompt injection. A malicious page can steer the model into fetching an internal address, and the response comes back to the model, where it can be summarized or passed on in a later call. This exposes services that rely on not being reachable from outside the host or its network: local admin panels, development servers, internal APIs and similar. The README also documents an HTTP transport bound to `0.0.0.0`; I found no authentication in `src/transports/http.ts`, so in that mode anyone who can reach the port can use the server to make these requests. The tool is marked `readOnlyHint: true`, but a GET to an internal service can still have side effects.

## Suggested fix
Check the destination of every request the browser makes, not only the first URL:

- In a `context.route("**/*", ...)` handler, parse `route.request().url()`, resolve the hostname with `dns.lookup(host, { all: true })`, and call `route.abort()` if any address is loopback, private (RFC 1918, RFC 4193), link-local, unspecified, or an IPv4-mapped IPv6 form of these. This also covers redirects and subresources.
- Parse IP literals with a proper library (for example `ipaddr.js`) so octal, hex and integer IPv4 forms are caught.
- Add an opt-in flag (for example `--allow-private-network`) for users who need local access.
- A check-then-fetch design can still be bypassed by DNS rebinding, because Chromium resolves the name again. If that matters, route the browser through a small forward proxy that enforces the rule on the address it actually connects to.

## Status on the default branch
Still present at `8754aff` (2026-01-14). The tested commit is the current head of the default branch.

## Prior reports
- #37 "[BUG] - `fetch_url` and `fetch_urls` allow non-blind SSRF to internal network targets" (issue, open 2026-06-30): the same bug. Protocol-only `validateUrlProtocol()`, then `page.goto(url)`, shown with a loopback listener whose body came back in the tool result, on 0.3.9. Not fixed.
- #38 "SSRF in fetcher-mcp fetch_url (no internal-IP filtering)" (issue, open 2026-07-08): the same bug, also on 0.3.9, with redirects noted as followed. The reporter says an email report sent on 5 June 2026 got no response. Not fixed.
- #24 "🔒 Security Audit Results — AgentAudit" (issue, open 2026-02-13): an automated audit whose finding 1 is the same gap ("only checks for HTTP/HTTPS protocol" in `src/utils/urlValidator.ts`). Not fixed.
- #40 "Please enable Private Vulnerability Reporting (security contact)" (issue, open 2026-08-14): an undisclosed issue "affecting the fetch tools in the HTTP transport deployment". It may overlap with this draft's unauthenticated HTTP-transport point; no details are public.
- Documentation: README.md documents `--transport=http --host=0.0.0.0` and has no security section; nothing warns that local or private addresses can be fetched. No `SECURITY.md`.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported publicly as #37 and #38 (both open, same root cause, same version 0.3.9) and as finding 1 in #24. Not fixed at `8754aff`. Do not file a new issue; at most add the octal-IPv4 and redirect/subresource points as a comment on #37.
- ToFu class / sanitizers: `ssrf` (CWE-918). Evidence alerts are "Silent Bug Alert" (URL sanitizers flagged the input, the tool ran without raising). Triggered list: `check_resource_exhaustion`, `check_strict_url_security_contract`, `check_url_alternative_ip_representations`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: e2-0922: 1 exec / 0 ok (budget 60s). The group file lists three evidence calls from that campaign, so the exec counter looks inconsistent with the evidence; not resolved.
- Evidence (verbatim, trimmed):
  - [e2-0922] input `{'url': 'http://[::1]:8080', 'timeout': 5000, 'waitUntil': 'load', 'extractContent': False, 'maxLength': 512, 'returnHtml': True, ...}` -> `Title: Error\nURL: http://[::1]:8080\nContent:\n\n<error>Failed to retrieve web page content: page.goto: net::ERR_CONNECTION_REFUSED at http://[::1]:8080/ ...`
  - [e2-0922] input `{'url': 'http://127.0.0.1:8500', 'timeout': 0, 'waitUntil': 'load', 'extractContent': True, 'maxLength': 100, ...}` -> `... page.goto: net::ERR_CONNECTION_REFUSED at http://127.0.0.1:8500/ ...`
  - [e2-0922] input `{'url': 'http://0177.0.0.1:8080', 'timeout': 10000, 'waitUntil': 'domcontentloaded', 'extractContent': True, ...}` -> `... page.goto: net::ERR_CONNECTION_REFUSED at http://127.0.0.1:8080/ ...`
- Hand-check hints: real. The URL reaches `page.goto` with only a protocol check, and `ERR_CONNECTION_REFUSED` shows Chromium attempted the loopback connection in all three calls. No response body was read during fuzzing because nothing was listening; the step 3 listener reproduction is derived from the code and was not run by me. Expect pushback that fetching arbitrary URLs is the tool's purpose; the request here is a default block on non-public destinations with an opt-in.
- Per coordinator instruction, the reproduction uses only the local `127.0.0.1:8099` listener; no metadata or private-network addresses are named. The "Actual behavior" excerpt still shows the loopback address from the octal evidence call (`0177.0.0.1:8080` rewritten to `127.0.0.1:8080`); drop it if even that is too much.
- The 301-then-200 behavior of `python3 -m http.server` for a directory path and Chromium's download handling of `application/octet-stream` are from my knowledge of those tools, not tested here.
- npm package name is `fetcher-mcp` (README uses `npx -y fetcher-mcp`); the reproduction uses a local build of the tested commit instead.
- Fuzzed commit `8754aff66e3d9207502207bf82a493f45f556bb8`; `head_sha` is the same commit.

</details>
