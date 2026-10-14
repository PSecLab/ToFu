# `tavily_crawl` forwards any `url` (loopback, empty, relative) to the Tavily crawl API without validation

**Repository:** `tavily-ai/tavily-mcp` · **Tool:** `tavily_crawl` · **Tested commit:** `248dc9e`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`tavily_crawl` takes a root `url` from the caller and sends it, unchanged, in a POST to `https://api.tavily.com/crawl`. The MCP server does not fetch the URL itself; the crawl runs on Tavily's service. The server does no local validation: empty strings, relative paths, non-standard ports and loopback or private addresses are all forwarded. This is a defence-in-depth gap rather than an SSRF in this process: any restriction on internal destinations depends entirely on the Tavily backend.

## Details
The handler copies `args.url` into the request (`src/index.ts:488-502`):

```ts
case "tavily_crawl":
  const crawlResponse = await this.crawl({
    url: args.url,
    max_depth: args.max_depth,
    ...
    allow_external: args.allow_external,
```

and `crawl` posts it to the fixed API endpoint (`src/index.ts:653-659`):

```ts
async crawl(params: any): Promise<TavilyCrawlResponse> {
  const response = await this.axiosInstance.post(this.baseURLs.crawl, {
    ...params,
    ...(IS_KEYLESS ? {} : { api_key: API_KEY })
  });
```

There is no `new URL(...)` parse, scheme check or host check anywhere in `src/index.ts`. The same holds for `tavily_extract` (`urls`) and `tavily_map` (`url`).

## Steps to reproduce
1. Prerequisites: Node.js 18+, a Tavily API key in `TAVILY_API_KEY` (in keyless mode the crawl endpoint returns "requires an API key"), and Python with the `mcp` package.
2. Start a listener on your own machine: `python3 -m http.server 8099 --bind 127.0.0.1`.
3. Start the server as the README describes (`npx -y tavily-mcp@latest`; `package.json` at the tested commit is `0.2.22`) and call the tool with `{"url": "http://127.0.0.1:8099/tofu-poc", "max_depth": 1, "limit": 1}`:

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="npx",
           args=["-y", "tavily-mcp@0.2.22"],
           env=dict(os.environ),  # must contain TAVILY_API_KEY
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("tavily_crawl", {
                   "url": "http://127.0.0.1:8099/tofu-poc", "max_depth": 1, "limit": 1})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the local listener does not receive a `GET /tofu-poc`, because the MCP server only talks to `api.tavily.com`. The tool returns whatever the Tavily API answers for that URL (an error or an empty crawl). What this shows is that the loopback URL was forwarded without any local check. Calling with `{"url": ""}` likewise sends an empty URL to the API.

## Expected behavior
Before calling the API, the tool parses `url`, requires `http` or `https` and a non-empty host, and rejects loopback, private, link-local and similar internal destinations with a clear error. That gives defence in depth and a faster, clearer error for bad input.

## Actual behavior
Any string is forwarded. In ToFu's run the server had no API key, so every call returned the keyless envelope:

```
This Tavily endpoint requires an API key. Keyless Tavily currently supports Search and Extract only. ...
```

Empty, relative and loopback inputs were all accepted and sent on without a local error.

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection. This server does not connect to the supplied URL, so a caller cannot use it to reach services on the user's machine or local network. The remaining risk lies with the hosted crawler: if the backend did not restrict internal destinations, a forwarded URL could make Tavily's infrastructure fetch addresses on its own network. That is a property of the Tavily service, which this report does not test. Treat this as low severity and a hardening suggestion for the client.

## Suggested fix
Add a small validator used by `tavily_crawl`, `tavily_map` and `tavily_extract`: parse with `new URL()`, allow only `http:`/`https:`, require a hostname, and reject literal loopback, private (RFC 1918), link-local, unique-local IPv6 and unspecified addresses, plus `localhost`. Hostnames that resolve to internal addresses can only be fully handled where the fetch happens (the Tavily backend), so document that the backend is the authoritative control.

## Status on the default branch
Still present at `1c1d54c` (2026-09-16). The one commit since the tested one adds a feedback tool and result formatting; `crawl` still posts `params` unchanged to `https://api.tavily.com/crawl` (`src/index.ts:755-761` on that commit), and there is still no URL validation in `src/index.ts`.

## Prior reports
- #133 "fix(security): implement strict parameter validation to prevent API exhaustion and parameter injection" (PR, closed 2026-03-23): hardening of the `extract`, `crawl` and `map` handlers (at most 20 `urls`, `url` must be a string, caps on `limit` and `max_depth`, unknown fields dropped). It adds no scheme or host check, so it would not fix this. Its changes are not in `src/index.ts` on the default branch, so it appears to have been closed without merging.
- No issue reports missing URL validation or internal destinations in `tavily_extract` or `tavily_crawl`. Searched all 67 issues and 147 pull requests (fetched 2026-10-01) and the README on the default branch (the only documentation file), which says nothing about URL restrictions.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf; `check_strict_url_security_contract`, `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`.
- Campaigns and executions: corpus-sbx 1024 exec / 277 success; e2-0922 1 / 1. All logged calls ran in keyless mode (no `TAVILY_API_KEY`).
- Evidence (trimmed; addresses and file paths redacted per the reporting rules):
  - `{'url': '', 'max_depth': 0, ...}` -> `This Tavily endpoint requires an API key. Keyless Tavily currently supports Search and Extract only. ...`
  - `{'url': 'http://<loopback>:8500', 'max_depth': 1, 'max_breadth': 20, 'limit': 50, 'instructions': 'Crawl all pages.', 'allow_external': True, ...}` -> same keyless message.
  - `{'url': '<relative ../ path>', ...}` -> same keyless message.
- Hand-check hints: unclear, very likely a ToFu false positive for this repo. The sanitizers fire on the input string alone ("ACCEPTED" because the call returned without an exception), but the code proves the MCP process never requests the URL: it only POSTs to the hard-coded `api.tavily.com/crawl`. No call in the log got past the keyless rejection. Whether Tavily's backend blocks internal targets is unknown and outside this repo; probing it would mean testing Tavily's infrastructure, which we should not do. If filed at all, file it as "add client-side URL validation", not as SSRF. Reproduction derived from code, not run.
</details>
