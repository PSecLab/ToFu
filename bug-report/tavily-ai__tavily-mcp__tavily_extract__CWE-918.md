# `tavily_extract` forwards any `urls` entry (loopback, private, malformed) to the Tavily extract API without validation

**Repository:** `tavily-ai/tavily-mcp` · **Tool:** `tavily_extract` · **Tested commit:** `248dc9e`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`tavily_extract` takes a list of URLs from the caller and sends it, unchanged, in a POST to `https://api.tavily.com/extract`. The MCP server does not fetch those URLs itself; extraction runs on Tavily's service. The server does no local validation, so loopback, private-network, non-HTTP and malformed URLs are all forwarded. This is a defence-in-depth gap, not an SSRF in this process: any restriction on internal destinations depends entirely on the Tavily backend. Extract also works in keyless mode, so this path is reachable without an API key.

## Details
The handler copies `args.urls` into the request (`src/index.ts:477-486`):

```ts
case "tavily_extract":
  response = await this.extract({
    urls: args.urls,
    extract_depth: args.extract_depth,
    include_images: args.include_images,
    format: args.format,
    include_favicon: args.include_favicon,
    query: args.query,
  });
```

and `extract` posts it to the fixed endpoint (`src/index.ts:645-651`):

```ts
async extract(params: any): Promise<TavilyResponse> {
  const response = await this.axiosInstance.post(this.baseURLs.extract, {
    ...params,
    ...(IS_KEYLESS ? {} : { api_key: API_KEY })
  });
```

There is no `new URL(...)` parse, scheme check or host check anywhere in `src/index.ts`. `tavily_crawl` and `tavily_map` follow the same pattern.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. `TAVILY_API_KEY` is optional; without it the server runs in keyless mode, which supports extract.
2. Start a listener on your own machine: `python3 -m http.server 8099 --bind 127.0.0.1`.
3. Start the server as the README describes (`npx -y tavily-mcp@latest`; `package.json` at the tested commit is `0.2.22`) and call the tool with `{"urls": ["http://127.0.0.1:8099/tofu-poc"]}`:

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="npx",
           args=["-y", "tavily-mcp@0.2.22"],
           env=dict(os.environ),
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("tavily_extract", {
                   "urls": ["http://127.0.0.1:8099/tofu-poc"]})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the local listener does not receive a `GET /tofu-poc`, because the MCP server only talks to `api.tavily.com`. The tool returns the Tavily API's answer for that URL. The point shown is that the loopback URL was forwarded with no local check.

## Expected behavior
Before calling the API, the tool parses each entry of `urls`, requires `http` or `https` and a non-empty host, and rejects loopback, private, link-local and similar internal destinations with a clear error.

## Actual behavior
Each string in `urls` is forwarded unchanged to the extract API. No run log of this tool survived, so there is no tool output to quote; the behaviour above is from the code.

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection. This server does not connect to the supplied URLs, so a caller cannot use it to reach services on the user's machine or local network. The remaining risk lies with the hosted extractor: if the backend did not restrict internal destinations, a forwarded URL could make Tavily's infrastructure fetch addresses on its own network. That is a property of the Tavily service, which this report does not test. Treat this as low severity and a hardening suggestion for the client.

## Suggested fix
Validate every entry of `urls` (and `url` in `tavily_crawl` / `tavily_map`) with one helper: parse with `new URL()`, allow only `http:`/`https:`, require a hostname, and reject literal loopback, private (RFC 1918), link-local, unique-local IPv6 and unspecified addresses, plus `localhost`. Hostnames that resolve to internal addresses can only be fully handled where the fetch happens, so the Tavily backend remains the authoritative control.

## Status on the default branch
Still present at `1c1d54c` (2026-09-16). The one commit since the tested one adds a feedback tool and result formatting; `tavily_extract` still forwards `args.urls` unchanged (`src/index.ts:567-576` and `747-753` on that commit), with no URL validation in `src/index.ts`.

## Prior reports
- #133 "fix(security): implement strict parameter validation to prevent API exhaustion and parameter injection" (PR, closed 2026-03-23): hardening of the `extract`, `crawl` and `map` handlers (at most 20 `urls`, `url` must be a string, caps on `limit` and `max_depth`, unknown fields dropped). It adds no scheme or host check, so it would not fix this. Its changes are not in `src/index.ts` on the default branch, so it appears to have been closed without merging.
- No issue reports missing URL validation or internal destinations in `tavily_extract` or `tavily_crawl`. Searched all 67 issues and 147 pull requests (fetched 2026-10-01) and the README on the default branch (the only documentation file), which says nothing about URL restrictions.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf; `check_strict_url_security_contract` only.
- Campaigns and executions: e2-0922 1 exec / 0 success.
- Evidence: none. `log_available: false`, no run log survived, so the triggering input and output are unknown. The reproduction and every statement about behaviour are derived from the code at `248dc9e`.
- Hand-check hints: unclear, very likely a ToFu false positive for this repo. A single execution, zero successes, and only the string-level URL contract sanitizer fired. The code proves the MCP process never requests the URL: it POSTs to the hard-coded `api.tavily.com/extract`. Whether Tavily's backend blocks internal targets is unknown and outside this repo, and we should not probe it. If filed at all, file it as "add client-side URL validation" together with the `tavily_crawl` draft, not as SSRF. Not run.
</details>
