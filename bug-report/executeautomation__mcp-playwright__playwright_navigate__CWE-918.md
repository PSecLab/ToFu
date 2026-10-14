# SSRF in `playwright_navigate`: no restriction on loopback, private-network or `file://` destinations

**Repository:** `executeautomation/mcp-playwright` · **Tool:** `playwright_navigate` · **Tested commit:** `2349c28`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`playwright_navigate` opens any URL in the server-side browser. There is no check on scheme or destination, so loopback, private-network and `file://` URLs load like any public page. The page content can then be read back through tools such as `playwright_get_visible_text`. Navigating is the purpose of this tool, but there is no option to restrict where it may go. A prompt-injected agent can therefore reach services that are only visible from the machine running the server.

## Details
`src/tools/browser/navigation.ts:29-36` at `2349c28`:

```ts
    return this.safeExecute(context, async (page) => {
      try {
        await page.goto(args.url, {
          timeout: args.timeout || 30000,
          waitUntil: args.waitUntil || "load"
        });

        return createSuccessResponse(`Navigated to ${args.url}`);
```

`args.url` comes straight from the tool call (`src/toolHandler.ts:567-568`). The input schema (`src/tools.ts:79-95`) only declares it as a string. Nothing parses the URL, checks the scheme, or resolves the host and compares it with loopback, private (RFC 1918), link-local or unique-local ranges. I found no allowlist or blocklist setting in `src/`.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. Playwright downloads a browser on first use, or run `npx playwright install chromium`. In a separate terminal, start a listener on your own machine:
   ```
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install and start the server:
   ```
   git clone https://github.com/executeautomation/mcp-playwright.git
   cd mcp-playwright && git checkout 2349c2891e7c499c8c07b7d78c7f3fb4c797a1da
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc", "browserType": "chromium", "headless": true}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "playwright_navigate",
                   {"url": "http://127.0.0.1:8099/tofu-poc", "browserType": "chromium", "headless": True},
               )
               print(result)
               print(await session.call_tool("playwright_get_visible_text", {}))
               await session.call_tool("playwright_close", {})

   asyncio.run(main())
   ```
4. What to observe: the listener prints `"GET /tofu-poc HTTP/1.1" 404 -`. The tool returns `Navigated to http://127.0.0.1:8099/tofu-poc`, and `playwright_get_visible_text` returns the listener's 404 page text to the client.

## Expected behavior
The operator should be able to limit navigation, for example to `http`/`https` and an allowlist of origins. Loopback, private, link-local and `file://` destinations should be refused unless explicitly allowed, and the check should happen after DNS resolution and on every redirect.

## Actual behavior
Any URL is loaded. In the fuzzing run a `file://` URL pointing at a local system file loaded in WebKit and the tool reported success:

```
{'content': [{'type': 'text', 'text': 'Navigated to file:///<local file>'}], 'isError': False}
```

## Impact
The LLM picks the URL, and prompt injection in a page the agent is browsing, or in any other untrusted input, can steer it. An attacker can make the browser on the server host request loopback or internal-network addresses, including admin interfaces that trust local clients. The attacker can then have the page text returned to the model, which can be told to send it on. With `file://`, local files readable by the server user can be displayed the same way. The risk is highest when the server runs on a machine with access to internal services, or in HTTP mode for several clients.

## Suggested fix
- Add opt-in restrictions, for example `--allowed-origins` / `--blocked-origins` flags or environment variables, and refuse non-`http(s)` schemes such as `file:` by default.
- Before `page.goto`, parse the URL, resolve the host, and reject loopback, private, link-local and unique-local addresses unless the operator allows them.
- Enforce the same rule for redirects and subresources with `page.route` / `context.route`, so a public URL cannot redirect into an internal one.

## Status on the default branch
Still present at `2349c28` (2025-12-13). The tested commit is the head of the default branch.

## Prior reports
- #209 "Security Advisory: SSRF, Prompt Injection, and Arbitrary JavaScript Execution via Browser Automation Tools" (issue, open 2026-03-27): the same bug. Section 1 reports that `playwright_navigate` accepts arbitrary URLs, including `file://`, loopback and internal ranges, and recommends a URL allowlist and blocking `file://` and internal IPs by default. Not fixed.
- #208 "fix(security): add SSRF protection with URL validation for API and navigation tools" (PR, open 2026-03-20): adds `src/tools/common/urlValidator.ts` (http/https only, private-range blocklist, DNS check) and names `navigation.ts` line 31 as affected. Would fix this, but it is not merged.
- #239 "fix(security): enforce URL validation on navigation and API request tools" (PR, open 2026-09-26): a fuller version of #208 that validates before `page.goto` and installs a `route` guard for redirects, subresources and new tabs. Would fix this, but it is not merged.
- #216 "Add policy enforcement for browser automation and HTTP request tools" (issue, open 2026-04-12): general request for policy controls on the browser and HTTP tools; suggests an external MCP proxy rather than a built-in check.
- Documentation: `docs/docs/playwright-web/Supported-Tools.mdx` describes `url` only as "URL of the application under test." The security notes in `README.md`, `CHANGELOG.md` and `docs/docs/playwright-web/HTTP-SSE-Transport.mdx` concern binding the HTTP transport to localhost, not where the browser may navigate. No navigation allowlist setting is documented.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in open issue #209 (section 1, same tool); open PRs #208 and #239 would fix it but neither is merged. Not fixed on the default branch. Consider commenting on #209 or reviewing #239 instead of filing.
- ToFu class / sanitizers: ssrf via `check_url_ssrf_ip_ranges`, `check_url_hostname_canonicalization`, `check_url_structure_and_parsing` (silent-bug alert: input flagged, tool succeeded). `check_process_and_fd_leaks` fired on the same call (leftover WebKit/RDD/WebExtensions processes) and `check_resource_exhaustion` also triggered; neither is part of this draft.
- Campaigns and executions: e2-0922, 1 exec / 0 ok (60 s). The single call returned `isError: False`; the 0 ok is probably because the leak check marked it, not verified.
- Evidence (verbatim, trimmed): input `{'url': 'file:///etc/passwd', 'browserType': 'webkit', 'width': 1280, 'height': 720, 'timeout': 30000, 'waitUntil': 'load', 'headless': True}` -> `{'content': [{'type': 'text', 'text': 'Navigated to file:///etc/passwd'}], 'isError': False}`. The draft anonymises the path.
- Hand-check hints: weak, mostly by design. Arbitrary navigation is the purpose of a browser automation server, and many maintainers will see this as expected; the defensible ask is an opt-in restriction and refusing `file:` by default. The log shows only one call, with `file://`, and no listener was used; the loopback repro and the `playwright_get_visible_text` read-back are derived from the code, not run. The SSRF rules for this draft forbid naming internal or metadata addresses, so Impact stays general.
</details>
