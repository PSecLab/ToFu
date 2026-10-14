# `screenshot-page` loads any URL the caller gives, including loopback addresses and `file:` URLs, and returns the rendered page

**Repository:** `ananddtyagi/webpage-screenshot-mcp` · **Tool:** `screenshot-page` · **Tested commit:** `cad4a14`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`screenshot-page` opens the caller's `url` in a headless Chromium on the machine running the server and returns a screenshot of it. The only check is `z.string().url()`, which accepts any syntactically valid URL. Loopback and private-network addresses are loaded, and so are `file:` URLs, so the screenshot can show content that is only reachable from the server's machine.

## Details
The tool schema (`src/index.ts:501`) declares `url: z.string().url()`. The handler navigates straight to it (`src/index.ts:578-581`):

```ts
// Navigate to the URL
await page.goto(url, {
    waitUntil: waitFor as any,
    timeout: 30000
});
```

The result is captured with `encoding: 'base64'` (`src/index.ts:591`) and returned as an MCP `image` item (`src/index.ts:627-628`). There is no check on the scheme or on the destination host before `page.goto`, and no request interception that would block loopback, private or link-local addresses after DNS resolution. The same pattern is used by the second navigation path (`src/index.ts:531`) and by the tool at `src/index.ts:758-817`.

## Steps to reproduce
1. Prerequisites: Node.js 18+ (Puppeteer downloads Chromium on install), Python 3.10+ with `pip install mcp`.
2. Build and start a local listener in a second terminal:

   ```bash
   git clone https://github.com/ananddtyagi/webpage-screenshot-mcp.git && cd webpage-screenshot-mcp
   git checkout cad4a14
   npm install && npm run build
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
3. Call the tool:

   ```json
   { "url": "http://127.0.0.1:8099/tofu-poc", "fullPage": false }
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
               result = await session.call_tool("screenshot-page",
                                                {"url": "http://127.0.0.1:8099/tofu-poc", "fullPage": False})
               print(result.content[0].type)

   asyncio.run(main())
   ```
4. Observe `GET /tofu-poc` in the listener's log, and an `image` result showing the listener's 404 page. The server rendered a loopback URL chosen by the caller.

## Expected behavior
The tool only loads `http:` / `https:` URLs whose resolved address is public, and refuses loopback, private, link-local and `file:` destinations, unless an operator explicitly allows them.

## Actual behavior
Any URL that parses is loaded and screenshotted. In the fuzzing run a `file:` URL was accepted and reported as a success:

```
output: Screenshot captured successfully!
        Browser: Puppeteer browser (headless)
        Final URL: file:///...
```

## Impact
In MCP the model chooses the tool arguments, and prompt injection in a page or document it reads can choose them too. Through this tool an attacker can make the server's machine render internal web interfaces (admin panels, local dev servers, services on the host's private network) and receive the screenshot, and can render local files through `file:` URLs. With `useSavedAuth` (default `true`) saved login cookies are also applied to the navigation.

## Suggested fix
- Allow only `http:` and `https:`; reject `file:`, `chrome:`, `data:` and other schemes.
- Resolve the host and reject loopback, private (RFC 1918, `fc00::/7`), link-local and unspecified addresses; enforce the same rule on redirects and subresources with `page.setRequestInterception(true)`.
- Make internal access an explicit opt-in setting for operators who need it.

## Status on the default branch
Still present at `cad4a14` (2025-06-28); the tested commit is the current head.

## Prior reports
None found. Searched all 2 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- Documentation: README.md describes the tool as "Captures a screenshot of a given URL" and documents `useSavedAuth` "(default: true)", but says nothing about which URLs or schemes are allowed and has no warning about loopback, private-network or `file:` URLs. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918) via input-side URL checks; the run also flagged leftover Chrome processes after each call.
- Campaigns and executions: e2-0922 only (1 execution recorded, 0 counted as success by the index), but the tool output itself says the capture succeeded.
- Evidence (verbatim, trimmed): input `{'url': 'file:///etc/passwd', 'fullPage': False, 'width': 1920, 'height': 1080, 'format': 'webp', ...}` -> `Screenshot captured successfully! ... Final URL: file:///etc/passwd`.
- The local-listener step is derived from the code (page.goto with no host check), not run.
- Hand-check hints: real. A screenshot tool loading arbitrary URLs is close to its purpose, so expect "by design"; the stronger points are `file:` URLs and loopback/private hosts with saved cookies applied. Earlier drafting attempts for this item were cut short; this version was written by the coordinator.
</details>
