# `pinterest_get_image_info` accepts any string as `image_url` without validation (reported as SSRF; no request is made today)

**Repository:** `terryso/mcp-pinterest` · **Tool:** `pinterest_get_image_info` · **Tested commit:** `b2b1b39`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`pinterest_get_image_info` is described as "Get Pinterest image information". It takes `image_url`, does not check that it is a Pinterest URL (or a URL at all), and returns it inside a JSON blob labelled `"source": "Pinterest"`. Our fuzzer flagged this as SSRF because loopback, `file:` and empty URLs were accepted. Reading the code, the handler never fetches the URL, so there is no server-side request today. This is a missing-validation issue that would become SSRF as soon as the handler starts fetching image metadata.

## Details
`pinterest-mcp-server.ts:498-519` (tested commit):

```ts
  private async handlePinterestGetImageInfo(args: any) {
    try {
      // Extract parameters
      const imageUrl = args.image_url;

      // Return image info
      return {
        content: [
          { type: 'text', text: `Pinterest Image Information` },
          {
            type: 'text',
            text: JSON.stringify({ image_url: imageUrl, source: 'Pinterest',
              timestamp: new Date().toISOString() }, null, 2),
          },
```

(Object literals condensed onto fewer lines; logic unchanged.) The schema at lines 198-211 only requires `image_url` to be a string. There is no scheme check, no host allow-list (`pinimg.com`, `pinterest.com`), and no network call. The tool result presents arbitrary caller input as Pinterest image information.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No accounts or env vars. Start a local listener in a separate terminal so you can see whether the server connects:
   ```bash
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/terryso/mcp-pinterest.git
   cd mcp-pinterest && npm install && npm run build
   # server entry point: node dist/pinterest-mcp-server.js
   ```
3. Call the tool:
   ```json
   {"image_url": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/pinterest-mcp-server.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("pinterest_get_image_info",
                                                {"image_url": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the tool returns the URL unchanged under `"source": "Pinterest"`. Based on the code, the listener log shows no `GET /tofu-poc`, i.e. no request is made.

## Expected behavior
The tool rejects values that are not `https` URLs on Pinterest hosts, and returns real metadata (or an error) for valid ones.

## Actual behavior
Any string is accepted and echoed back as Pinterest image information. From the fuzzing run (`image_url: "file:///etc/shadow"`):

```
Pinterest Image Information
{
  "image_url": "file:///etc/shadow",
  "source": "Pinterest",
  "timestamp": "2026-09-26T23:21:59.773Z"
}
```

No file was read and no request was made; the string is only reflected.

## Impact
Today the impact is low: the tool reports unverified input as if it came from Pinterest, which can mislead the model or the user. Tool arguments are chosen by the LLM and can be steered by prompt injection. If the handler is later changed to fetch the URL (the tool name suggests it should), the missing validation would let a steered agent make the server send requests to internal or local services that should not be reachable from it.

## Suggested fix
- Parse `image_url` with `new URL()`, require `https:`, and allow only Pinterest hosts (`i.pinimg.com`, `*.pinterest.com`).
- If fetching is added later, also resolve the host and refuse private, loopback and link-local addresses after DNS resolution, and disable redirects or re-check every redirect target.
- Until real lookup exists, consider documenting that the tool only echoes its input, or removing it.

## Status on the default branch
Still present at `b2b1b39` (2025-07-02). The tested commit is the current head of the default branch.

## Prior reports
- #5 "Add MseeP.ai badge to README" (PR, merged/closed 2025-05-05): a third-party badge PR whose dependency scan lists an axios SSRF advisory (GHSA-jr5f-v2jv-69x6) reached through `@myno_21/pinterest-scraper` / `googlethis`. It is about a transitive dependency, not `pinterest_get_image_info`, which makes no request. Not a report of this behaviour.
- No other related issue or PR among the 3 issues and 3 pull requests (fetched 2026-10-01).
- Documentation: `.ai/architecture.md` §4.2 documents the tool's output as "包含图片信息的对象（包括 URL、来源、时间戳）" ("an object with the image info: URL, source, timestamp"), which matches the echo-only behaviour; `README.md` describes it as "Get detailed information about a Pinterest image". Neither mentions URL validation. The architecture doc's security section (§7) covers download paths and file names only.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf; `check_strict_url_security_contract`, `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges` (plus `check_url_alternative_ip_representations` in the triggered set). All are input-side URL checks ("Validation Bypass Alert ... ACCEPTED").
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; e2-0922 1 exec / 1 ok (60 s budget).
- Evidence (verbatim, trimmed), corpus-sbx:
  - `{'image_url': ''}` -> `{"image_url": "", "source": "Pinterest", ...}`
  - `{'image_url': '/etc/passwd\x00'}` -> `{"image_url": "/etc/passwd\u0000", "source": "Pinterest", ...}`
  - `{'image_url': 'file:///etc/shadow'}` -> `{"image_url": "file:///etc/shadow", "source": "Pinterest", ...}`
- Hand-check hints: weak, likely false positive as SSRF. The handler (lines 498-531) has no network sink at all; the alerts fired because the URL was accepted, not because a request was made. Recommend not filing as a security issue; at most a low-priority "validate `image_url`" note. The repro step 4 is inferred from the code, not run. The server writes a few `console.log` lines to stdout at startup (e.g. line 73), which are not JSON-RPC; ToFu's runs completed, so the client tolerated them, but a strict client may log parse warnings.
</details>
