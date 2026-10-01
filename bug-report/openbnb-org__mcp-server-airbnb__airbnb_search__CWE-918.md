# `airbnb_search` (reported as SSRF): all requests go to fixed hosts; no caller-controlled destination found

**Repository:** `openbnb-org/mcp-server-airbnb` · **Tool:** `airbnb_search` · **Tested commit:** `d5a8f18`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF) (as flagged by the fuzzer; not confirmed)

## Summary
`airbnb_search` builds an Airbnb search URL from `location` and the filter arguments, optionally geocodes `location` through Photon and Nominatim first, then fetches the page. Our fuzzer flagged it as SSRF, but no request log from that run survived. Reading the code, every request goes to one of three hard-coded hosts. `location` is URL-encoded into a path segment or a query string, and the other string arguments are added through `URLSearchParams`. I could not find a way for a caller to choose the destination host. This draft records the review so the alert can be closed.

## Details
The search URL, `index.ts:423-426`:

```ts
  const slug = location
    .replace(/,\s*/g, "--")   // "Paris, France" → "Paris--France"
    .replace(/\s+/g, "-");    // remaining spaces → single dash
  const searchUrl = new URL(`${BASE_URL}/s/${encodeURIComponent(slug)}/homes`);
```

`BASE_URL` is the constant `https://www.airbnb.com` (`index.ts:150`). `placeId`, `checkin`, `checkout`, `cursor` and the numeric filters go in through `searchUrl.searchParams.append` (`index.ts:429-474`). The geocoders use fixed hosts with `encodeURIComponent(location)` in the query: `https://photon.komoot.io/api/?q=...` (`index.ts:186`) and `https://nominatim.openstreetmap.org/search?q=...` (`index.ts:233`). The page fetch is `fetchWithUserAgent(searchUrl.toString())` (`index.ts:543`). Geocoding can be turned off with `DISABLE_GEOCODING=true` (`index.ts:303`).

## Steps to reproduce
1. Prerequisites: Node.js and network access to `www.airbnb.com`. Start a local listener so you can see whether the server connects to it:

   ```sh
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Start the server as the README describes, with geocoding off to limit outbound calls: `DISABLE_GEOCODING=true npx -y @openbnb/mcp-server-airbnb`. To test the tested commit, run `npm install && npm run build` in a checkout at `d5a8f18`, then `node dist/index.js`.
3. Call the tool with a URL in place of the location:

   ```json
   {"location": "http://127.0.0.1:8099/tofu-poc", "ignoreRobotsText": false}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@openbnb/mcp-server-airbnb"], env={"DISABLE_GEOCODING": "true"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("airbnb_search", {"location": "http://127.0.0.1:8099/tofu-poc", "ignoreRobotsText": False})
               print(result)

   asyncio.run(main())
   ```
4. Expected from the code: the listener logs no request. The server requests `https://www.airbnb.com/s/http%3A%2F%2F127.0.0.1%3A8099%2Ftofu-poc/homes?...` and returns Airbnb results or an error from that host.

## Expected behavior
Requests stay on Airbnb and the geocoder hosts.

## Actual behavior
Matches the expected behavior per the code. No fuzzing log is available for this tool, so there is no observed output to quote.

## Impact
None found for SSRF. A `location` of exactly `.` or `..` is left as a dot segment and normalized by the URL parser, so the request goes to a different path on `www.airbnb.com` (for example `/homes`). The host does not change, so this is not a security issue.

## Suggested fix
No security fix needed. Optionally reject `location` values that are only `.` or `..`.

## Status on the default branch
Unchanged at `d5a8f18` (2026-08-05). The tested commit is the current head of the default branch.

## Prior reports
- No SSRF or destination-control report. Searched all 33 issues and 29 pull requests (fetched 2026-10-01).
- #60 "Hardcoded BASE_URL breaks both tools from non-US IPs: airbnb.com returns a domain-handoff stub, not the page" (issue, open 2026-08-10), #61 "fix: detect Airbnb country-domain handoff and allow overriding the domain" (PR, open 2026-08-10) and #39 "fix: use airbnb.ca as base URL to avoid Canadian JS-redirect" (PR, open 2026-07-14): all touch `BASE_URL`. The PRs would add an `AIRBNB_BASE_URL` environment variable set by the operator, not by the tool caller, so the destination would still not be caller-controlled. None is merged at `d5a8f18`.
- Documentation: README.md "External Services": "In addition to `airbnb.com`, the server makes geocoding requests to two third-party services" (Photon and Nominatim, with `DISABLE_GEOCODING` to opt out). This documents the fixed outbound hosts and supports the false-positive verdict.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918). Triggered for this tool: `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`, `check_resource_exhaustion`. These are input-side URL checks; which argument they fired on is unknown.
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget. One unsuccessful execution plus `check_resource_exhaustion` suggests a timeout (for example no network in the sandbox), but that is a guess.
- Evidence: none. `log_available: false`, so the reproduction above is derived from the code only.
- Hand-check hints: **weak, false positive** for SSRF. All three fetch targets are constants (`index.ts:150`, `:186`, `:233`); caller input is only ever encoded into the path or query. The `.`/`..` dot-segment note is from code reading, based on the WHATWG URL parser's dot-segment normalization. Not executed. Recommend not filing.
</details>
