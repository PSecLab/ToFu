# `clear-auth-cookies`: lossy host-to-filename mapping lets a `url` for one host clear another host's saved cookies

**Repository:** `ananddtyagi/webpage-screenshot-mcp` · **Tool:** `clear-auth-cookies` · **Tested commit:** `cad4a14`
**Weakness:** CWE-694 Use of Multiple Resources with Duplicate Identifier

## Summary
`clear-auth-cookies` deletes the saved cookie file for the host in `url`. The file name is the hostname with every `.` replaced by `_`, so different hosts map to the same file: `a.b.example` and `a_b.example` both become `a_b_example.json`. A call for one host can delete the saved login of another host. The same helper names the files that `login-and-wait` and `screenshot-page` write and read, so those tools share the collision.

## Details
`src/index.ts:255-262` builds the cookie file name, and `src/index.ts:699-702` deletes it:

```ts
function getDomainFromUrl(url: string): string {
    try {
        const urlObj = new URL(url);
        return urlObj.hostname.replace(/\./g, '_');
    } catch {
        return 'unknown';
    }
}
// clear-auth-cookies handler
const domain = getDomainFromUrl(url);
const cookiesPath = path.join(cookiesDir, `${domain}.json`);
await fsPromises.unlink(cookiesPath);
```

`_` is a legal character in a URL hostname, so the `.` to `_` replacement is not reversible. The `url` argument is only checked with `z.string().url()` (`src/index.ts:691`), which accepts any scheme. Every URL without a host (for example `file:///x`) maps to the same file, `.json`. The deletion itself stays inside `~/.mcp-screenshot-cookies`: a parsed hostname cannot contain `/` or `\`, and dots are rewritten.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and npm. This tool does not start a browser. The server reads `os.homedir()`, which follows `$HOME`, so the steps below point `HOME` at a scratch directory.
2. Build the server as the README describes, and create a marker file that stands in for saved cookies of `a.b.example`:
   ```sh
   git clone https://github.com/ananddtyagi/webpage-screenshot-mcp && cd webpage-screenshot-mcp
   npm install && npm run build
   mkdir -p /tmp/tofu-poc/.mcp-screenshot-cookies
   echo '[]' > /tmp/tofu-poc/.mcp-screenshot-cookies/a_b_example.json
   ```
3. Call the tool with `{"url": "http://a_b.example/"}`:

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/path/to/webpage-screenshot-mcp/dist/index.js"],
           env={"HOME": "/tmp/tofu-poc", "PATH": os.environ["PATH"]},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("clear-auth-cookies", {"url": "http://a_b.example/"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the tool reports `Cookies cleared for domain: a_b_example`, and `/tmp/tofu-poc/.mcp-screenshot-cookies/a_b_example.json` (the file used for `a.b.example`) is gone.

## Expected behavior
Clearing cookies for `http://a_b.example/` removes only the cookies saved for `a_b.example`. Each host has its own cookie file.

## Actual behavior
The call removes the file that `login-and-wait` and `screenshot-page` use for `a.b.example`, and reports `Cookies cleared for domain: a_b_example`. The reported name is the lossy file name, not the host that was passed in. During fuzzing the tool accepted every URL that parsed and answered in the same form, for example `No cookies found for domain: <derived name>`.

## Impact
Low. The LLM picks `url`, and prompt injection can steer it. In this tool the collision adds little, because a steered call can already clear any host by name, or all hosts by omitting `url`. The same naming in `screenshot-page` matters slightly more: with `useSavedAuth` (default `true`), screenshotting a page on `a_b.example` that sets cookies overwrites the saved login for `a.b.example` (`src/index.ts:609-613`).

## Suggested fix
- Name cookie files with a collision-free encoding of the hostname, for example `encodeURIComponent(hostname)` or a SHA-256 hex digest of it. Existing files would need a one-time rename.
- Restrict `url` to `http:` and `https:` in the zod schema (`z.string().url().refine(u => ['http:', 'https:'].includes(new URL(u).protocol))`), so hostless URLs cannot share `.json`.

## Status on the default branch
Still present at `cad4a14` (2025-06-28). The tested commit is the current head of the default branch.

## Prior reports
No issue or PR reports the cookie file name collision. Searched all 2 issues and 3 pull requests (fetched 2026-10-01). Related context only:
- #3 "Mark `clear-auth-cookies` as destructive" (issue, open 2025-08-22): asks to annotate this tool as destructive for the Claude Desktop extension submission. Same tool, different concern; not about file naming.
- #4 "Claude desktop extension feedback" (issue, open 2025-09-18): repeats the request for read-only/destructive tool annotations (naming `clear-auth-cookies`) and an SDK update. Not about file naming.
- Documentation: README.md: "Cookies are automatically saved for each domain you visit" in "the `.mcp-screenshot-cookies` directory in your home folder", and `clear-auth-cookies` "Clears saved authentication cookies for a specific domain or all domains". This implies one file per domain; it does not mention the `.` to `_` mapping. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `ssrf` (CWE-918). Fired: `check_strict_url_security_contract`, `check_url_alternative_ip_representations`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`. These are input-shape checks; the analysis text reports no observed request.
- Campaigns and executions: corpus-sbx 3072 exec / 631 success (60 s); e2-0922 1536 / 325 (60 s).
- Evidence (verbatim, trimmed):
  - `{'url': 'http://[::1]'}` -> `No cookies found for domain: [::1]`
  - `{'url': 'http://2130706433'}` -> `No cookies found for domain: 127_0_0_1`
  - `{'url': 'http://0177.0.0.1'}` -> `No cookies found for domain: 127_0_0_1`
- Hand-check hints: **weak.** ToFu's class is wrong. `clear-auth-cookies` makes no network request; `url` only selects a file under `~/.mcp-screenshot-cookies` to unlink (`src/index.ts:699-702`). No path traversal either. The draft is re-framed as the cookie-file name collision, CWE changed from 918 to 694; verify that choice. I checked hostname parsing with Node 22's built-in `URL`, not with repo code: `http://a_b.example/` and `http://a.b.example/` both give `a_b_example.json`; `2130706433` and `0177.0.0.1` normalize to `127.0.0.1` (so ToFu's "non-canonical IP accepted" is the URL parser canonicalizing, which is correct); `file:///x` gives `.json`. The reproduction relies on `os.homedir()` honoring `$HOME` on POSIX. Not run. Consider not filing separately and folding this into the `screenshot-page` issue.
</details>
