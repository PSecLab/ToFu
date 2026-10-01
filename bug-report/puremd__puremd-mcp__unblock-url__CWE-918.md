# Unvalidated `url` in `unblock-url`: any text is appended to the pure.md request path, with no scheme or destination check

**Repository:** `puremd/puremd-mcp` · **Tool:** `unblock-url` · **Tested commit:** `48bc4d8`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`unblock-url` fetches `https://pure.md/<url>` and returns the response body. `url` is any string: it is not parsed, not limited to `http`/`https`, not encoded, and not checked for loopback or private destinations. The MCP server itself only ever connects to `pure.md`, so the local machine does not request internal addresses. Two smaller problems remain. Any blocking of internal targets is left entirely to the pure.md backend. And an empty or non-URL value selects arbitrary paths on `pure.md` itself, with the user's API token attached.

## Details
`src/index.ts:25-30` at `48bc4d8`:

```ts
server.tool("unblock-url", { url: z.string() }, async ({ url }) => {
  try {
    const response = await fetch(`https://pure.md/${url}`, {
      headers: { "x-puremd-api-token": PUREMD_API_KEY },
    });
    const markdown = await response.text();
    return {
      content: [{ type: "text", text: markdown }],
```

The schema is `z.string()`, so `""`, relative paths, `file:`-style strings, and URLs pointing at loopback or private addresses all pass. The host part of the request is fixed (`pure.md`), so the value cannot change where this process connects. It does decide which pure.md path is requested and which target the pure.md service is asked to fetch. `search-web` (`src/index.ts:45`) has a related gap: `query` is placed into `?q=` without `encodeURIComponent`, so `&` or `#` in a query changes the request.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and outbound HTTPS access to `pure.md`. An API key is optional; set `PUREMD_API_KEY=""` for anonymous use. In a separate terminal, start a listener on your own machine:
   ```
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install and start the server:
   ```
   git clone https://github.com/puremd/puremd-mcp.git
   cd puremd-mcp && git checkout 48bc4d8b16d9e1e78afbbedd3ed31bd250390056
   npm install && npm run build
   PUREMD_API_KEY="" node dist/index.js
   ```
3. Call the tool twice, first with a loopback URL, then with an empty string:
   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc"}
   {"url": ""}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"], env={"PUREMD_API_KEY": ""})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("unblock-url", {"url": "http://127.0.0.1:8099/tofu-poc"}))
               print(await session.call_tool("unblock-url", {"url": ""}))

   asyncio.run(main())
   ```
4. What to observe: for the first call the local listener should log no request, because the process only contacts `pure.md`; the result is whatever pure.md answers for that target (in the fuzzing run a loopback URL returned `Bad request`). For the second call the tool returns the HTML of the pure.md home page, which shows that the argument chooses a path on `pure.md` rather than a target URL.

## Expected behavior
The tool should accept only absolute `http`/`https` URLs, for example `z.string().url()` plus a scheme check, and should encode the value before placing it in the request path. It could also reject loopback, private and link-local hosts up front, so behavior does not depend only on the backend.

## Actual behavior
All inputs are forwarded. From the fuzzing run:

```
{'url': 'http://[::1]/'}  -> 'Bad request'      (isError: False)
{'url': ''}               -> '<!doctype html>\n<html>\n  <head>\n    ... <title>pure.md - global cache between LLMs and the web</title> ...'
```

Both calls returned `isError: false`. The loopback request was refused by pure.md, not by the MCP server.

## Impact
The LLM picks the URL, and prompt injection can steer it. Because the MCP process only talks to `pure.md`, this is not SSRF against the user's own network. The remaining risks are small. Whether pure.md can be made to fetch internal addresses on its own infrastructure depends on backend checks that this client does not duplicate. Non-URL input makes the tool request other pure.md paths with the user's token, and the result is reported as success.

## Suggested fix
- Change the schema to `z.string().url()` and reject anything whose `new URL(url).protocol` is not `http:` or `https:`.
- Build the request as `https://pure.md/${encodeURI(url)}`, or with whatever encoding the pure.md API expects for the target URL.
- Optionally resolve the target host and reject loopback, private, link-local and unique-local addresses before calling pure.md.
- Set `isError: true` when `response.ok` is false, so a refused fetch is not reported as success.
- In `search-web`, use `encodeURIComponent(query)`.

## Status on the default branch
Still present at `48bc4d8` (2025-04-01). The tested commit is the head of the default branch.

## Prior reports
- No issue or PR found. The repository has 0 issues and 2 pull requests (fetched 2026-10-01): #1 (Smithery deployment) and #2 (MseeP.ai badge, whose scan reports no findings). Neither is related.
- Documentation: README.md: "simply prefix any URL with `pure.md/`" and `unblock-url` "Extract markdown from web pages without getting blocked". This documents that any URL is meant to be passed through to pure.md; nothing documents input validation or which destinations pure.md refuses. No SECURITY.md or `docs/`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf via `check_url_ssrf_ip_ranges`, `check_url_hostname_canonicalization`, `check_url_structure_and_parsing`; `check_url_alternative_ip_representations` also triggered. All are input-side alerts (silent-bug: input flagged, tool returned normally).
- Campaigns and executions: corpus-sbx 512 exec / 512 ok (60 s); e2-0922 1 exec / 1 ok (60 s).
- Evidence (verbatim, trimmed): `{'url': ''}` -> pure.md home page HTML (it contains pure.md's public front-end config, including a Supabase anon key; not a repo secret, do not paste it); `{'url': 'http://[::1]/'}` -> `Bad request`, `isError: False`; `{'url': '/etc/passwd\x00'}` -> `Bad request`, `isError: False`.
- Hand-check hints: weak, likely a false positive as SSRF. The request host is hard-coded to `pure.md`, so no request from the user's machine reaches internal addresses; the loopback attempt in the log was refused by the pure.md backend. What is real is missing input validation and encoding, plus `isError: false` on failed fetches. The listener repro is expected to show no request; it was not run. Not verified: what pure.md does for private or link-local targets, and whether any pure.md path is sensitive when called with a user token.
</details>
