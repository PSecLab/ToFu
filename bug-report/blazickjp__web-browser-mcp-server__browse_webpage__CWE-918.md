# SSRF in `browse_webpage`: `url` is fetched with no restriction on loopback or private destinations

**Repository:** `blazickjp/web-browser-mcp-server` · **Tool:** `browse_webpage` · **Tested commit:** `97f66a9`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`browse_webpage` fetches a URL with `aiohttp` and returns the page title, text and links. The caller's `url` goes straight to `session.get()`. There is no scheme check beyond what aiohttp enforces, no host or IP check, and redirects are followed. The server can therefore be pointed at services on the local machine or the private network it runs in, and their response text is returned to the caller.

## Details
`src/web_browser_mcp_server/server.py:84-120` (tested commit):

```python
    url = arguments["url"]
    selectors = arguments.get("selectors", {})

    async with aiohttp.ClientSession() as session:
        try:
            headers = {"User-Agent": settings.USER_AGENT}
            timeout = aiohttp.ClientTimeout(total=settings.REQUEST_TIMEOUT)

            async with session.get(url, headers=headers, timeout=timeout) as response:
                if response.status >= 400:
                    return [types.TextContent(type="text", text=f"Error: HTTP {response.status} - Failed to fetch webpage")]
                html = await response.text()
                soup = BeautifulSoup(html, "html.parser")
                result = {"title": ..., "text": soup.get_text(strip=True), "links": [...]}
                ...
                return [types.TextContent(type="text", text=str(result))]
```

`session.get()` uses aiohttp's default `allow_redirects=True`, so a public URL that redirects to an internal address is followed as well. Non-HTTP schemes such as `file://` are rejected by aiohttp itself, which is why the fuzzer's `file:///etc/passwd` attempt only returned an error.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. In a separate terminal, start a local listener: `python3 -m http.server 8099 --bind 127.0.0.1`
2. Install the server as the README describes: `uv tool install web-browser-mcp-server` (or, for the tested commit, clone the repo and run `uv run web-browser-mcp-server` from it).
3. Call the tool with:

   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["tool", "run", "web-browser-mcp-server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("browse_webpage", {"url": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the listener's log: it shows `"GET /tofu-poc HTTP/1.1"` from `127.0.0.1`. The tool replies `Error: HTTP 404 - Failed to fetch webpage` because the path does not exist; for a path that returns 200, the page text would be returned in the reply.

## Expected behavior
By default the tool refuses URLs whose host resolves to a loopback, private, link-local or otherwise non-public address, checks every redirect hop the same way, and accepts only `http` and `https`. Users who need local access can opt in through a setting.

## Actual behavior
Any reachable URL is fetched. The fuzzing run itself only recorded calls that failed before a connection (empty URL, a NUL-containing path, `file://`):

```
{'url': '', 'selectors': {}}                                -> Error: 
{'url': '/etc/passwd\x00', 'selectors': {'etc': '#file'}}   -> Error: /etc/passwd%00
{'url': 'file:///etc/passwd', 'selectors': {'file': 'body'}} -> Error: file:///etc/passwd
```

The missing destination check is shown by the source above and by the reproduction.

## Impact
The LLM chooses `url`, and prompt injection in a page the agent has just browsed can tell it which URL to open next. An attacker can then make the server send GET requests to hosts only the user's machine or network can reach, such as local admin consoles, development servers or internal web apps, and read back the text of the responses. When the server runs in a container or a hosted environment, the same applies to that environment's internal network. Only GET requests with a fixed user agent are possible, which limits what can be changed on the target, but reading internal pages is enough to leak data.

## Suggested fix
- Accept only `http` and `https`.
- Resolve the host and reject the request if any resolved address is loopback, private, link-local, unique-local, multicast or unspecified (`ipaddress.ip_address(addr).is_global` is a good default test).
- Do the check at connect time to avoid DNS rebinding, for example with a custom resolver on `aiohttp.TCPConnector`, or pass `allow_redirects=False` and validate each `Location` before following it.
- Offer an explicit opt-in setting (for example `ALLOW_PRIVATE_NETWORK=true`) for users who browse local services on purpose.

## Status on the default branch
Still present at `97f66a9` (2025-03-05). The tested commit is the current default branch head.

## Prior reports
- Issues and pull requests: none related. Searched all 2 issues and 4 pull requests (fetched 2026-10-01); they cover start-up and install problems, a Dockerfile and badges.
- Documentation: `README.md` describes the purpose as letting AI assistants "browse and extract content from the web" (fetching caller-chosen URLs is the intended feature). The only documented setting is `REQUEST_TIMEOUT`; there is no allow-list, private-network option or security note. No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918). Evidence calls fired `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges` (input-pattern "silent bug" alerts) and once `check_strict_markitdown_security_contract`. `triggered` for the tool also lists `check_introspection_ssrf`, `check_url_alternative_ip_representations`, `check_strict_url_security_contract`, `check_resource_exhaustion`, `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`; none of those is in the three evidence calls.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; e2-0922 512 exec / 512 ok (60 s budgets). All three evidence calls are from corpus-sbx.
- Evidence (verbatim, trimmed): see "Actual behavior". The Markdown alert on the `file://` call fired because the error text contains the path `/etc/passwd`; nothing was read.
- Hand-check hints: real. The URL reaches `aiohttp.ClientSession.get` with no destination check (confirmed in source, `server.py:84-92`), and the response text is returned. The logged evidence does not show a connection to an internal host; `check_introspection_ssrf` in `triggered` suggests one happened in e2-0922, but no call record for it is in the item, so the reproduction is derived from source. For a local stdio browsing tool, fetching arbitrary URLs is the feature; the case for a fix is the default reachability of loopback/private hosts under prompt injection. Repro follows the coordinator's SSRF rule (local listener on 127.0.0.1:8099 only).
</details>
