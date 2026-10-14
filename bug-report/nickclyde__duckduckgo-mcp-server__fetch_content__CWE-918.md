# SSRF hardening in `fetch_content`: the guard resolves the host separately from the connection (DNS-rebinding window)

**Repository:** `nickclyde/duckduckgo-mcp-server` · **Tool:** `fetch_content` · **Tested commit:** `8182af3`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`fetch_content` downloads a caller-supplied URL. By default it runs `_validate_public_url` on the URL and on every redirect hop, and refuses hosts that resolve to loopback, private, link-local, reserved, multicast or unspecified addresses. That guard works for direct addresses: a request to a local listener is refused. The remaining gap is the one your `SECURITY.md` already notes: the guard calls `getaddrinfo` itself, and then httpx or curl_cffi resolves the name again to connect. A hostname whose DNS answer changes between the two lookups can still reach a non-public address. This report is a request to close that window, not a new bypass.

## Details
`src/duckduckgo_mcp_server/server.py:685-719` at `8182af3`:

```python
    try:
        infos = await asyncio.to_thread(
            socket.getaddrinfo, host, port, 0, socket.SOCK_STREAM
        )
    ...
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        ...
        if (
            not ip.is_global
            ...
        ):
            raise BlockedURLError(
```

`_fetch_httpx` (`server.py:958-983`) then calls `await self._guard_url(current)` followed by `client.get(current, ...)` with the hostname, not the validated IP. `_fetch_curl` (`server.py:998-1011`) does the same. The docstring at lines 665-668 and the SSRF section of `SECURITY.md` describe this TOCTOU and call it out of scope. Everything else in the guard looked correct on reading: scheme allow-list, `localhost`/`.localhost` names, IPv4-mapped IPv6 unwrapping, `not is_global` as a catch-all, and per-hop re-validation with manual redirects.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. Start a local listener in a separate terminal:
   ```
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install the server from source:
   ```
   git clone https://github.com/nickclyde/duckduckgo-mcp-server.git
   cd duckduckgo-mcp-server && git checkout 8182af3f2295017ca90527a924f48147fbf18d5b
   uv venv .venv && source .venv/bin/activate
   uv pip install -e .
   ```
   The client script below starts it with `duckduckgo-mcp-server` (stdio, default settings, guard on).
3. Call the tool with these arguments:
   ```json
   {"url": "http://127.0.0.1:8099/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="duckduckgo-mcp-server", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("fetch_content", {"url": "http://127.0.0.1:8099/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: with the default settings the tool returns `Error: Refusing to fetch http://127.0.0.1:8099/tofu-poc (...)` and the listener logs no request. That is the expected, guarded behaviour. Adding `args=["--allow-private-urls"]` makes the listener log `GET /tofu-poc`, which is the documented opt-in. The rebinding window itself needs a hostname whose resolver returns a public address to the guard's lookup and the local listener's address to the client's lookup; it is not reproducible with a fixed address, so this report rests on code reading.

## Expected behavior
The address the HTTP client actually connects to is the same address the guard approved, so a changing DNS answer cannot move the request to a non-public host.

## Actual behavior
The guard approves the result of one DNS lookup, and the HTTP client performs its own lookup for the connection. The two results are not tied together.

## Impact
In MCP the LLM chooses the URL, and prompt injection in search results or fetched pages can steer it. An attacker who controls a domain's DNS could use the window to make the server send GET requests to loopback or internal services reachable from the host, and read the response text back through the tool. It needs attacker-controlled DNS with very short TTLs and a race, so the practical risk is low, as `SECURITY.md` already says.

## Suggested fix
Validate the address that is actually connected, not a separate lookup. Two common options: resolve once, check every address, then connect to the chosen IP while sending the original `Host` header and SNI (for httpx, a custom transport or `httpcore` network backend can do this); or check the socket's peer address right after connect and abort if it is not public. On the curl path, libcurl's `CURLOPT_RESOLVE` pins a host name to an address and may serve the same purpose through curl_cffi's `curl_options`.

## Status on the default branch
Still present at `8182af3` (2026-09-04). The tested commit is the head of the default branch.

## Prior reports
- #48 "`fetch_content` allows non-blind SSRF to localhost and internal network targets" (issue, closed 2026-07-01): the original direct SSRF (no host validation, automatic redirects). Fixed by #51; the guard this draft describes is that fix.
- #51 "fix(security): block SSRF to private/internal targets in fetch_content (#48)" (PR, closed 2026-07-01): added `_validate_public_url`, per-hop redirect checks and `--allow-private-urls`. Its body already notes the DNS-rebinding (TOCTOU) window and calls pinning the connection to the validated IP out of scope, which is exactly what this draft asks for.
- Documentation: SECURITY.md: "leaving a small DNS-rebinding (TOCTOU) window" (the residual risk is documented as known and accepted; the same file says to report vulnerabilities privately, not in a public issue)
- Documentation: README.md: "**SSRF protection:** By default `fetch_content` refuses URLs that resolve to" loopback, private and link-local addresses (documents the guard and the `--allow-private-urls` opt-out)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: known and documented. The direct SSRF was reported in #48 and fixed by #51; the DNS-rebinding window in this draft is acknowledged as out of scope in #51 and SECURITY.md. File only as a hardening request, if at all.
- ToFu class / sanitizers: ssrf. Fired: `check_url_structure_and_parsing`, `check_url_hostname_canonicalization`, `check_url_ssrf_ip_ranges` (the evidence rows), plus `check_strict_url_security_contract`, `check_url_alternative_ip_representations`, `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_resource_exhaustion` per `triggered`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok (60 s); e2-0922 1 / 1 (60 s). Only one execution per campaign.
- Evidence (verbatim, trimmed): `{'url': '', 'start_index': 0, 'max_length': 0, 'backend': '', 'parse_mode': ''}` -> `"Error: Unknown fetch backend ''. Supported: ('httpx', 'curl', 'auto')"`; `{'url': <absolute file path + \x00>, ..., 'backend': 'curl', 'parse_mode': 'main'}` -> `None`; `{'url': <relative ../ path>, ..., 'backend': None, 'parse_mode': None}` -> `None`. All three are "Silent Bug Alert: sanitizers flagged this input as malicious, but the target tool executed successfully".
- Hand-check hints: weak, likely a false positive as reported. None of the evidence shows an outbound request: the first input stops at the backend check, and the other two have no http(s) scheme, so `_validate_public_url` would reject them (the `None` outputs suggest the harness's `ctx` was missing, not a fetch). The guard is solid on reading, and the only residual issue (DNS rebinding) is already documented by the maintainer in `SECURITY.md` and the docstring. I would not file this as a vulnerability; at most a hardening issue, or skip it. `SECURITY.md` asks for private reporting.
</details>
