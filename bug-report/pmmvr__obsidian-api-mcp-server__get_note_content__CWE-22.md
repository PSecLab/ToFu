# Path traversal in `get_note_content`: `../` in `path` leaves the `/vault/` route of the Local REST API

**Repository:** `pmmvr/obsidian-api-mcp-server` · **Tool:** `get_note_content` · **Tested commit:** `9a93913`
**Weakness:** CWE-22 Path Traversal

## Summary
`get_note_content` fetches a note through the Obsidian Local REST API by requesting `/vault/<path>`. The `path` argument is URL-quoted with `/` and `.` left as-is, and httpx removes `..` segments from the URL before sending it. A `path` such as `../x` therefore turns into a request for `/x` on the API instead of a note inside the vault. The tool is annotated `readOnlyHint: true` and documented as reading a note "within the vault", but it can be pointed at other API routes. It does not read files from disk outside the vault; that boundary is enforced, if at all, by the Obsidian plugin.

## Details
`src/obsidian_mcp/server.py:107-125` passes `path` straight to the client, and `src/obsidian_mcp/client.py:34-40` builds the URL at `9a93913`:

```python
    async def get_note_metadata(self, path: str) -> Dict[str, Any]:
        encoded_path = quote(path, safe='/')
        return await self._request(
            "GET",
            f"/vault/{encoded_path}",
            headers={"Accept": "application/vnd.olrapi.note+json"}
        )
```

`urllib.parse.quote(path, safe='/')` never encodes `.` or `/`, so `../x` stays `../x`. `_request` (`client.py:15-25`) joins it to `OBSIDIAN_API_URL` and sends it with httpx. httpx normalizes the path per RFC 3986 section 5.2.4 (`httpx/_urlparse.py`, `normalize_path`), so `/vault/../x` is sent as `/x`. The request carries the `Authorization: Bearer <OBSIDIAN_API_KEY>` header. Neither the tool nor the client rejects `..` segments or checks that the final path is still under `/vault/`.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. Obsidian is not needed: a local listener stands in for the API. Do not set `OBSIDIAN_API_KEY` for this test, so no key is sent to the listener. Start the listener in an empty folder:

   ```bash
   mkdir -p /tmp/tofu-poc/www && cd /tmp/tofu-poc/www
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install as the README describes (development install):

   ```bash
   git clone https://github.com/pmmvr/obsidian-api-mcp-server.git
   cd obsidian-api-mcp-server && git checkout 9a93913
   uv venv && uv pip install -e .
   ```
3. Call the tool with:

   ```json
   {"path": "../tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="/path/to/obsidian-api-mcp-server/.venv/bin/obsidian-api-mcp",
           args=[],
           env={"OBSIDIAN_API_URL": "http://127.0.0.1:8099"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_note_content", {"path": "../tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the listener's log: it shows `"GET /tofu-poc HTTP/1.1" 404`, not `GET /vault/../tofu-poc` or `GET /vault/tofu-poc`. Calling with `{"path": "tofu-poc"}` shows `GET /vault/tofu-poc` for comparison.

## Expected behavior
The tool rejects any `path` with a `..` segment (or an absolute path) before making a request, so every request stays under `/vault/`.

## Actual behavior
The request leaves `/vault/` and goes to another route of the configured API. In the fuzzing run, Obsidian was not running, so every call failed with a connection error, but no call was rejected for its path:

```
input:  {"path": "../../../../etc/passwd"}
output: {"success": false, "error": "Failed to get note at path '../../../../etc/passwd': All connection attempts failed", "data": null}
```

## Impact
In MCP the LLM chooses `path`, and prompt injection from untrusted content (for example a note or web page the agent reads) can steer it. With this tool, an attacker can make authenticated GET requests to Local REST API routes other than `/vault/`, on the server the user configured. I have not checked which of those routes return data that `/vault/` would not. The tool cannot reach other hosts, and it cannot read files outside the vault unless the Obsidian plugin itself allows that. Low severity; the main issue is that the tool does more than its read-only "note within the vault" contract says.

## Suggested fix
- Reject `path` values that contain a `..` or `.` segment, start with `/`, or contain a backslash, for example by splitting on `/` and checking each part, before calling `get_note_metadata`.
- In `ObsidianClient`, build vault URLs from per-segment quoting (`"/".join(quote(p, safe="") for p in path.split("/"))`) and assert the final URL path starts with `/vault/`.
- Apply the same helper in `list_directory` (used by `browse_vault_structure`).

## Status on the default branch
Still present at `9a93913` (2025-05-31). The default branch head is the tested commit.

## Prior reports
None found. Searched all 0 issues and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. The README's only security note is about not hardcoding `OBSIDIAN_API_KEY`; nothing documents or restricts the `path` argument.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal` (input-pattern match only). Also fired: `check_introspection_ssrf` (connection to `127.0.0.1:27124`, which is the default `OBSIDIAN_API_URL`, so expected behaviour, not SSRF), `check_reflected_output` (the error echoes `path`).
- Campaigns and executions: corpus-sbx 3072 exec / 3066 ok (60 s); e2-0922 512 exec / 506 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'path': '/etc/passwd\x00'}` -> `"Failed to get note at path '/etc/passwd\\u0000': All connection attempts failed"`
  - `{'path': '../../../../etc/passwd'}` -> same connection error.
  - `{'path': '/var/log/../etc/shadow'}` -> same connection error.
- Hand-check hints: weak, and ToFu's framing (file read outside a root) does not fit. Obsidian was not running in the campaign, so no request ever got a response. Verified by code reading: `quote(..., safe='/')` keeps `..`, and httpx 0.28 `normalize_path` drops dot segments (read in a local httpx 0.28.0 copy; uv.lock pins 0.28.1). So `../` can only move the request to other routes of the same Local REST API, with the user's API key attached. I did not verify the plugin's route list or whether any non-`/vault/` GET route leaks more than the vault already exposes. Repro uses only the local listener and was not executed. Side note (out of scope): `client.py:19` sets `verify=False` for all requests (documented in README for self-signed certs).
</details>
