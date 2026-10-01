# Path traversal in `browse_vault_structure`: `../` in `path` leaves the `/vault/` route of the Local REST API

**Repository:** `pmmvr/obsidian-api-mcp-server` · **Tool:** `browse_vault_structure` · **Tested commit:** `9a93913`
**Weakness:** CWE-22 Path Traversal

## Summary
`browse_vault_structure` lists a vault folder by requesting `/vault/<path>/` from the Obsidian Local REST API. `path` is URL-quoted with `/` and `.` left as-is, and httpx removes `..` segments before sending the request, so `../x` becomes a request for `/x/` instead of a folder inside the vault. In recursive mode, request errors are swallowed and the tool reports `success: true` with an empty listing. The tool cannot list files on disk outside the vault by itself; that boundary sits in the Obsidian plugin.

## Details
`src/obsidian_mcp/server.py:143-146` strips quotes and whitespace and passes the rest to the client. `src/obsidian_mcp/client.py:42-51` builds the URL at `9a93913`:

```python
    async def list_directory(self, path: str = "") -> List[str]:
        if path:
            # Just URL encode the path and try it directly
            encoded_path = quote(path, safe='/')
            endpoint = f"/vault/{encoded_path}/"
        else:
            endpoint = "/vault/"

        result = await self._request("GET", endpoint)
        return result.get("files", [])
```

`quote(path, safe='/')` never encodes `.` or `/`, so `../x` stays `../x`. `_request` (`client.py:15-25`) sends the URL with httpx, which drops dot segments per RFC 3986 (`httpx/_urlparse.py`, `normalize_path`), so `/vault/../x/` goes out as `/x/`, with the `Authorization` header attached. In `browse_vault` (`client.py:73-96`), the recursive branch wraps every request in `except Exception: pass`, which is why the logged calls with `recursive: true` returned `success: true` with no items even though no server was reachable.

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
   {"path": "../tofu-poc", "include_files": true, "recursive": false}
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
               result = await session.call_tool("browse_vault_structure", {
                   "path": "../tofu-poc",
                   "include_files": True,
                   "recursive": False,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the listener's log: it shows `"GET /tofu-poc/ HTTP/1.1" 404`, not a request under `/vault/`. With `"recursive": true`, the same request is made and the tool still returns `"success": true` with an empty listing.

## Expected behavior
The tool rejects any `path` with a `..` segment (or an absolute path) before making a request, so every request stays under `/vault/`. Request failures in recursive mode are reported, not turned into an empty success.

## Actual behavior
The request leaves `/vault/`. In the fuzzing run, Obsidian was not running, yet recursive calls reported success:

```
input:  {"path": "/etc/passwd\x00", "include_files": true, "recursive": true}
output: {"success": true, "path": "/etc/passwd\u0000", ..., "directories": [], "files": [], "total_items": 0}
```

## Impact
In MCP the LLM chooses `path`, and prompt injection from untrusted content (for example a note the agent reads) can steer it. With this tool an attacker can send authenticated GET requests to Local REST API routes other than `/vault/` on the configured server, and only the `files` array of the response is returned. I have not checked which routes would return a `files` array. The tool cannot reach other hosts or list files outside the vault unless the plugin allows it. Low severity. The silent `success: true` on errors is a separate reliability problem: an agent cannot tell an empty folder from a failed request.

## Suggested fix
- Reject `path` values that contain a `..` or `.` segment, start with `/`, or contain a backslash, before calling `browse_vault`.
- In `ObsidianClient.list_directory`, quote each segment separately (`"/".join(quote(p, safe="") for p in path.split("/"))`) and assert that the final URL path starts with `/vault/`.
- In the recursive branch of `browse_vault`, at least propagate the error for the starting folder instead of `pass`.

## Status on the default branch
Still present at `9a93913` (2025-05-31). The default branch head is the tested commit.

## Prior reports
None found. Searched all 0 issues and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. The README's only security note is about not hardcoding `OBSIDIAN_API_KEY`; nothing documents or restricts the `path` argument.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal` (input-pattern match only). Also fired: `check_introspection_ssrf` (connection to `127.0.0.1:27124`, the default `OBSIDIAN_API_URL`, so expected behaviour, not SSRF), `check_reflected_output` (`path` echoed in the reply).
- Campaigns and executions: corpus-sbx 3072 exec / 3068 ok (60 s); e2-0922 512 exec / 508 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'path': '/etc/passwd\x00', 'include_files': True, 'recursive': True}` -> `success: true`, empty listing.
  - `{'path': '../../../../etc/passwd', 'include_files': True, 'recursive': False}` -> `"Failed to browse vault structure for path '../../../../etc/passwd': All connection attempts failed"`.
  - `{'path': '..\\..\\..\\..\\windows\\win.ini', 'include_files': False, 'recursive': True}` -> `success: true`, empty listing.
- Hand-check hints: weak, and ToFu's framing (directory listing outside a root) does not fit. Obsidian was not running, so no request got a response; the "success" results are the swallowed-exception path. Verified by code reading: `..` survives `quote(..., safe='/')` and httpx 0.28 drops dot segments (read in a local httpx 0.28.0 copy; uv.lock pins 0.28.1). Effect is limited to other routes of the same Local REST API with the user's key attached. I did not verify the plugin's route list. Repro uses only the local listener and was not executed. Consider one combined issue with `get_note_content`.
</details>
