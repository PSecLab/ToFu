# [Likely false positive, do not file as is] Path traversal check in `insert_part_from_library`: `..` and absolute paths are already rejected by the addon

**Repository:** `neka-nat/freecad-mcp` · **Tool:** `insert_part_from_library` · **Tested commit:** `3da6db5`
**Weakness:** CWE-22 Path Traversal (reported by the fuzzer; not confirmed)

## Summary
`insert_part_from_library` asks the FreeCAD addon, over XML-RPC, to merge a part from the parts library into the active document. The fuzzer flagged it because traversal strings were accepted as input without an exception. In the fuzzing environment FreeCAD was not running, so every call failed with "Connection refused" before any file was touched. At the tested commit the addon already resolves the path and refuses anything outside the parts library, and unit tests cover both the `..` and the absolute-path cases.

## Details
`addon/FreeCADMCP/rpc_server/parts_library.py:7-25` (tested commit):

```python
def insert_part_from_library(relative_path):
    parts_lib_path = os.path.join(FreeCAD.getUserAppDataDir(), "Mod", "parts_library")
    parts_lib_real = os.path.realpath(parts_lib_path)
    part_path = os.path.realpath(os.path.join(parts_lib_path, relative_path))

    # os.path.join drops parts_lib_path for an absolute relative_path, and
    # neither join nor realpath rejects a ".." that walks outside it.
    if os.path.commonpath([part_path, parts_lib_real]) != parts_lib_real:
        raise ValueError(f"relative_path escapes the parts library: {relative_path}")

    if not os.path.exists(part_path):
        raise FileNotFoundError(f"Not found: {part_path}")
    ...
    FreeCADGui.ActiveDocument.mergeProject(part_path)
```

`realpath` collapses `..` and follows symlinks, and `commonpath` then requires the result to be inside the library. `tests/test_parts_library.py:59-82` checks that an absolute path and `../../../secret.FCStd` both raise `ValueError` and that nothing is merged. The MCP side (`src/freecad_mcp/server.py:426-452`, `src/freecad_mcp/operations/core.py:159-177`) only forwards `relative_path` to `127.0.0.1:9875`.

## Steps to reproduce
1. Prerequisites: FreeCAD with the `FreeCADMCP` addon installed as the README describes, and its RPC server started ("Start RPC Server" in the FreeCAD MCP toolbar). Python with `uv`.
2. Start the MCP server as the README describes: `uvx freecad-mcp`. The client below does this itself.
3. Call the tool with a traversal path and with an absolute path:

   ```json
   {"relative_path": "../../../../../../tmp/tofu-poc.FCStd", "include_screenshot": false}
   ```
   ```json
   {"relative_path": "/tmp/tofu-poc.FCStd", "include_screenshot": false}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["freecad-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for p in ["../../../../../../tmp/tofu-poc.FCStd", "/tmp/tofu-poc.FCStd"]:
                   result = await session.call_tool("insert_part_from_library", {"relative_path": p, "include_screenshot": False})
                   print(p, result)

   asyncio.run(main())
   ```
4. Observe `Failed to insert part from library: relative_path escapes the parts library: ...` for both. The check runs before the existence check, so `/tmp/tofu-poc.FCStd` does not need to exist.

## Expected behavior
Paths outside the parts library are refused.

## Actual behavior
Based on the code and its tests, they are refused. The fuzzing run never reached FreeCAD:

```
{'relative_path': '/etc/passwd\x00', 'include_screenshot': True, 'view_name': 'Top'}          -> Failed to insert part from library: [Errno 111] Connection refused
{'relative_path': '../../../../etc/passwd', 'include_screenshot': True, 'view_name': 'Isometric'} -> Failed to insert part from library: [Errno 111] Connection refused
```

## Impact
None found. The tool cannot merge files from outside the parts library.

## Suggested fix
None needed.

## Status on the default branch
Unchanged at `d6bbe4b` (2026-09-25): `parts_library.py` is identical to the tested commit, so the check is still in place.

## Prior reports
- #121 "insert_part_from_library has no path-containment check on relative_path" (issue, closed 2026-08-26): the same weakness, reported for the code before the fix (`..` and absolute paths reached `mergeProject`).
- #122 "fix(rpc): constrain insert_part_from_library to the parts library" (PR, closed 2026-08-26, "Fixes #121"): adds the `realpath` + `commonpath` check and `tests/test_parts_library.py`. This is the check quoted in Details; it is on the tested commit and on the default branch at `d6bbe4b`, so the issue is fixed.
- #26 "Improve security, code quality, and project structure" (PR, closed 2025-11-16): proposed a path check in `parts_library.py` among unrelated changes; per #121 its author closed it without review.
- Documentation: docs/tools.md: "Insert a part from the FreeCAD parts library" (describes the intended scope); docs/configuration.md warns that `execute_code` "runs arbitrary Python inside FreeCAD with your user's permissions", so path containment in this tool is not the security boundary.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in #121 and fixed by #122 (both closed 2026-08-26); the fix is present at the tested commit 3da6db5 and at HEAD d6bbe4b. Do not file.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (input-pattern "silent bug" alert) plus `check_introspection_ssrf`. The SSRF alert is the MCP server's own fixed XML-RPC connection to `127.0.0.1:9875` (`freecad_client.py:27-37`, `server.py:81`), so that is a false positive too.
- Campaigns and executions: corpus-sbx 3072 exec / 2937 ok; e2-0922 1024 exec / 971 ok (60 s budgets).
- Evidence (verbatim, trimmed): three calls (`/etc/passwd\x00`, `../../../../etc/passwd` twice with different `view_name` / `include_screenshot: 'yes'`), all `Failed to insert part from library: [Errno 111] Connection refused`.
- Hand-check hints: false positive (counted as weak). Containment exists at the tested commit and at HEAD, with tests. The checkout is shallow, so I could not see when the check was added. Recommend not filing. Unrelated to this item: the server also exposes `execute_code`, which runs arbitrary Python in FreeCAD by design, so file-path containment in this tool is not the security boundary anyway.
</details>
