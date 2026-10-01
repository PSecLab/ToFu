# Path traversal in `manage_folder`: `path`/`newPath` escape the vault for create, move, rename and delete

**Repository:** `newtype-01/obsidian-mcp` · **Tool:** `manage_folder` · **Tested commit:** `dc048e4`
**Weakness:** CWE-22 Path Traversal

## Summary
`manage_folder` creates, renames, moves or deletes a folder at a caller-supplied `path` (and `newPath`)
inside the vault. When the Obsidian Local REST API is unreachable, every operation falls back to the
filesystem and joins the caller path to the vault root with no containment check. `../` segments resolve
outside the vault, so a caller can create folders anywhere the process can write, and rename/move/delete
directories outside the vault.

## Details
`handleManageFolder` dispatches to `createFolder` / `renameFolder` / `moveFolder` / `deleteFolder`
(`src/index.ts:1529`). Each filesystem fallback uses `path.join(VAULT_PATH, ...)` with no check that the
result stays under the vault:

```ts
private async createFolder(folderPath: string): Promise<void> {
  try { await this.api.post(`/folders/${encodeURIComponent(folderPath)}`); }
  catch (error) {
    const fullPath = path.join(VAULT_PATH, folderPath);   // 2461
    if (!fs.existsSync(fullPath)) { fs.mkdirSync(fullPath, { recursive: true }); }
  }
}
private async renameFolder(folderPath: string, newPath: string): Promise<void> {
  // ...
  const fullPath = path.join(VAULT_PATH, folderPath);      // 2477
  const newFullPath = path.join(VAULT_PATH, newPath);      // 2478
  fs.renameSync(fullPath, newFullPath);                    // 2494
}
```

`moveFolder` just calls `renameFolder` (`src/index.ts:2498`). `deleteFolder` resolves the same way
(`src/index.ts:2511`) and then calls `deleteFolderRecursive`, which removes the directory tree. `node`'s
`path.join` collapses `..`, and there is no `path.resolve` + `startsWith(VAULT_PATH)` guard anywhere in the
file. The fallback runs whenever the Local REST API is unreachable, the default when that Obsidian plugin is
not configured.

## Steps to reproduce
1. Prerequisites: Node 16+. Do not run the Obsidian Local REST API (so the filesystem fallback is used).
2. Build and point the server at an empty vault:
   ```
   npm install && npm run build
   mkdir -p /tmp/tofu-vault /tmp/tofu-poc
   ```
3. Call the tool (the non-destructive `create` operation is enough to show escape). Arguments as JSON:
   `{"operation": "create", "path": "../tofu-poc/newdir"}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["build/index.js"],
           env={"OBSIDIAN_VAULT_PATH": "/tmp/tofu-vault"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "manage_folder",
                   {"operation": "create", "path": "../tofu-poc/newdir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc/newdir` now exists, one directory above the vault root
   (`path.join('/tmp/tofu-vault', '../tofu-poc/newdir')` -> `/tmp/tofu-poc/newdir`). The `rename`/`move`/
   `delete` operations resolve `path`/`newPath` the same way.

## Expected behavior
Folder operations should be confined to the vault; a resolved path outside `VAULT_PATH` should be rejected.

## Actual behavior
The folder is created outside the vault and the tool reports success, e.g.
`{'content': [{'type': 'text', 'text': 'Folder created successfully at ../../../.{'}]}`.

## Impact
The `operation`, `path` and `newPath` arguments are chosen by the LLM and can be steered by prompt injection
from untrusted content. Beyond `create`, the `delete` operation is a recursive directory removal
(`deleteFolderRecursive`, `src/index.ts:2522`) whose target also resolves through the unchecked join, so an
attacker-influenced call can delete a directory tree outside the vault. `rename`/`move` can relocate
directories out of the vault. Impact is bounded by the server process's filesystem permissions.

## Suggested fix
Resolve `path` and `newPath` with `path.resolve(VAULT_PATH, x)` and reject them unless they remain under
`path.resolve(VAULT_PATH) + path.sep` before any `mkdir`/`rename`/recursive-delete. Apply the guard to all
four operations.

## Status on the default branch
Still present at `dc048e4` (2025-08-04). The current default branch head is the same commit that was tested.

## Prior reports
- #12 "[Potential Vulnerability] arbitrary file read / write / delete via the filesystem fallback in `obsidian-mcp`" (issue, open 2026-07-26): same root cause (unconfined `path.join(VAULT_PATH, ...)` in the filesystem fallback, "no `path.resolve(...).startsWith(VAULT_PATH)` check anywhere in the file"), verified against the same commit `dc048e4`. The fetched part of its body lists `read_note`, `create_note`, `delete_note`, `move_note` and `list_notes` but not `manage_folder`, so the folder create/rename/move/delete paths are not explicitly covered there. No fix.
- #14 "Request: enable Private Vulnerability Reporting (or share a security contact)" (issue, open 2026-08-19): asks for a private channel for an undisclosed issue and states a 90-day disclosure date of 17 November 2026. No details, so overlap is unknown.
- Documentation: README.md: "Dual API Strategy: Obsidian REST API with filesystem fallback for maximum reliability" (the fallback is documented as a feature; nothing says it is confined to the vault or warns about it). There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: root cause already reported in open issue #12, which does not name `manage_folder` in its fetched body. Not fixed. File as a comment on #12 adding `manage_folder` (create, rename, move, recursive delete) rather than as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` fired, `check_reflected_output`
  listed.
- Campaigns and executions: repo24 (171,520 / 9,667, 4200s) and e2-0922 (1,024 / 31, 60s).
- Evidence (verbatim, trimmed): input `{'operation': 'create', 'path': '"operation": "create", "path":
  "../../../.{"', 'newPath': ''}` -> `Folder created successfully at ...`. A `rename` evidence row with
  `newPath` `../etc/pa...` also returned success.
- Hand-check hints: REAL. All four folder ops use `path.join(VAULT_PATH, ...)` with no containment (create
  2461, rename 2477/2478, move via rename 2498, delete 2511). Same caveats as the other obsidian-mcp reports:
  the fallback only runs when the Local REST API is unreachable, and the evidence `path` strings are the
  fuzzer's malformed JSON blobs (they still contain literal `../`). I deliberately demonstrate with `create`
  (harmless) and only describe the recursive-delete risk in words; do not run a delete PoC.
</details>
