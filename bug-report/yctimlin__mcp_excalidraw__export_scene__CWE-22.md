# Path containment in `export_scene`: check does not resolve symlinks and defaults to the process working directory

**Repository:** `yctimlin/mcp_excalidraw` · **Tool:** `export_scene` · **Tested commit:** `713706e`
**Weakness:** CWE-22 Path Traversal

## Summary
`export_scene` writes the current canvas to `filePath`. The path goes through `sanitizeFilePath`, which blocks `../` escapes from the export directory, and that check held for every input in our run. Two gaps remain: the check compares `path.resolve()` strings and does not resolve symlinks, and the export directory defaults to `process.cwd()`, which for many MCP clients is the user's home or project directory. Inside that directory the tool overwrites any file, whatever its name or extension.

## Details
`src/core/normalize.ts:6-16` and `src/core/config.ts:14` (tested commit):

```ts
export const ALLOWED_EXPORT_DIR = process.env.EXCALIDRAW_EXPORT_DIR || process.cwd();

export function sanitizeFilePath(filePath: string): string {
  const resolved = path.resolve(filePath);
  const allowedDir = path.resolve(ALLOWED_EXPORT_DIR);
  if (!resolved.startsWith(allowedDir + path.sep) && resolved !== allowedDir) {
    throw new Error(`Path traversal blocked: ...`);
  }
  return resolved;
}
```

The handler (`src/core/mcp-dispatch.ts:469-491`) then calls `fs.writeFileSync(safePath, output, 'utf-8')`. `writeFileSync` follows symlinks, so a symlink inside the export directory that points elsewhere (for example `<dir>/out -> /tmp`) lets `out/tofu-poc.txt` pass the check and write outside it. The same helper guards `export_to_image` and `import_scene`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. A scratch directory with a symlink to show the gap: `mkdir -p /tmp/tofu-export && ln -s /tmp /tmp/tofu-export/out`.
2. Start the server with that directory as its working directory: `cd /tmp/tofu-export && npx -y mcp-excalidraw-server` (the canvas auto-starts on `127.0.0.1:3000`).
3. Call the tool with:

   ```json
   {"filePath": "out/tofu-poc.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-excalidraw-server"],
                                      cwd="/tmp/tofu-export")
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("export_scene", {"filePath": "out/tofu-poc.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc.txt` now contains the scene JSON, although `/tmp` is outside the export directory.

## Expected behavior
Exports land only under a dedicated export directory, resolved with `fs.realpathSync` (on both the directory and the target's parent), with an expected extension.

## Actual behavior
In the fuzzing run, Windows-style traversal strings on Linux were written as literal file names inside the export directory, which is the correct outcome:

```
Scene exported to /home/.../yctimlin__mcp_excalidraw/..\..\..\..\windows\win.ini (0 elements)
```

The symlink case above is derived from the code and was not part of the run.

## Impact
The LLM chooses `filePath`, and prompt injection can steer it. With the default (cwd) export root, a steered call can overwrite any file under the user's working directory with scene JSON or Obsidian Markdown, for example a config file in a project. Escaping that directory needs a pre-existing symlink. Medium/low.

## Suggested fix
- Default `ALLOWED_EXPORT_DIR` to a dedicated folder (for example `~/excalidraw-exports`) instead of `process.cwd()`.
- In `sanitizeFilePath`, `realpath` the allowed directory and the target's parent directory, then compare; refuse to write through an existing symlink (`fs.lstatSync`) or open with `O_NOFOLLOW`.
- Accept only `.excalidraw`, `.json`, `.md` (and `.png`/`.svg` for `export_to_image`).

## Status on the default branch
Still present at `713706e` (2026-09-08). The tested commit is the current default branch head.

## Prior reports
- #74 "security: authentication, path traversal, prompt injection, and hardening fixes" (PR, open 2026-04-16): item M2/M3, "Loose `sanitizeFilePath`", makes `EXCALIDRAW_EXPORT_DIR` mandatory and rejects home/root directories, which covers the cwd-default part of this report; it does not mention symlinks or `realpath`. Not merged: `ALLOWED_EXPORT_DIR` still defaults to `process.cwd()` on the default branch.
- #39 "Security audit: 7 vulnerabilities (2 critical, 3 high, 2 medium)" (issue, open 2026-02-08): the readable part of the body (first 4000 characters) covers authentication and CORS; it does not mention `export_scene` or `sanitizeFilePath`.
- #82 "fix(logger): platform-aware default log path instead of CWD" (PR, closed 2026-05-16, superseded by #83 which landed): explains that an MCP server child's "working directory is **the client's workspace**" and moved the log file out of it; the same reasoning applies to the export default, which was not changed.
- Documentation: README.md, Environment Variables: "`EXCALIDRAW_EXPORT_DIR` | Base directory MCP file exports may write to | current working dir" (the cwd default is documented; the symlink gap is not).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: partly reported, not fixed. Open PR #74 (M2/M3) proposes making EXCALIDRAW_EXPORT_DIR mandatory (the cwd-default part); unmerged, and the symlink gap is not mentioned anywhere.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, also `check_reflected_output` on this tool.
- Campaigns and executions: corpus-sbx 1024 exec / 384 ok; e2-0922 512 exec / 267 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'filePath': '..\\..\\..\\..\\windows\\win.ini'}` -> `Scene exported to /home/mza6485/toolfuzzer/eval/targets/yctimlin__mcp_excalidraw/..\\..\\..\\..\\windows\\win.ini (0 elements)`
  - `{'filePath': '"filePath": "..\\\\..\\\\..\\\\..\\\\windows\\\\win.in"'}` -> exported inside the same directory (2 elements).
  - `{'filePath': '"&ilePath": "..."'}` -> same.
- Hand-check hints: weak; the evidence is a false positive. `check_path_traversal` matched `..\` in the input string; on Linux `\` is not a separator, so every write stayed inside the export dir (cwd) and `sanitizeFilePath` worked. The symlink escape and the cwd default are from source reading, not run. Side note: if cwd is `/`, `allowedDir + path.sep` is `//` and every export is refused (functional bug, not security).
</details>
