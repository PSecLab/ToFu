# `manage_workspace`: path-traversal sanitizer fired, but the workspace path containment held

**Repository:** `aaronsb/google-workspace-mcp` · **Tool:** `manage_workspace` · **Tested commit:** `ccdf507`
**Weakness:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Summary
`manage_workspace` does file CRUD inside a sandboxed workspace directory. ToFu flagged its `mkdir` operation as a possible path traversal. On review, the `filename`/`path` argument is run through `sanitizePath` and `resolveWorkspacePath`, which reject `..`/`.` segments and strip separators, and the evidence shows the created directory landing inside the workspace with the dangerous characters replaced by `_`. The containment held in every evidence row. This is most likely a false positive; it is written up so a maintainer can confirm the containment is complete and that no other operation reaches a file op without it.

## Details
Every `manage_workspace` operation resolves its argument through `resolveWorkspacePath` then `verifyPathSafety`. `mkdir`, `src/server/handlers/workspace.ts:260-277`:

```ts
const dirName = (params.path as string) || (params.filename as string);
if (!dirName) throw new Error('path is required');
...
const dirPath = resolveWorkspacePath(dirName);
await verifyPathSafety(dirPath);
await fs.mkdir(dirPath, { recursive: true, mode: 0o755 });
```

`resolveWorkspacePath` (`src/executor/workspace.ts:161-175`) calls `sanitizePath`, which throws on a bare `..` or `.` segment and replaces separators and other dangerous characters per segment (`sanitizeFilename`, lines 117-133), then re-checks that the resolved path is still under the workspace root. `verifyPathSafety` (lines 181-194) additionally rejects symlink escapes via `fs.realpath`.

## Steps to reproduce
1. Prerequisites: Node.js 22.12+. No account needed. Point `XDG_CONFIG_HOME`/`XDG_DATA_HOME` at a temp directory.
2. Build the tested commit: `git clone https://github.com/aaronsb/google-workspace-mcp.git && cd google-workspace-mcp && git checkout ccdf507 && npm ci && npm run build`.
3. Call `mkdir` with a traversal-style name:

   ```json
   {"operation": "mkdir", "path": "../../../../tmp/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["build/index.js"],
           env={"XDG_CONFIG_HOME": "/tmp/tofu-gws/config", "XDG_DATA_HOME": "/tmp/tofu-gws/data"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("manage_workspace",
                   {"operation": "mkdir", "path": "../../../../tmp/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: `sanitizePath` throws on the `..` segments, so the call returns an error and no directory is created outside the workspace. (A name with `..` embedded inside a larger segment, as in the fuzzing input, is not a bare `..` segment and is instead flattened to `_`, landing inside the workspace.)

## Expected behavior
Every file operation stays inside the workspace directory. That is what the code does here.

## Actual behavior
The directory was created inside the workspace, with the traversal characters neutralized. From the fuzzing run the returned path was under the server's workspace scratch directory:

```
Directory created: **"operation": "move", ... "../:c" ...**

**Path:** /home/<user>/.tofu_scratch/.../workspace/_operation_ _move_, _, _path_ _, _soure_c_ _/_c_ _/ca/s/peswd_, _destinati
```

## Impact
No traversal is demonstrated. The only observed effect is that an unusual `filename` produces an oddly named directory inside the workspace. If a maintainer confirms containment across all operations, there is no security impact here.

## Suggested fix
No change required if containment is confirmed. Optional hardening: reject or normalize names that flatten to long `_`-runs so that malformed input does not create confusing directory names; keep the existing `sanitizePath` + `verifyPathSafety` checks on every operation.

## Status on the default branch
`src/server/handlers/workspace.ts` and `src/executor/workspace.ts` are unchanged between `ccdf507` and `14c25e6` (2026-10-01); the containment behavior is the same.

## Prior reports
- #191 "fix(calendar,drive): repair what live exercise caught after the #187–#190 merge" (PR, closed 2026-08-22): the maintainer notes "`verifyPathSafety` early-returns on `ENOENT`, so on the write path the symlink check is a no-op" and leaves it unfixed. The code is unchanged at `14c25e6` (`src/executor/workspace.ts`). This is a known containment gap in the same check this draft relies on: for a path that does not exist yet (`mkdir`, `write`), a symlinked parent inside the workspace is not caught. The `..` rejection in `sanitizePath` is not affected.
- #80 "feat(workspace): nested directories, move, and mkdir" (PR, closed 2026-03-27): added `sanitizePath` ("rejecting `..`/`.` traversal") and the `mkdir` operation. This is the containment the draft confirms.
- #69 "feat: workspace file CRUD + unified file output for containerized agents" (PR, closed 2026-03-18): introduced `manage_workspace` "jailed to workspace via `resolveWorkspacePath`" and asked reviewers to check bypasses, symlink following and TOCTOU. No follow-up report of a bypass found.
- Documentation: README.md: "`manage_workspace` | File operations in the workspace sandbox" (containment is the documented behaviour).
- Documentation: SECURITY.md: "**DO NOT** open a public issue on GitHub" (security reports go by email to aaronsb@gmail.com).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_path_traversal`, `check_temp_file_leak`.
- Campaigns and executions: `corpus-sbx` 1,536/792 and `e2-0922` 1,024/586, 60 s each.
- Evidence (verbatim, trimmed): row 1 input `operation: mkdir`, `filename: '"operation": "move", """, "path": "", "soure:c" "../:c" "../.ca/s/peswd", "destinati\x00...'` -> output `Directory created: **...** **Path:** /home/<user>/.tofu_scratch/.../workspace/_operation_ _move_, _, _path_ _, _soure_c_ _/_c_ _/ca/s/peswd_, _destinati`. All three rows are "silent bug" (check_path_traversal fired, tool succeeded).
- Hand-check hints: weak / likely false positive. The embedded `../` fragments are not bare `..` segments after `split('/')`, so `sanitizeFilename` flattens them to `_` and the path stays inside the workspace — which the output `Path:` confirms. I did not find any `manage_workspace` operation that reaches a file op without `resolveWorkspacePath` + `verifyPathSafety`. Recommend not filing unless hand-check finds a bypass of `sanitizePath`.
</details>
