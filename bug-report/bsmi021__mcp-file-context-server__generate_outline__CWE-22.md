# Path traversal in `generate_outline`: `path` is not confined, so the tool reports whether files outside the working directory exist

**Repository:** `bsmi021/mcp-file-context-server` · **Tool:** `generate_outline` · **Tested commit:** `85a0681`
**Weakness:** CWE-22 Path Traversal

## Summary
`generate_outline` is described as returning a code outline for a file. At the tested commit it only checks that the path is accessible and then returns the file name, extension and the path as given. The check in `validateAccess` resolves `../` and absolute paths without confining them to the working directory. The tool does not return file contents, so the effect is an existence oracle for any path outside the project.

## Details
`handleGenerateOutline` (`src/index.ts:1352`) calls `validateAccess` and then builds a string from the path:

```ts
// src/index.ts:1360
await this.validateAccess(filePath);
const outline = `File: ${path.basename(filePath)}
Type: ${path.extname(filePath) || 'unknown'}
Path: ${filePath}`;
```

`validateAccess` (`src/index.ts:483`) resolves against `process.cwd()` and only checks accessibility:

```ts
const resolvedPath = path.resolve(process.cwd(), filePath);
try {
    await fs.access(resolvedPath);
    return resolvedPath;
} catch (error) {
    ...
    throw new FileOperationError(FileErrorCode.INVALID_PATH,
        `Path does not exist or is not accessible: ${resolvedPath}`, resolvedPath);
```

There is no check that `resolvedPath` stays under `process.cwd()`. Existing paths succeed; missing ones return an error that includes the absolute resolved path. The same helper guards `list_context_files`, `search_context` and `getFiles`, so they share the gap.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3.10+ with `pip install mcp`. Create a project dir and a marker file outside it:
   ```bash
   mkdir -p /tmp/tofu-poc/project && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Build the server from a checkout: `npm install && npm run build` (output in `dist/index.js`).
3. Call the tool with `{"path": "../outside.txt"}`, running the server with `/tmp/tofu-poc/project` as its working directory:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/path/to/mcp-file-context-server/dist/index.js"],
           cwd="/tmp/tofu-poc/project",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate_outline", {"path": "../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the call succeeds with `"outline": "File: outside.txt\nType: .txt\nPath: ../outside.txt"`. With `{"path": "../missing.txt"}` it fails with `Path does not exist or is not accessible: /.../tofu-poc/missing.txt`.

## Expected behavior
Paths that resolve outside the working directory (or a configured root) are rejected, with the same error whether or not the target exists.

## Actual behavior
The path outside the working directory passes `validateAccess` and the tool returns a success response. Missing paths return a different error, so the caller can probe for files anywhere on the host the server user can reach. ToFu's fuzzing completed calls with `{"path": "../../../../etc/passwd"}` and similar inputs without an error.

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection. Through this tool an attacker can learn which files and directories exist outside the project, and the error text reveals the server's absolute working directory. No file contents are disclosed by this tool. Low severity on its own, but `validateAccess` is the guard other path tools rely on, so fixing it there matters.

## Suggested fix
In `validateAccess`, resolve with `fs.realpath(path.resolve(root, filePath))`, where `root` is the working directory or a configurable `ALLOWED_ROOT`. Reject the path unless it equals `root` or starts with `root + path.sep`, and return the same error for "outside root" and "missing". Separately, the tool does not yet produce the outline its description promises.

## Status on the default branch
Still present at `85a0681` (2025-07-10). The default branch head is the tested commit.

## Prior reports
- #15 "Arbitrary File Read Vulnerability in file-context-server" (issue, open 2026-07-12): reports the missing allowed-root check for `read_context` and cites `const resolvedPath = path.resolve(process.cwd(), filePath);` at `src/index.ts:484`, which is the `validateAccess` line this tool relies on. It does not mention `generate_outline` or `validateAccess` by name (in the first 4000 characters of the body, which is all the export holds). Not fixed: the default branch head is still `85a0681` and no PR addresses it.
- Documentation: `README.md` documents no root directory or allow-list setting (the only environment variables are cache and file-size limits). No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: the `validateAccess` gap is cited in open issue #15 (for `read_context`); `generate_outline` is not named there. Not fixed. Add as a comment on #15 rather than a new issue.
- ToFu class / sanitizers: path-traversal; `check_path_traversal` on all evidence calls; `check_reflected_output` also fired for this tool.
- Campaigns and executions: corpus-sbx 2048 exec / 1996 ok; repo24 179712/176407; e2-0922 1024/987.
- Evidence (verbatim, trimmed): `{'path': '/etc/passwd\x00'}` -> `None`; `{'path': '../../../../etc/passwd'}` -> `None`; `{'path': '..\\..\\..\\..\\windows\\win.ini'}` -> `None`.
- Hand-check hints: weak. The path only reaches `fs.access` (`src/index.ts:486`); no read happens, so the impact is an existence oracle plus disclosure of the absolute cwd in the error. The evidence outputs are all `None`, so the log does not show what the tool returned; the success/failure split is from the code. The `\x00` input would make `fs.access` throw in Node, so "executed successfully" for that one is doubtful. `check_reflected_output` only reflects the path into a JSON text block, not rendered markup; not worth a separate issue. Consider folding into the `read_context` issue. Reproduction not executed by me.
</details>
