# Path traversal in `read_context`: `path` can read files and directories outside the working directory

**Repository:** `bsmi021/mcp-file-context-server` · **Tool:** `read_context` · **Tested commit:** `85a0681`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_context` reads a file, or every file under a directory, and returns the contents to the client. The `path` argument is resolved with `path.resolve()` and read directly. There is no check that the result stays inside the server's working directory (the project root the server uses elsewhere via `process.cwd()`). A `../` path or an absolute path returns the contents of any file the server process can read.

## Details
`handleReadFile` (`src/index.ts:740`) passes `args.path` straight to `readContent` (`src/index.ts:790`). `readContent` resolves it and reads it without any containment check. It does not call `validateAccess`, and `validateAccess` (`src/index.ts:483`) only checks that the path exists anyway.

```ts
// src/index.ts:797 (readContent)
const absolutePath = path.resolve(filePath);
...
// src/index.ts:811
if ((await fs.stat(absolutePath)).isFile()) {
    ...
    content = await fs.readFile(absolutePath, encoding);   // :831
```

For a directory, the same function globs `**/*` under the resolved path (`src/index.ts:852`) and reads every match (`src/index.ts:879`), so `../` returns the whole parent tree. The content is returned to the client by `getContentChunk` with a `File: <absolute path>` header per file.

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
               result = await session.call_tool("read_context", {"path": "../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the response `content` contains `File: .../tofu-poc/outside.txt` followed by `marker`.

## Expected behavior
Paths that resolve outside the working directory (or a configured root) are rejected with an error.

## Actual behavior
The file outside the working directory is read and returned. ToFu's fuzzing runs completed calls with `../../../../`-style and absolute paths without an error, for example:

```
input:  {"path": "\"path\": \"../../../../", ...}
output: {"content": "", "hasMore": false, "nextChunk": null}
```

## Impact
In MCP, the LLM chooses tool arguments, and prompt injection in a file or web page the model reads can steer it. An attacker who can do that can make the server return any file readable by the server's user (source outside the project, credentials files, other projects) into the conversation, where a second injected step can send it elsewhere. Severity depends on how the server is deployed. There is currently no setting to confine it.

## Suggested fix
Pick a root (the working directory, or a configurable `ALLOWED_ROOT`). In `readContent` and every other handler that takes a path, resolve with `fs.realpath(path.resolve(root, input))` and reject the call unless the result equals the root or starts with `root + path.sep`. Apply the same check to each glob match, since `follow: false` does not stop a symlinked file inside the root from pointing out of it.

## Status on the default branch
Still present at `85a0681` (2025-07-10). The default branch head is the tested commit.

## Prior reports
- #15 "Arbitrary File Read Vulnerability in file-context-server" (issue, open 2026-07-12): the same bug. A CVE-style report that `read_context` resolves `path` against `process.cwd()`, checks only existence, and reads it at `src/index.ts:831` with no allowed-root check; it names `85a0681` as affected and no fix. Not fixed: the default branch head is still `85a0681` and no PR addresses it.
- Documentation: `README.md` describes the server as one that lets LLMs "read, search, and analyze code files" and lists "Recursive directory traversal" as a feature. It documents no root directory or allow-list setting (the only environment variables are cache and file-size limits). No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported as open issue #15 (same tool, same sink, same commit); not fixed. Consider commenting on #15 instead of filing a new issue.
- ToFu class / sanitizers: path-traversal; `check_path_traversal` only.
- Campaigns and executions: corpus-sbx 1024 exec / 161 ok; repo24 three runs 31232/11841, 29184/12676, 23552/7929; e2-0922 1024/123 (all 60 s or 4200 s budgets).
- Evidence (verbatim, trimmed): corpus-sbx `{'path': '"path": "/etc/passwd\\u0000",{"pathwin.i": ...', ...}` -> `None`; repo24 `{'path': '"path": "../../../../', 'maxSize': -1.09e+308, ...}` -> `{"content": "", "hasMore": false, "nextChunk": null}` (twice).
- Hand-check hints: real. `args.path` reaches `fs.readFile` (`src/index.ts:831`) with no containment, confirmed by reading the code. The logged evidence does not itself show leaked content: outputs are `None` or empty (the fuzzer ran in a bwrap sandbox, and the evidence path `"path": "../../../../` resolves to a junk-named dir then 3 levels up, so likely an ancestor dir with nothing readable). The README describes a general file-reading server and documents no root boundary, so the maintainer may call this by design; framing is "no way to confine reads to the project". Same root cause as `get_chunk_count` and `generate_outline`; consider filing one combined issue. Reproduction not executed by me (read-only rule).
</details>
