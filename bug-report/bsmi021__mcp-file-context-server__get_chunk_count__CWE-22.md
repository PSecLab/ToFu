# Path traversal in `get_chunk_count`: `path` reads files outside the working directory and leaks their existence and size

**Repository:** `bsmi021/mcp-file-context-server` · **Tool:** `get_chunk_count` · **Tested commit:** `85a0681`
**Weakness:** CWE-22 Path Traversal

## Summary
`get_chunk_count` tells the client how many chunks `read_context` will return for a path. It reads the target through the same `readContent` function as `read_context`, which has no check that the path stays inside the server's working directory. The tool returns only a chunk count, so on its own it discloses whether a file or directory outside the project exists and roughly how large it is. The underlying read is unrestricted.

## Details
`handleGetChunkCount` (`src/index.ts:764`) passes `args.path` to `readContent` (`src/index.ts:790`), which resolves and reads it without containment:

```ts
// src/index.ts:773
const filesInfo = await this.readContent(filePath, encoding as BufferEncoding, maxSize, recursive, fileTypes);
const totalChunks = this.getTotalChunks(filesInfo);

// src/index.ts:797 (readContent)
const absolutePath = path.resolve(filePath);
...
content = await fs.readFile(absolutePath, encoding);   // :831
```

`validateAccess` (`src/index.ts:483`) is not called here, and it would not help: it only checks that the path exists. For a directory, `readContent` reads every file under it recursively (`src/index.ts:852`, `:879`).

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
               result = await session.call_tool("get_chunk_count", {"path": "../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the call succeeds with `{"totalChunks": 1, "chunkSize": 65536}`. Repeat with `{"path": "../missing.txt"}` and it fails, so the tool distinguishes existing from missing files outside the project.

## Expected behavior
Paths that resolve outside the working directory (or a configured root) are rejected before anything is read.

## Actual behavior
The file outside the working directory is read in full and its chunk count is returned: `{"totalChunks": 1, "chunkSize": 65536}` for the marker file. A missing path returns an error instead, which makes the tool an existence and size oracle for any path the server process can read.

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection. Through this tool alone an attacker learns whether paths outside the project exist and their approximate size. The same unchecked read in `read_context` returns the contents, so the fix should cover both. Low severity on its own.

## Suggested fix
Fix it once in `readContent`: resolve with `fs.realpath(path.resolve(root, input))` against the working directory (or a configurable `ALLOWED_ROOT`) and reject the call unless the result equals the root or starts with `root + path.sep`. Check each glob match the same way.

## Status on the default branch
Still present at `85a0681` (2025-07-10). The default branch head is the tested commit.

## Prior reports
- #15 "Arbitrary File Read Vulnerability in file-context-server" (issue, open 2026-07-12): reports the same unconfined read for `read_context`, citing the `fs.readFile(absolutePath, encoding)` sink at `src/index.ts:831` that `get_chunk_count` also reaches through `readContent`. It does not mention `get_chunk_count` (in the first 4000 characters of the body, which is all the export holds). Not fixed: the default branch head is still `85a0681` and no PR addresses it.
- Documentation: `README.md` documents no root directory or allow-list setting (the only environment variables are cache and file-size limits). No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: root cause already reported in open issue #15 (for `read_context`, same `readContent` sink); this tool is not named there. Not fixed. Add as a comment on #15 rather than a new issue.
- ToFu class / sanitizers: path-traversal; `check_path_traversal` only.
- Campaigns and executions: corpus-sbx 512 exec / 1 ok; repo24 three runs 23040/9531, 28160/11237, 20992/9123; e2-0922 1024/186.
- Evidence (verbatim, trimmed): corpus-sbx `{'path': '"path": "/etc/passwd\\u0000", "encoding": ...', 'encoding': '', 'maxSize': 0.0, ...}` -> `None`; repo24 `{'path': '"path":.\\\\..\\\\..\\\\..\\\\windows\\\\win.ini", ...', ...}` -> `{"totalChunks": 0, "chunkSize": 65536}`.
- Hand-check hints: real code path but low impact for this tool. `args.path` reaches `fs.readFile` unchecked (`src/index.ts:831`), but the tool returns only a count, so it is an existence/size oracle. The logged evidence is weak: the repo24 path uses Windows backslashes on Linux, so it resolved to a single junk-named entry under cwd, not a traversal. Why that call succeeded with `totalChunks: 0` instead of an ENOENT I could not determine from the code (an entry with that name would have had to exist in the sandbox cwd); do not quote this output as proof of traversal. The traversal is established from the code. Best filed together with `read_context` as one issue. Reproduction not executed by me.
</details>
