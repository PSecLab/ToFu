# Missing output encoding in `create_subdirectory`: `name` is echoed raw, and is not kept inside the download folder

**Repository:** `dazeb/markdown-downloader` · **Tool:** `create_subdirectory` · **Tested commit:** `3d4394b`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create_subdirectory` creates a folder under the configured download directory and replies with the full path. The caller's `name` goes into that path, and into the reply, without any checks. The echo in the reply is low severity because the reply is plain MCP text. The same missing check also lets `name` point outside the download directory, which matters more.

## Details
`src/index.ts:334-371` (tested commit):

```ts
const subdirectoryName = request.params.arguments?.name;
if (!subdirectoryName || typeof subdirectoryName !== 'string') { throw new McpError(...); }
try {
  const config = getConfig();
  const newSubdirectoryPath = path.join(config.downloadDirectory, subdirectoryName);
  await fs.ensureDir(newSubdirectoryPath);
  return { content: [{ type: 'text', text: `Subdirectory created: ${newSubdirectoryPath}` }] };
```

`name` is any non-empty string. `path.join` resolves `..` segments, and `fs.ensureDir` creates every missing parent. No check confirms that the result is still under `config.downloadDirectory`, and the full path is echoed back unchanged.

## Steps to reproduce
1. Prerequisites: Node.js 18+. The server writes its config to `~/.config/markdown-downloader/config.json` and uses `~/.markdown-downloads` by default.
2. Install and build as the README describes: `git clone https://github.com/dazeb/markdown-downloader.git && cd markdown-downloader && npm install && npm run build`
3. Call the tool with:

   ```json
   {"name": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create_subdirectory", {"name": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Subdirectory created: <download dir>/<b>tofu-poc</b>` with the markup unchanged. A folder with that literal name now exists in the download directory; remove it afterwards.

## Expected behavior
`name` is limited to a single safe path segment (no `/`, `\`, `..`, or control characters), the resolved path is checked to stay under the download directory, and the reply does not echo unchecked text.

## Actual behavior
From the fuzzing run (host path shortened):

```
Subdirectory created: <download dir>/"\x7f\x7fw{{"w"\x7fw"w
```

## Impact
The LLM chooses `name`, and prompt injection can steer it. The echoed path goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. For the echo alone, low severity. Because the path is not contained, a `name` such as `../../tmp/tofu-poc` would also create directories outside the download folder, wherever the server user can write (from code reading, not run).

## Suggested fix
Reject names that are not a single segment, for example `if (path.basename(name) !== name || name === '..' || /[\x00-\x1f]/.test(name)) throw ...`. Then resolve and check containment: `const target = path.resolve(root, name); if (!target.startsWith(path.resolve(root) + path.sep)) throw ...`. Echo only the validated name.

## Status on the default branch
Still present at `3d4394b` (2025-07-18). The tested commit is the current default branch head.

## Prior reports
- #12 "Path Traversal Vulnerability in dazeb/markdown-downloader" (issue, open 2026-04-27): reports, at the same commit `3d4394b`, that `create_subdirectory` passes `subdirectoryName` to `path.join(config.downloadDirectory, ...)` and `fs.ensureDir` with no root check (plus the same problem in `download_markdown` and `list_downloaded_files`). This is the containment part of this draft, already reported and not fixed. It does not mention the raw echo of the path in the reply.
- #5 "Add MseeP.ai badge to README" (PR, closed 2025-05-03): its scan summary lists semgrep "Potential path traversal in fs module" findings in `src/index.ts` (lines 24 and 25 named, 11 more not shown). A general signal only; no fix followed.
- Documentation: README.md "Security": "Local files are saved with sanitized filenames". The README does not document `create_subdirectory` at all, and subdirectory names are not sanitized. README also documents `set_download_directory`, which lets a caller move the download root to any existing writable directory, so the root is caller-controlled by design.
- Searched all 5 issues and 5 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: the path-escape part of this draft is already reported in #12 (open, not fixed at `3d4394b`); the raw echo (the CWE-79 part) is not reported anywhere. If filing, file as a comment on #12 or drop.
- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 1014 ok (60 s). Not seen in e2-0922 or repo24-b.
- Evidence (verbatim, trimmed; the real output contained the fuzz host's scratch path, replaced here):
  - `{'name': '"\x7f\x7fw{{"w"\x7fw"w'}` -> `Subdirectory created: <scratch>/home/.markdown-downloads/"\x7f\x7fw{{"w"\x7fw"w`
  - `{'name': '"\x7f\x7fw{{"w"\x7fw"w\x7f'}` -> same shape.
- Hand-check hints: weak as XSS (only `{{` echoed into a plain-text reply; confirmed at `index.ts:346-355`). The `<b>` payload is my substitution and was not run. The real issue in this handler is CWE-22: `path.join(downloadDirectory, name)` plus `fs.ensureDir` with no containment check (`index.ts:346-349`), so `../` in `name` creates directories outside the download root. That is from code reading; I did not run it. Check whether a separate CWE-22 draft exists for this tool or for `download_markdown`'s `subdirectory`, and consider filing that instead of this one.
</details>
