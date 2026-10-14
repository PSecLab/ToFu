# `get_code`: `localPath` is not checked to be absolute, and generated file paths are not contained under it

**Repository:** `f2c-ai/f2c-mcp` · **Tool:** `get_code` · **Tested commit:** `84f7408`
**Weakness:** CWE-22 Path Traversal

## Summary
`get_code` converts a Figma node to code and, when `localPath` is set, writes the generated files and images under that directory. The schema says `localPath` must be an absolute path, but the handler accepts relative values and `../` segments and resolves them against the server's working directory. The generated files are then written to `path.join(localPath, file.path)`, where `file.path` comes from the F2C API response, with no check that the result stays under `localPath`. This is a low-severity hardening issue: the caller can already pick any absolute `localPath` by design.

## Details
The schema is at `src/server/figma/tools/v03.ts:43-48` at `84f7408`:

```ts
      localPath: z
        .string()
        .optional()
        .describe(
          'Absolute path for asset(e.g., images) and code storage. Directory will be created if non-existent. ...',
        ),
```

The handler passes it straight to the downloader (`v03.ts:65-69`). `src/server/figma/helpers/downloader.ts:14-19` stores it, and `downloader.ts:129-144` writes each generated file:

```ts
  async saveContentToFile(content: string, filePath: string): Promise<string> {
    try {
      const fullPath = path.join(this.savePath, filePath)
      const dirPath = path.dirname(fullPath)
      ...
      await this.ensureDirectoryExists(dirPath)
      ...
      await fsp.writeFile(fullPath, content)
```

There is no `path.isAbsolute(localPath)` check, no `path.resolve` plus prefix check on `fullPath`, and `ensureDirectoryExists` creates any missing parent directories. `fsp.writeFile` overwrites existing files. Images are written the same way under `<localPath>/assets` (`downloader.ts:27-47`). `fileKey` and `ids` are sent as URL query parameters (`src/server/figma/apis/f2c.ts:53-67`), so they do not reach the filesystem.

## Steps to reproduce
1. Prerequisites: Node.js 18+, `bun`, a Figma personal access token, and the file key and a node id of a Figma design you own. Create an empty working folder:

   ```bash
   mkdir -p /tmp/tofu-poc/root
   ```
2. Install and build as `docs/en/GettingStarted.md` describes:

   ```bash
   git clone https://github.com/f2c-ai/f2c-mcp.git
   cd f2c-mcp && git checkout 84f7408
   bun install && bun run build
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with a relative `localPath`:

   ```json
   {"fileKey": "<your file key>", "ids": "<your node id>", "localPath": "../out", "imgFormat": "png", "scaleSize": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/path/to/f2c-mcp/dist/stdio.js"],
           env={"FIGMA_API_KEY": "<your token>"},
           cwd="/tmp/tofu-poc/root",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_code", {
                   "fileKey": "<your file key>",
                   "ids": "<your node id>",
                   "localPath": "../out",
                   "imgFormat": "png",
                   "scaleSize": 1,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply says `## Save Location\n../out`, and the generated files appear in `/tmp/tofu-poc/out/`, outside the working folder, although the schema requires an absolute path.

## Expected behavior
A relative `localPath` is rejected (or resolved and shown as an absolute path before writing). Every generated file path is resolved and rejected unless it stays under `localPath`.

## Actual behavior
Relative and `../` values are accepted. In the fuzzing run every call failed at the API with a 404 before anything was written, and no call was rejected for its path:

```
input:  {"fileKey": "ABCDEFGH12345678", "ids": "1:2", "personalToken": "", "localPath": "../../../../etc/passwd", "imgFormat": "png", "scaleSize": 1}
output: Error: HTTP error! status: 404
```

## Impact
In MCP the LLM chooses `localPath`, and prompt injection from untrusted content (for example text inside a Figma design or a linked page) can steer it. Because `localPath` is meant to be any directory, the extra reach from relative paths is small; the main effect is that files land somewhere other than what the user sees in the reply. The second point depends on the F2C API: if a response ever contained a `file.path` with `../` segments or an absolute path, the server would write outside `localPath` and overwrite files there. I have not seen such a response.

## Suggested fix
- In the handler, reject `localPath` unless `path.isAbsolute(localPath)`, and report `path.resolve(localPath)` in the reply.
- In `saveContentToFile` and `downloadImage`, compute `const root = path.resolve(this.savePath); const full = path.resolve(root, filePath);` and skip the file unless `path.relative(root, full)` is non-empty and does not start with `..` and is not absolute.
- Optionally refuse to overwrite existing files unless the caller opts in.

## Status on the default branch
Still present at `84f7408` (2025-11-26). The default branch head is the tested commit.

## Prior reports
- #55 "Security Report — Path Traversal via API-Controlled File Paths in figma_to_code" (issue, open 2026-04-19): reports the same sink, `path.join(this.savePath, filePath)` in `saveContentToFile` (`helpers/downloader.ts`), with an API-supplied `file.path` escaping `localPath`, and proposes a `path.resolve` plus prefix check. It names `figma_to_code`, whose registration is commented out on the default branch; `get_code` uses the same `downloader` singleton. Not fixed: the default branch head `84f7408` (2025-11-26) predates the report. It does not mention the missing absolute-path check on `localPath`.
- Searched all 38 issues and 17 pull requests (fetched 2026-10-01); no other item mentions `localPath`, path validation or traversal. #4 "Feature/download image and replace image path" (PR, closed 2025-05-22) has an empty body; by its title it added the local image download, and it describes no path checks.
- Documentation: README.md: "F2C automates downloading Figma images to local assets for efficiency." (no warning or restriction on where files are written). The "Absolute path" requirement exists only in the tool schema description.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: the API-controlled file.path containment part is already reported in open issue #55 (same saveContentToFile sink, under the tool name figma_to_code); not fixed. The relative-localPath part is new. Reference #55 instead of filing a duplicate.
- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal` only (input-pattern match on `../` or `/etc/passwd`). No tracer-based file alert fired.
- Campaigns and executions: e2-0922, 1 exec / 0 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'fileKey': '../../../../etc/passwd', 'ids': '1:2', 'personalToken': '', 'localPath': '/tmp/output', ...}` -> `Error: HTTP error! status: 404` (fileKey goes into a query parameter; no filesystem effect).
  - `{'fileKey': 'ABCDEFGH12345678', 'ids': '1:2', 'personalToken': '', 'localPath': '../../../../etc/passwd', ...}` -> `Error: HTTP error! status: 404`.
  - `{'fileKey': 'ABCDEFGH12345678', ..., 'localPath': '/tmp/output; cat /etc/passwd', ...}` -> `Error: HTTP error! status: 404`.
- Hand-check hints: weak, close to a misclassification. All logged calls failed at the remote API before `downloader.checkLocalAndDownload` could write anything; the alert is input-pattern only. `localPath` is documented as an arbitrary absolute directory, so traversal in it adds little. The two concrete gaps (no absolute-path check despite the schema text, and no containment of API-supplied `file.path`) are verified by code reading only. Repro needs a real Figma token and design, was not executed, and I did not confirm `dist/stdio.js` is the build output name beyond the `inspector` script in `package.json`. I did not check what `file.path` values the F2C API returns.
</details>
