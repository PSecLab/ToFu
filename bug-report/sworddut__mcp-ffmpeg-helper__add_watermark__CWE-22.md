# Path traversal in `add_watermark`: `inputPath`, `watermarkPath` and `outputPath` are not confined, so output can be written or overwritten anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `add_watermark` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`add_watermark` overlays the image at `watermarkPath` on the video at `inputPath` and writes the result to `outputPath`. None of the three paths is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates the output's parent directories and passes `-y`, so an existing file at `outputPath` is overwritten without asking. A caller can read media from anywhere the server user can read and write output anywhere that user can write.

## Details
`src/tools/handlers.ts:107-114` and `:138`:

```ts
case "add_watermark": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const watermarkPath = validatePath(String(args?.watermarkPath), true);
  const outputPath = validatePath(String(args?.outputPath));
  const position = String(args?.position || "bottomright");
  const opacity = Number(args?.opacity || 0.5);

  await ensureDirectoryExists(outputPath);
  ...
  const command = `-i "${inputPath}" -i "${watermarkPath}" -filter_complex "...overlay=${overlayPosition}..." -codec:a copy "${outputPath}" -y`;
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and, for inputs, that the file exists. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })`. Nothing resolves the paths or compares them with an allowed root. (`position` maps to fixed strings and `opacity` is converted with `Number()`, so neither is a concern.)

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`, and the paths are only wrapped in double quotes. A `"`, `` ` `` or `$(...)` in `outputPath` is interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a test video, a watermark image and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=1:size=64x64:rate=1 -pix_fmt yuv420p /tmp/tofu-in.mp4
   ffmpeg -f lavfi -i color=c=red:s=16x16 -frames:v 1 /tmp/tofu-wm.png
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
   {"inputPath": "/tmp/tofu-in.mp4", "watermarkPath": "../../../../../../../../tmp/tofu-wm.png", "outputPath": "../../../../../../../../tmp/tofu-poc/watermarked.mp4", "position": "center", "opacity": 0.5}
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
               result = await session.call_tool("add_watermark", {
                   "inputPath": "/tmp/tofu-in.mp4",
                   "watermarkPath": "../../../../../../../../tmp/tofu-wm.png",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/watermarked.mp4",
                   "position": "center",
                   "opacity": 0.5,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the watermark is read through a `../` path, `/tmp/tofu-poc/` is created, and `/tmp/tofu-poc/watermarked.mp4` is written, all outside the server's working directory. A second run overwrites the output without a prompt.

## Expected behavior
All three paths are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created, and existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal and absolute paths passed validation and stopped only because the sandbox had no matching input video:

```
{'inputPath': 'input.mp4', 'watermarkPath': 'watermark.png', 'outputPath': '/etc/passwd\x00', 'position': 'center', 'opacity': 0.0}
-> Error: Input file does not exist: input.mp4
{'inputPath': '../../../../etc/passwd', 'watermarkPath': 'watermark.png', 'outputPath': 'output.mp4', ...}
-> Error: Input file does not exist: ../../../../etc/passwd
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite media files anywhere the user can write. The input-only paths let it read any media or image file the user can read and fold it into the output. ffmpeg picks the muxer from the extension, so overwriting a file without a media extension usually fails with this tool. The shell problem above is more severe and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve all three paths and reject any of them unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Call `spawn("ffmpeg", argv)` with an argument array and no shell.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it does not list `add_watermark`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 3584 exec / 3584 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': 'input.mp4', 'watermarkPath': 'watermark.png', 'outputPath': '/etc/passwd\x00', 'position': 'center', 'opacity': 0.0}` -> `Error: Input file does not exist: input.mp4`
  - `{'inputPath': '../../../../etc/passwd', 'watermarkPath': 'watermark.png', 'outputPath': 'output.mp4', 'position': 'topleft', 'opacity': 0.5}` -> `Error: Input file does not exist: ../../../../etc/passwd`
  - `{'inputPath': 'input.mp4', 'watermarkPath': '..\\..\\..\\..\\windows\\win.ini', 'outputPath': 'output.mp4', 'position': 'bottomright', 'opacity': 1.0}` -> `Error: Input file does not exist: input.mp4`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README shows absolute paths. Every evidence call stopped at the first input existence check; neither the watermark nor the output path was ever exercised. This tool has fewer injectable free-text fields than the others (no options string), but `outputPath` still goes through `/bin/sh` (CWE-78, `src/utils/ffmpeg.ts:36-40`). Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The reproduction above was derived from the code and has not been run.
</details>
