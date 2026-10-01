# Path traversal in `extract_frames`: `inputPath` and `outputDir` are not confined, so frame images can be written into any directory

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `extract_frames` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`extract_frames` runs ffmpeg to save frames of `inputPath` as numbered images (`00001.jpg`, `00002.jpg`, ...) in `outputDir`. Neither path is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates `outputDir` recursively and passes `-y`, so existing files with those names are overwritten. A caller can read any video the server user can read and fill any directory that user can write with images.

## Details
`src/tools/handlers.ts:188-198` and `:228-232`:

```ts
case "extract_frames": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const outputDir = String(args?.outputDir || "output");
  const frameRate = String(args?.frameRate || "1");
  const format = String(args?.format || "jpg");
  ...
  await ensureDirectoryExists(join(outputDir, "dummy.txt"));
  ...
  const outputPattern = join(outputDir, `%05d.${format}`);
  command += ` "${outputPattern}" -y`;
  const result = await runFFmpegCommand(command);
```

`outputDir` is not passed through any check. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(...), { recursive: true })` on it, and `path.join` normalizes `../` segments without restricting them. `validatePath` on `inputPath` (`src/utils/file.ts:23-33`) only checks existence.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`. `startTime` and `duration` are inserted unquoted, and `frameRate`, `format` and `outputDir` are only inside double quotes, so shell metacharacters in them are interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a test video and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=2:size=64x64:rate=1 -pix_fmt yuv420p /tmp/tofu-in.mp4
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
   {"inputPath": "/tmp/tofu-in.mp4", "outputDir": "../../../../../../../../tmp/tofu-poc/frames", "frameRate": "1", "format": "png", "quality": 95}
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
               result = await session.call_tool("extract_frames", {
                   "inputPath": "/tmp/tofu-in.mp4",
                   "outputDir": "../../../../../../../../tmp/tofu-poc/frames",
                   "frameRate": "1",
                   "format": "png",
                   "quality": 95,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/frames/` is created and `00001.png`, `00002.png`, ... are written there, outside the server's working directory.

## Expected behavior
`inputPath` and `outputDir` are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created, and existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal paths in both arguments passed and stopped only because the sandbox had no matching input video:

```
{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'outputDir': '../tmp', 'frameRate': '0.5', 'format': 'png', ...}
-> Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini
{'inputPath': '../../../../etc/passwd', 'outputDir': 'output', ...}
-> Error: Input file does not exist: ../../../../etc/passwd
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories anywhere the user can write and drop or overwrite numbered image files there. Arbitrary file names cannot be chosen through `outputDir` alone, so this is mostly clutter and limited overwrite. The shell problem above is more severe and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve `inputPath` and `outputDir` and reject either one unless it is inside the root.
- Validate `format` against a list of image extensions and `startTime`/`duration`/`frameRate` against numeric or time formats.
- Replace `-y` with `-n` or an explicit `overwrite` argument, and call `spawn("ffmpeg", argv)` with an argument array and no shell.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it names `extract_frames` `format`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': '../../../../etc/passwd', 'outputDir': 'output', 'frameRate': '1', 'format': 'jpg', 'quality': 95, ...}` -> `Error: Input file does not exist: ../../../../etc/passwd`
  - `{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'outputDir': '../tmp', 'frameRate': '0.5', 'format': 'png', 'quality': 100, ...}` -> `Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini`
  - `{'inputPath': '/etc/passwd\x00', 'outputDir': '/tmp/frames', 'frameRate': '1/30', 'format': 'gif', ...}` -> `Error: Input file does not exist: /etc/passwd\x00`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README shows absolute paths. Every evidence call stopped at the input existence check before `mkdir`, so no traversal write was observed. Overwrite impact is limited to files named `NNNNN.<format>`. The real issue is CWE-78 (`shell: true`, `src/utils/ffmpeg.ts:36-40`; unquoted `startTime`/`duration` at `handlers.ts:204-211`). Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The reproduction above was derived from the code and has not been run.
</details>
