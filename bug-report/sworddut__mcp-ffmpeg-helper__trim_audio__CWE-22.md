# Path traversal in `trim_audio`: `inputPath` and `outputPath` are not confined, so trimmed audio can be written or overwritten anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `trim_audio` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`trim_audio` runs ffmpeg to cut a time range from the audio file at `inputPath` into `outputPath`. Neither path is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates the output's parent directories and passes `-y`, so an existing file at `outputPath` is overwritten without asking. A caller can read any media file the server user can read and write or overwrite audio anywhere that user can write.

## Details
`src/tools/handlers.ts:149-178`:

```ts
case "trim_audio": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const outputPath = validatePath(String(args?.outputPath));
  const startTime = String(args?.startTime || "0");
  const duration = String(args?.duration || "");
  const endTime = String(args?.endTime || "");
  const format = String(args?.format || "");

  await ensureDirectoryExists(outputPath);
  let command = `-i "${inputPath}" -ss ${startTime}`;
  ...
  command += ` "${outputPath}" -y`;
  const result = await runFFmpegCommand(command);
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and, for the input, that it exists. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })`. Nothing resolves the path or compares it with an allowed root.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`. `startTime`, `duration`, `endTime` and `format` are inserted unquoted, so shell metacharacters in them are interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a test audio file and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i sine=duration=2 /tmp/tofu-in.m4a
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
   {"inputPath": "/tmp/tofu-in.m4a", "outputPath": "../../../../../../../../tmp/tofu-poc/trim.m4a", "startTime": "0", "duration": "1"}
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
               result = await session.call_tool("trim_audio", {
                   "inputPath": "/tmp/tofu-in.m4a",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/trim.m4a",
                   "startTime": "0",
                   "duration": "1",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/` is created and `/tmp/tofu-poc/trim.m4a` is written, outside the server's working directory. A second run overwrites it without a prompt.

## Expected behavior
Input and output paths are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created, and existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal paths passed validation and stopped only because the sandbox had no matching input file:

```
{'inputPath': 'input.mp3', 'outputPath': '../../../../tmp/evil.mp3', 'startTime': '00:00:00', 'duration': '00:00:10', ...}
-> Error: Input file does not exist: input.mp3
{'inputPath': '../../../../etc/passwd', 'outputPath': 'output.mp3', ...}
-> Error: Input file does not exist: ../../../../etc/passwd
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite audio files anywhere the user can write. One example is truncating a recording in the user's music folder to one second. Because `format` and the time fields are inserted unquoted, extra ffmpeg options such as `-f` can be smuggled in, which also allows overwriting files without a media extension. The shell problem above is more severe and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve both paths and reject either one unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Validate the time fields against a time format and `format` against a list of codec names. Call `spawn("ffmpeg", argv)` with an argument array and no shell.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it names `trim_audio` `startTime`, `duration`, `endTime` and `format`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'outputPath': 'output.aac', 'startTime': '0', 'duration': '10', 'endTime': '10', 'format': 'aac'}` -> `Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini`
  - `{'inputPath': '../../../../etc/passwd', 'outputPath': 'output.mp3', ..., 'format': 'mp3'}` -> `Error: Input file does not exist: ../../../../etc/passwd`
  - `{'inputPath': 'input.mp3', 'outputPath': '../../../../tmp/evil.mp3', ..., 'format': 'mp3'}` -> `Error: Input file does not exist: input.mp3`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README shows absolute paths. Every evidence call stopped at the input existence check, so no traversal write was observed. The real issue is CWE-78 via the unquoted fields and `shell: true` (`src/utils/ffmpeg.ts:36-40`, `handlers.ts:160-176`). Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The reproduction above was derived from the code and has not been run.
</details>
