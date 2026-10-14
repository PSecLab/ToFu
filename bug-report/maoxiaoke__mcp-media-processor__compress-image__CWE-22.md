# Path traversal in `compress-image`: `outputFilename` escapes the Downloads folder and `outputPath` overwrites files anywhere

**Repository:** `maoxiaoke/mcp-media-processor` · **Tool:** `compress-image` · **Tested commit:** `2aecf0f`
**Weakness:** CWE-22 Path Traversal

## Summary
`compress-image` recompresses a PNG with ImageMagick and saves the result. When `outputPath` is omitted the output is meant to land in `~/Downloads`, but `outputFilename` is joined onto that folder without any check, so `../` sequences place the file anywhere. `outputPath` is used as given: missing parent directories are created and an existing file at that path is replaced without warning.

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
// ... compress-image handler, lines 286-295:
      const absoluteInputPath = await getAbsolutePath(inputPath);
      if (!absoluteInputPath.toLowerCase().endsWith('.png')) {
      const defaultFilename = outputFilename || `${inputFileName}_compressed.png`;
      const finalOutputPath = await getOutputPath(outputPath, defaultFilename);
```

The only input check is the `.png` suffix (line 289). `join('~/Downloads', '../../x.png')` normalizes to a path outside `~/Downloads`. A caller `outputPath` is accepted as is, and `ensureDirectoryExists` (lines 21-27) runs `fs.mkdir(..., { recursive: true })` on its parent. The resolved paths then go to ImageMagick `convert` (lines 298-299), which replaces an existing output file without asking.

## Steps to reproduce
1. Prerequisites: Node.js 18+, ImageMagick 6 with `convert` on `PATH`. No accounts or env vars. Create test files:
   ```bash
   convert -size 64x64 xc:red /tmp/tofu-in.png
   printf 'original content\n' > /tmp/tofu-poc.png
   ```
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/maoxiaoke/mcp-media-processor.git
   cd mcp-media-processor && npm install && npm run build
   # server entry point: node build/index.js
   ```
3. Call the tool twice. Call A (escape from `~/Downloads` via `outputFilename`):
   ```json
   {"inputPath": "/tmp/tofu-in.png", "quality": 80, "outputFilename": "../../../../../../../../tmp/tofu-poc-escape.png"}
   ```
   Call B (silent overwrite via `outputPath`):
   ```json
   {"inputPath": "/tmp/tofu-in.png", "quality": 80, "outputPath": "/tmp/tofu-poc.png"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   CALLS = [
       {"inputPath": "/tmp/tofu-in.png", "quality": 80,
        "outputFilename": "../../../../../../../../tmp/tofu-poc-escape.png"},
       {"inputPath": "/tmp/tofu-in.png", "quality": 80,
        "outputPath": "/tmp/tofu-poc.png"},
   ]

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for arguments in CALLS:
                   result = await session.call_tool("compress-image", arguments)
                   print(result)

   asyncio.run(main())
   ```
4. Observe: call A reports `Image successfully compressed and saved to: /tmp/tofu-poc-escape.png` and the file exists there, not under `~/Downloads`. After call B, `cat /tmp/tofu-poc.png` no longer prints `original content`; the file now holds image data.

## Expected behavior
`outputFilename` is treated as a bare file name and the result stays inside `~/Downloads`. If `outputPath` is supported, it is confined to an allowed root, and an existing file is not replaced unless the caller explicitly asks for it.

## Actual behavior
Any `outputFilename` or `outputPath` is accepted, parent directories are created, and existing files are overwritten. In the fuzzing sandbox ImageMagick was not installed, so every recorded call stopped at `checkImageMagick()` before the paths were used, for example input `{"inputPath": "../../../../etc/passwd", "quality": 80, "outputPath": "/tmp/output.png", ...}` returned:

```
Error compressing image: ImageMagick is not installed. Please install it first.
```

The behavior described above comes from reading the code at the tested commit, not from an observed write.

## Impact
Tool arguments are chosen by the LLM, and prompt injection in content the agent reads can steer them. An attacker can make the agent overwrite any file the user can write (dotfiles, project files, documents) with image data, or drop files and create directories in arbitrary locations. The written bytes are the processed image, not attacker-chosen text, so this is mainly an integrity and availability problem. Reading arbitrary input images is documented behavior ("Absolute path to input PNG image").

## Suggested fix
- In `getOutputPath`, reject an `outputFilename` that is not a plain file name (`path.basename(name) !== name`, or contains `..`).
- Resolve the final path and require it to stay under an allowed root, e.g. `const p = path.resolve(root, name); if (!p.startsWith(root + path.sep)) throw ...`. If `outputPath` must stay, confine it to a configurable list of roots and check the `fs.realpath` of the parent directory.
- Refuse to overwrite an existing file unless an explicit `overwrite: true` is passed.
- Only create directories inside the allowed root.
- The helpers are shared, so one fix covers all ten tools.

## Status on the default branch
Still present at `2aecf0f` (2025-02-20). The tested commit is the current head of the default branch.

## Prior reports
- #7 "Security Vulnerability: Command Injection in multiple mcp-media-processor tools due to unsafe use of child_process.execSync" (issue, open 2026-04-23): names this tool, but reports a different weakness (shell injection through `outputFilename` and other arguments passed to `execSync`). It does not mention the `../` escape from `~/Downloads` or the silent overwrite, and its suggested switch to `execFile` would not fix them. No fix has been merged.
- Documentation: README.md: "`inputPath` (string): Absolute path to input image file" and "`outputPath` (string, optional): Custom output path" (arbitrary input and output locations are documented; nothing says `outputFilename` may contain directories, and there is no allowed-root setting or warning about untrusted input).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` only ("Silent Bug Alert": the input matched a traversal pattern and the tool returned without an exception).
- Campaigns and executions: corpus-sbx 3584 exec / 434 ok; e2-0922 1536 exec / 196 ok (60 s budget each).
- Evidence (verbatim, trimmed), all corpus-sbx, all with the same output `Error compressing image: ImageMagick is not installed. Please install it first.`:
  - `{'inputPath': '/etc/passwd\x00', 'quality': 1, 'outputPath': '/etc/shadow', 'outputFilename': 'shadow.png'}`
  - `{'inputPath': '../../../../etc/passwd', 'quality': 50, 'outputPath': '/dev/full', 'outputFilename': 'full.png'}`
  - `{'inputPath': '../../../../etc/passwd', 'quality': 80, 'outputPath': '/tmp/output.png', 'outputFilename': 'output.png'}`
- Hand-check hints: real at code level, low-medium severity. Evidence is weak: ImageMagick was missing in the sandbox, so no call got past `checkImageMagick()` (lines 69-76) and the alert fired on the input shape alone. The escape is confirmed by reading `getOutputPath` (line 51). The excerpt trims the `if` body at line 289 to keep it short. Arbitrary absolute paths are documented, so the maintainer may call that part by design; the Downloads escape and the silent overwrite are the strongest points. Same root cause in all ten tools of this server; consider one combined issue. Not run by us.
</details>
