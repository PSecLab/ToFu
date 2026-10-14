# Unrestricted local file access in `upload_ad_media`: `file_path` can name any image or video file on the host

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `upload_ad_media` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-22 Path Traversal

## Summary
`upload_ad_media` uploads a local image or video (or a public video URL) to the active ad account. A local `file_path` is used as given, with no allowed directory, so any file the process can read is uploaded to Meta as long as its name ends in an accepted image or video extension. Login is checked first and the extension allowlist blocks files like `/etc/passwd`, which limits the impact.

## Details
`src/tools/ad-tools.ts:70-108` (tested commit):

```ts
ensureSdk();
if (!filePath) throw new Error('Chybí cesta k souboru nebo URL (file_path).');
const isUrl = /^https?:\/\//i.test(filePath);
const pathname = isUrl ? new URL(filePath).pathname : filePath;
const ext = path.extname(pathname).toLowerCase();
...
if (!isUrl && !fs.existsSync(filePath)) throw new Error(`Soubor nenalezen: ${filePath}`);
if (!isUrl && ['.jpg', '.jpeg', '.png', '.gif'].includes(ext)) {
  const buffer = fs.readFileSync(filePath);
  const image: any = await adAccount.createAdImage([], { bytes: buffer.toString('base64'), name: fileName });
```

Video files go to `uploadAdVideoDirect` (`src/tools/ad-tools.ts:30-66`), which also calls `fs.readFileSync(filePathOrUrl)`. Neither path is resolved and checked against a media root, and `../` is accepted. Files without an allowed extension are rejected with "Nepodporovaný typ".

## Steps to reproduce
1. Prerequisites: Node.js 18+ and a connected ad account (`node dist/index.js login`). Without login the tool stops at `ensureSdk()`.
2. Install and build: `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
3. Create a harmless test image outside the project, e.g. `cp <any small png> /tmp/tofu-poc.png`, then call the tool with a traversal path to it from the server's working directory:

   ```json
   {"file_path": "../../../../../../../../tmp/tofu-poc.png"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("upload_ad_media",
                   {"file_path": "../../../../../../../../tmp/tofu-poc.png"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the file outside the project is read and uploaded, and an `image_hash` is returned. A missing path returns `Soubor nenalezen: ...`, which reveals whether an image or video file exists.

## Expected behavior
Local uploads are limited to a configured media directory: the resolved real path must stay under it.

## Actual behavior
Any path is accepted. In the fuzzing run, without login, the calls stopped at the SDK check:

```
Chyba: Chyba při nahrávání média: Nejsi přihlášen k Facebooku. ...
```

## Impact
The LLM chooses `file_path`, and prompt injection can steer it. With a connected account, an attacker can cause private images or videos on the host (for example screenshots or photos) to be uploaded to the user's ad account media library at Meta, and can probe for the existence of such files. The destination is the user's own account and the extension allowlist excludes most secrets, so the severity is low to medium.

## Suggested fix
Add a media root setting, resolve `file_path` with `fs.realpathSync`, and reject it unless it starts with that root plus a path separator. Keep the extension allowlist and consider checking the file signature.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2556 ok; e2-0922 1536 exec / 1534 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'file_path': '/etc/passwd\x00', ...}` -> `Chyba: Chyba při nahrávání média: Nejsi přihlášen k Facebooku...`
  - `{'file_path': '../../../../etc/passwd', ...}` -> same.
  - `{'file_path': '../../../../etc/shadow', ...}` -> same.
- Hand-check hints: weak. The sanitizer matched the input string only; every evidence call was rejected by `ensureSdk()` before any filesystem access, so the run shows no file access. Source confirms an uncontained `readFileSync` after login, but only for `.jpg/.jpeg/.png/.gif` and video extensions, so `/etc/passwd`-style targets are rejected. The tool is documented as taking an absolute path. Repro step 3 is derived from source, not run.
</details>
