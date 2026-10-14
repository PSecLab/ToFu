# Unrestricted local file access in `create_video_post`: `file_path` can name any file, and existence is disclosed before login

**Repository:** `Tisik79/MCP-Facebook` · **Tool:** `create_video_post` · **Tested commit:** `2ebfbc9`
**Weakness:** CWE-22 Path Traversal

## Summary
`create_video_post` uploads a local video to the connected Facebook page. `file_path` is used as given, with no allowed directory and no file-type check, so the tool will open any file the server process can read and send its bytes to Meta. The existence check also runs before any login or page check, so the tool answers "file not found" or not for arbitrary paths even when no account is connected.

## Details
`src/tools/post-tools.ts:167-202` (tested commit):

```ts
export async function create_video_post(filePath: string, content: string, published = false) {
  if (!filePath) throw new Error('Chybí cesta k video souboru (file_path).');
  if (!fs.existsSync(filePath)) throw new Error(`Soubor nenalezen: ${filePath}`);

  const pageInfo = await getPageInfo();
  ...
  const fileSize = fs.statSync(filePath).size;
  ...
  const fd = fs.openSync(filePath, 'r');
  ...
  fs.readSync(fd, chunk, 0, len, startOffset);
  form.append('video_file_chunk', chunk, { filename: fileName, ... });
```

The handler in `src/index.ts:1113-1131` passes `file_path` straight through. There is no `path.resolve` plus prefix check against a media directory, and no extension or content-type check. `../` sequences and absolute paths are accepted.

## Steps to reproduce
1. Prerequisites: Node.js 18+. The existence oracle needs no account. The upload path needs a connected page (`node dist/index.js login`).
2. Install and build: `git clone https://github.com/Tisik79/MCP-Facebook.git && cd MCP-Facebook && npm install && npm run build`
3. Call the tool twice, once with an existing file and once with a missing one:

   ```json
   {"file_path": "/etc/hostname", "message": "test", "published": false}
   ```
   ```json
   {"file_path": "/tmp/tofu-does-not-exist.mp4", "message": "test", "published": false}
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
               for p in ["/etc/hostname", "/tmp/tofu-does-not-exist.mp4"]:
                   result = await session.call_tool("create_video_post",
                       {"file_path": p, "message": "test", "published": False})
                   print(p, result)

   asyncio.run(main())
   ```
4. Observe: the missing file returns `Soubor nenalezen: ...`; `/etc/hostname` gets past the check and fails later on the page lookup. With a connected page, the server opens `/etc/hostname` and sends its bytes to `/{page-id}/videos`.

## Expected behavior
The tool only reads files under a configured media directory (or the user's chosen upload folder), only with video extensions, and checks login before touching the filesystem.

## Actual behavior
Any path is accepted. In the fuzzing run, traversal paths reached `fs.existsSync`:

```
Chyba: Soubor nenalezen: ../../../../etc/passwd
```

(The file did not exist relative to the sandboxed working directory, so the call stopped there.)

## Impact
The LLM chooses `file_path`, and prompt injection in content the agent reads can steer it. An attacker can probe which files exist on the host, and on an account with a page can cause any readable file to be uploaded to Meta under the user's page (unpublished by default; `published: true` is also accepted). Meta will likely fail to process a non-video file, but the bytes have already left the machine. The destination is the user's own page, not the attacker's, so this is a medium/low local-file exposure rather than direct exfiltration.

## Suggested fix
- Resolve the path with `fs.realpathSync` and reject it unless it is inside an allowed media root (for example a `FB_MEDIA_DIR` setting).
- Accept only video extensions (`.mp4`, `.mov`, ...) and optionally check the file signature.
- Do the login/page check before any filesystem access, and do not echo the raw path in the error.

## Status on the default branch
Still present at `2ebfbc9` (2026-07-06). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 1 issue and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, also `check_reflected_output` on this tool.
- Campaigns and executions: corpus-sbx 2560 exec / 2552 ok; e2-0922 1536 exec / 1528 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'file_path': '/etc/passwd\x00', ...}` -> `Chyba: Soubor nenalezen: /etc/passwd\x00`
  - `{'file_path': '../../../../etc/passwd', ...}` -> `Chyba: Soubor nenalezen: ../../../../etc/passwd`
  - `{'file_path': '..\\..\\..\\..\\windows\\win.ini', ..., 'published': True}` -> `Chyba: Soubor nenalezen: ...`
- Hand-check hints: weak to real-low. The path does reach `fs.existsSync`/`openSync`/`readSync` with no containment (confirmed in source), but the tool is documented as taking an absolute path, so there is no "intended directory" being escaped. No evidence call actually read a file: all three returned "not found" (NUL byte, relative path outside the sandbox cwd, Windows path on Linux). The pre-auth existence oracle is the only effect reachable without an account. Upload of arbitrary files needs a valid page token; not tested.
</details>
