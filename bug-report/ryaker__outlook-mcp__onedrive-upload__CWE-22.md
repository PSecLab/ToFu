# `onedrive-upload`: `path` reaches the Graph API with only slash-trimming (not a local path traversal)

**Repository:** `ryaker/outlook-mcp` · **Tool:** `onedrive-upload` · **Tested commit:** `95d6ff2`
**Weakness:** CWE-22 Path Traversal

## Summary
A fuzzer flagged `onedrive-upload` for path traversal because the caller-supplied `path` is only
slash-trimmed before use. On reading the code, `path` is not used in any local filesystem operation; it is
embedded in a Microsoft Graph API endpoint that targets the authenticated user's own OneDrive. There is no
read or write to the server's local disk, so the classic local path-traversal impact does not apply. The
remaining, lesser concern is that `path` is passed to the Graph URL without validation.

## Details
`handleUpload` builds a Graph endpoint from `path` (`onedrive/upload.js:13`):

```js
async function handleUpload(args) {
  const path = args.path;
  const content = args.content;
  if (!path) return /* "Path is required..." */;
  if (!content) return /* "Content is required." */;
  // ...
  const accessToken = await ensureAuthenticated();
  const normalizedPath = path.replace(/^\/+|\/+$/g, '');          // 51: trims leading/trailing slashes only
  const endpoint = `me/drive/root:/${normalizedPath}:/content`;   // 52: Graph drive-path addressing
  const response = await callGraphAPI(accessToken, 'PUT', endpoint, content, queryParams);
}
```

`normalizedPath` strips only leading/trailing `/`. Interior segments (including `..`) are left in place and
placed into a Graph `root:/<path>:/content` address. This is a remote path in the user's OneDrive, resolved
by Microsoft Graph; it never touches the MCP server's local filesystem. `callGraphAPI`
(`utils/graph-api.js`) is an HTTPS call to `graph.microsoft.com`.

## Steps to reproduce
1. Prerequisites: a Microsoft 365 account authenticated through the server's `authenticate` tool (the upload
   path requires a valid Graph access token). Node 18+, `npm install`.
2. Start the server: `node index.js`.
3. Call the tool. Arguments as JSON: `{"path": "/Documents/tofu-poc.txt", "content": "tofu marker"}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "onedrive-upload",
                   {"path": "/Documents/tofu-poc.txt", "content": "tofu marker"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the content is PUT to the user's own OneDrive drive path. No file is read from or written to
   the server's local disk, regardless of `..` segments in `path`.

## Expected behavior
`path` should be validated as a OneDrive-relative path (no `..`, no NUL) before being placed in the Graph
address.

## Actual behavior
In the fuzzing evidence every flagged call was rejected before the Graph request, at the
`if (!content)` check: output `{'content': [{'type': 'text', 'text': 'Content is required.'}]}`. The flagged
`path` values never reached `callGraphAPI`.

## Impact
No local file disclosure or local file write: `path` controls a location inside the already-authenticated
user's own OneDrive, which this tool is designed to write to anyway. The residual issue is input hygiene -
unvalidated `..`/NUL in a Graph drive-path - which Graph itself largely rejects or normalizes. Proportionate
severity is low.

## Suggested fix
Validate `normalizedPath`: reject `..` segments and control characters (e.g. NUL), and reject absolute or
scheme-like inputs, before composing the Graph endpoint.

## Status on the default branch
Still present at `95d6ff2` (2026-03-30). The current default branch head is the same commit that was tested;
`onedrive/upload.js` still trims only slashes.

## Prior reports
- #34 "feat: extend to m365-assistant with OneDrive and Power Automate support" (PR, closed 2026-03-04): introduced the OneDrive tools, including `onedrive-upload`. The body does not mention validating `path`.
- #69 "Add email attachment read support (list + download)" (PR, open 2026-07-15): sanitizes attachment filenames "against path traversal" before writing to local disk. Different tool (`download-attachment`); it does not touch `onedrive-upload`.
- Documentation: README.md lists `onedrive-upload` as "Upload small file (<4MB)"; neither README.md nor CLAUDE.md says anything about allowed `path` values. No SECURITY.md or `docs/`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` fired.
- Campaigns and executions: corpus-sbx (3,072 / 2,363, 60s) and e2-0922 (512 / 458, 60s).
- Evidence (verbatim, trimmed): input `{'path': '"path": "/etc/passwd\\u0000", "content": "fake content",...',
  'content': '', 'conflictBehavior': 'rename'}` -> output `Content is required.` All three rows carried an
  empty `content` and were rejected before the Graph call.
- Hand-check hints: WEAK / false positive for local CWE-22. `path` flows only into a Graph `root:/<path>:/content`
  URL (onedrive/upload.js:52), never to `fs`. The `/etc/passwd` string in the fuzzer payload is just the
  injected literal; there is no local file sink to traverse. Requires Microsoft auth even to reach the Graph
  call. Recommend downgrading to an input-validation nit or dropping. The file-path PoC rules (local marker
  under /tmp/tofu-poc) do not apply because there is no local filesystem operation to demonstrate.
</details>
