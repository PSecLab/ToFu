# `create-token`: `imageUrl` is read as an unrestricted local file path, so any file the server can read becomes the token image

**Repository:** `noahgsolomon/pumpfun-mcp-server` · **Tool:** `create-token` · **Tested commit:** `acda9d3`
**Weakness:** CWE-73 External Control of File Name or Path

## Summary
`create-token` takes an optional `imageUrl`, described in the tool schema as "URL to token image". The server does not fetch it as a URL. It passes the string to `fs.readFileSync` and sends the bytes to `pumpdotfun-sdk` as the token image. There is no check on the path, so the caller can make the server read any local file, including the wallet keypairs in `.keys/`, and attach it to a new token.

## Details
`src/index.ts:105` declares the argument as a free string. `src/create-token.ts` uses it as a path:

```ts
// src/create-token.ts:52
let fileBlob: Blob | undefined;
if (imageUrl) {
  const imageData = fs.readFileSync(imageUrl);
  fileBlob = new Blob([imageData], { type: "image/png" });
}

const tokenMetadata: any = { name, symbol, description, file: fileBlob };

const result = await sdk.createAndBuy(account, mint, tokenMetadata, ...);  // :65
```

No URL parsing, no directory restriction, no file type check. An `http(s)://` value fails with `ENOENT`, so the documented URL use does not work, while any readable local path does. The keypair files sit at predictable paths (`<repo>/.keys/<accountName>.json`, `src/create-token.ts:32`, `src/utils.ts:36`). The read happens after the balance check (`src/create-token.ts:35-48`) and before the token is created.

## Steps to reproduce
These steps stop at the file read and never create a token or spend funds.

1. Prerequisites: Node.js 18+, Python 3.10+ with `pip install mcp`, the Solana CLI for a devnet airdrop. Create the marker directory: `mkdir -p /tmp/tofu-poc`.
2. Install and build as the README describes: `npm install && npm run build`. Point the server at Solana devnet (test SOL only): `echo 'HELIUS_RPC_URL=https://api.devnet.solana.com' > .env` in the repo root.
3. Call the tool once to get the auto-created `default` account address from the "Insufficient SOL balance" reply, fund it with `solana airdrop 1 <address> --url devnet`, then call it again with a path that does not exist:

   ```json
   {"name": "PocToken", "symbol": "POC", "description": "poc", "imageUrl": "/tmp/tofu-poc/missing.png", "initialBuyAmount": 0.0001, "accountName": "default"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/pumpfun-mcp-server/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("create-token", {
                   "name": "PocToken", "symbol": "POC", "description": "poc",
                   "imageUrl": "/tmp/tofu-poc/missing.png",
                   "initialBuyAmount": 0.0001, "accountName": "default"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: `Error creating token: ENOENT: no such file or directory, open '/tmp/tofu-poc/missing.png'`. With `"imageUrl": "/tmp/tofu-poc"` the error is `EISDIR`. Both show the value is opened as a local path. Do not pass an existing file: the call would continue to `createAndBuy` and publish it.

## Expected behavior
`imageUrl` is treated as a URL (as documented), or, if local files are intended, it is limited to image files inside a configured directory. Keypair files are never readable through it.

## Actual behavior
Any path is passed to `fs.readFileSync` and the bytes become the token image. In ToFu's fuzzing runs no call got this far: every call returned `Error creating token: HELIUS_RPC_URL environment variable is not set` because no RPC was configured.

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection. If an attacker can get the model to call `create-token` with `imageUrl` pointing at `.keys/default.json`, the wallet's secret key becomes the image of a new public token. Token images are part of public token metadata, so the key would be exposed and the wallet could be drained. The attack needs a funded wallet and a successful token creation, which costs the user SOL, so it is not silent. I have not traced the upload inside `pumpdotfun-sdk` for this report.

## Suggested fix
Pick one meaning for the argument. If it is a URL: accept only `https:`, fetch it with a size limit and an image content-type check, and block private, loopback and link-local addresses after DNS resolution. If it is a local file: rename it (for example `imagePath`), resolve it with `fs.realpathSync` and require it to stay under a configured images directory, reject anything under the keys folder, and check the file's magic bytes for PNG/JPEG/GIF/WebP.

## Status on the default branch
Still present at `acda9d3` (2025-03-14). The default branch head is the tested commit.

## Prior reports
- No related issue or pull request among the 1 issue and 4 pull requests (fetched 2026-10-01). PRs #3 and #4 quote an automated scan that lists only dependency advisories (`bigint-buffer` via `@solana/*`), not this code.
- Documentation: README.md: "`imageUrl` (string, optional): Path to local image file" and "you must provide a local file path to the image. Remote URLs are not supported." (reading a local path is the documented behaviour, so the draft's "as documented" URL reading in Expected behavior should be reworded before filing; the missing restriction to image files outside `.keys` is not documented)
- Documentation: README.md: "The keypairs are stored unencrypted in the `.keys` folder. Make sure to secure this folder appropriately." (documents the keypair location this report says is readable through `imageUrl`)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918); `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: corpus-sbx 2560 exec / 288 ok; e2-0922 1024 / 182.
- Evidence (verbatim, trimmed): `{'name': 'SSRF Test 2', ..., 'imageUrl': 'http://localhost:8080', 'initialBuyAmount': 1, 'accountName': 'admin'}` -> `Error creating token: HELIUS_RPC_URL environment variable is not set`. Same output for `'imageUrl': 'http://127.0.0.1:8500'` and `'/etc/passwd\x00'`.
- Hand-check hints: ToFu's class is wrong. There is no network fetch of `imageUrl` anywhere; it goes to `fs.readFileSync` (`src/create-token.ts:54`). The SSRF sanitizers fired on the input shape alone; every logged call stopped at `initializeSDK` (`src/get-token-info.ts:13`) before any sink. Reframed as uncontrolled local file read: real by code reading, but the read is gated behind an RPC and a funded wallet, and the claim that the image is published relies on `pumpdotfun-sdk` (`github:rckprtr/pumpdotfun-sdk`, not vendored, not checked). I rate it unclear until someone confirms the SDK upload path. Aside, not in this draft: `accountName` goes into `path.join(keysFolder, name + ".json")` (`src/utils.ts:36`) unchecked, so `../` there can read or create keypair files outside `.keys`; may deserve its own issue. Reproduction not executed by me.
</details>
