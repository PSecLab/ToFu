# Missing output encoding in `signNote`: part of the `privateKey` argument is echoed in the error text

**Repository:** `AustinKelsay/nostr-mcp-server` · **Tool:** `signNote` · **Tested commit:** `010b6dc`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`signNote` signs an unsigned note with a private key. A non-hex, non-nsec `privateKey` is passed unchanged to `schnorr.getPublicKey`. The library's error, which quotes the first invalid two-character pair of the key string, is forwarded to the client verbatim. The reflected text is short (two characters), but it is caller input taken from a secret-bearing argument and returned unescaped.

## Details
`note/note-tools.ts:196-210` at `010b6dc`:

```ts
// Helper function to convert private key to hex if nsec format
function normalizePrivateKey(privateKey: string): string {
  if (privateKey.startsWith('nsec')) {
    ...
    return decoded.data;
  }
  return privateKey;
}

// Helper function to derive public key from private key
function getPublicKeyFromPrivate(privateKey: string): string {
  return Buffer.from(schnorr.getPublicKey(privateKey)).toString('hex');
}
```

`signNote` (`note/note-tools.ts:261-296`) catches the exception and returns `` `Error signing note: ${error.message}` ``. `index.ts:1798-1806` then wraps that as `` `Failed to sign note: ${result.message}` ``. `@noble/hashes`' `hexToBytes` builds the message as `hex string expected, got non-hex character "<pair>" at index <n>`.

The repo already has a stricter `normalizePrivateKey` in `utils/keys.ts:9-31`. It rejects anything other than 64-char hex or `nsec1...` with a fixed message, but `note-tools.ts` uses its own local copy instead.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. You need no keys or relays.
2. Install and start the server:
   ```
   git clone https://github.com/AustinKelsay/nostr-mcp-server.git
   cd nostr-mcp-server && git checkout 010b6dcb5aa87d268e0182554e3f9b0055e8fdab
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"privateKey": "{{tofu-poc}}", "noteEvent": {"kind": 1, "content": "", "tags": [], "created_at": 0, "pubkey": ""}}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("signNote", {"privateKey": "{{tofu-poc}}", "noteEvent": {"kind": 1, "content": "", "tags": [], "created_at": 0, "pubkey": ""}})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Failed to sign note: Error signing note: private key must be hex string or Uint8Array, cause: Error: hex string expected, got non-hex character "{{" at index 0`.

## Expected behavior
Malformed keys should be rejected with a fixed message that does not quote any part of the key, as `utils/keys.ts` already does.

## Actual behavior
Two characters of the key argument are quoted back. From the fuzzing run:

```
Failed to sign note: Error signing note: private key must be hex string or Uint8Array, cause: Error: hex string expected, got non-hex character "{{" at index 0
```

## Impact
Very low. Only one two-character pair is reflected, so this cannot carry a useful markup payload. The more relevant point is hygiene: the tool returns text derived from a private-key argument to the model and its transcript. A typo in a real key would leak two of its characters plus their position.

## Suggested fix
Use the validated `normalizePrivateKey` from `utils/keys.ts` in `note/note-tools.ts` (and remove the local copy). Return a fixed error message for invalid keys instead of the library's message.

## Status on the default branch
Still present at `010b6dc` (2026-04-04). The tested commit is the head of the default branch. The README at that commit says the project is no longer maintained and points to `AustinKelsay/nostr-agent-interface`.

## Prior reports
- No related issue or PR. Searched all 3 issues and 14 pull requests (fetched 2026-10-01).
- Documentation: README.md: "This project is no longer maintained." (the default-branch head `010b6dc` redirects users to `nostr-agent-interface`, so a report here may get no response; no README or `_docs/` text covers this behaviour)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired.
- Campaigns and executions: corpus-sbx 3,072 exec / 3,027 ok (60 s).
- Evidence (verbatim, trimmed): input `{'privateKey': '{{\x7f\x7f\x7f{\x7f\x7f', 'noteEvent': {'kind': 0.0, 'content': '', 'tags': [], 'created_at': 0.0, 'pubkey': ''}}` -> `'Failed to sign note: Error signing note: private key must be hex string or Uint8Array, cause: Error: hex string expected, got non-hex character "{{" at index 0'`. Two more inputs starting with `{{` gave the same output.
- Hand-check hints: weak. By construction only 2 characters can be reflected (`@noble/hashes` `hexToBytes`, `node_modules/@noble/hashes/esm/utils.js:139-159` in the local fuzz target copy). An odd-length key gives an "unpadded hex of length N" message with no echo, which is why the PoC key has even length (12 chars). On runtimes where `Uint8Array.fromHex` exists, noble uses the built-in and the message text differs. Not checked. The duplicate weaker `normalizePrivateKey` in `note-tools.ts` is the actionable part. The repo is unmaintained.
</details>
