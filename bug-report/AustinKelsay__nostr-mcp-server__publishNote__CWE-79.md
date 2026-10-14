# Missing output encoding in `publishNote`: note fields are echoed raw, and a note with no relays is reported as "published"

**Repository:** `AustinKelsay/nostr-mcp-server` · **Tool:** `publishNote` · **Tested commit:** `010b6dc`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`publishNote` publishes a signed Nostr event to relays and then summarizes it. The summary copies the event's `id`, `content` and, when it is not valid hex, `pubkey` into the text result verbatim. Markup and template syntax in these fields come back unescaped. When `relays` is an empty list, the tool reports "Note published successfully!" and "Note is valid" without sending or verifying anything.

## Details
`index.ts:1827-1841` at `010b6dc`:

```ts
  async ({ signedNote, relays }) => {
    try {
      const result = await publishNote(signedNote, relays);

      if (result.success) {
        let response = `Note published successfully!\n\n`;
        response += `${result.message}\n`;
        if (result.noteId) {
          response += `Note ID: ${result.noteId}\n`;
        }
        response += `Content: "${signedNote.content}"\n`;
        response += `Author: ${formatPubkey(signedNote.pubkey)}\n`;
```

- `publishNote` (`note/note-tools.ts:316-323`) returns `success: true` with `noteId: signedNote.id` as soon as `relays.length === 0`. It does not check the id hash or the signature.
- `formatPubkey` (`utils/formatting.ts:10-22`) returns the input unchanged when it cannot convert it to an npub.
- None of the echoed fields are escaped or length-limited.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later. You need no keys, and no relays are contacted with `relays: []`.
2. Install and start the server:
   ```
   git clone https://github.com/AustinKelsay/nostr-mcp-server.git
   cd nostr-mcp-server && git checkout 010b6dcb5aa87d268e0182554e3f9b0055e8fdab
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"signedNote": {"id": "<b>tofu-poc</b>{{7*7}}", "pubkey": "${7*7}", "created_at": 0, "kind": 1, "tags": [], "content": "<i>tofu-poc</i>", "sig": ""}, "relays": []}
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
               result = await session.call_tool("publishNote", {"signedNote": {"id": "<b>tofu-poc</b>{{7*7}}", "pubkey": "${7*7}", "created_at": 0, "kind": 1, "tags": [], "content": "<i>tofu-poc</i>", "sig": ""}, "relays": []})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is
   ```
   Note published successfully!

   Note is valid and ready to publish (no relays specified)
   Note ID: <b>tofu-poc</b>{{7*7}}
   Content: "<i>tofu-poc</i>"
   Author: ${7*7}
   ```

## Expected behavior
Echoed event fields should be escaped, or replaced by values the server computed (for example the recomputed event hash). An empty relay list should not be reported as a successful, valid publish unless the id and signature have been checked.

## Actual behavior
The fields are reflected verbatim, and the call reports success. From the fuzzing run (trimmed):

```
Note published successfully!

Note is valid and ready to publish (no relays specified)
Note ID: "signedNote":${"id": "id10", "pubkey": "pubey1k0", ... "relays": ["wss://relay3.nostr.co
Content: ""
Author: ", "../../../.pcet//.a../
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call can put markup into the tool result. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. The misleading "published successfully" and "valid" text can make the model tell the user that a malformed or forged note was published. That is a correctness problem more than a security one.

## Suggested fix
- Verify the event before reporting it as valid: recompute the id with `getEventHash` and check `sig` against `pubkey`, as the signing tools already can.
- With `relays: []`, report "not published (no relays given)" instead of "published successfully".
- Escape or truncate echoed `id`, `content` and `pubkey`, or echo only values that passed validation (64-char hex id and pubkey).

## Status on the default branch
Still present at `010b6dc` (2026-04-04). The tested commit is the head of the default branch. The README at that commit says the project is no longer maintained and points to `AustinKelsay/nostr-agent-interface`.

## Prior reports
- No related issue or PR. Searched all 3 issues and 14 pull requests (fetched 2026-10-01).
- Documentation: README.md: "This project is no longer maintained." (the default-branch head `010b6dc` redirects users to `nostr-agent-interface`, so a report here may get no response; no README or `_docs/` text covers this behaviour)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired.
- Campaigns and executions: corpus-sbx 3,072 exec / 2,989 ok (60 s).
- Evidence (verbatim, trimmed):
  - input `{'signedNote': {'id': '"signedNote":{{"id": "../../../../e\x7f...\x7ftc/passwdl content", "sig": "sig1/relay1.nos*r.c\x14m"', 'pubkey': '', ...}, 'relays': []}` -> `'Note published successfully!\n\nNote is valid and ready to publish (no relays specified)\nNote ID: "signedNote":{{"id": ...\nContent: ""\nAuthor: unknown\n'`.
  - input with `id` containing `${` and `pubkey` `'", "../../../.pcet//.a../'` -> `Author: ", "../../../.pcet//.a../` echoed raw.
- Hand-check hints: weak as XSS. The output is plain text content, and only `{{` and `${` were seen. The "published successfully / valid" message for an unverified note with no relays is the more useful part of this report. I did not test the path with real relays (`getFreshPool(relays)`). Relay URL validation there was not reviewed. The repo is unmaintained.
</details>
