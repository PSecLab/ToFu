# Path traversal in `set_image_fill`: `imagePath` reads any file the server can access and sends it over the relay

**Repository:** `sonnylazuardi/cursor-talk-to-figma-mcp` · **Tool:** `set_image_fill` · **Tested commit:** `ddd90f3`
**Weakness:** CWE-22 Path Traversal

## Summary
`set_image_fill` reads `imagePath` with `fs.readFile` and no check on location or file type. The bytes are base64-encoded and sent through the WebSocket relay to the Figma plugin. On the way they are written in full to the MCP server's stderr (`[DEBUG] Request details`) and to the relay console, and broadcast to every other client in the channel. Any file readable by the server process, such as SSH keys or cloud credentials, can be pulled into those logs and onto the relay.

## Details
The handler reads the caller's path directly (`src/talk_to_figma_mcp/server.ts:3102-3104`) and sends the result (`server.ts:3122-3126`):

```ts
      let base64Data: string;
      if (imagePath) {
        base64Data = (await readFile(imagePath)).toString("base64");
      } else if (imageUrl) {
...
      const result = await sendCommandToFigma("set_image_fill", {
        nodeId,
        imageBase64: base64Data,
        scaleMode: scaleMode || "FILL",
      });
```

`sendCommandToFigma` logs the whole request, file bytes included (`server.ts:3058-3060`):

```ts
    logger.info(`Sending command to Figma: ${command}`);
    logger.debug(`Request details: ${JSON.stringify(request)}`);
    ws.send(JSON.stringify(request));
```

`logger.debug` always writes to stderr; there is no level filter (`server.ts:57-63`). The relay prints every message in full (`src/socket.ts:87`) and forwards it to all other clients in the channel (`socket.ts:159-175`). The relay has no authentication: any local process that connects to port 3055 and joins the channel name receives the broadcast. There is no allowlisted directory, no `realpath` check and no image-type check before the read. The file type is only checked later by Figma (`figma.createImage`, `src/cursor_mcp_plugin/code.js:1069-1075`), after the bytes have already left the server.

## Steps to reproduce
1. Prerequisites: Linux (for `/etc/hostname`), Bun, a checkout at `ddd90f3` with `bun install`. Figma is not required to see the read and the relay traffic.
2. Start the relay with `bun socket` (README "WebSocket Server"). Point the MCP client at `bun /path-to-repo/src/talk_to_figma_mcp/server.ts` (README "Local Development Setup").
3. Join a channel, then call `set_image_fill` with `{"nodeId": "0:1", "imagePath": "/etc/hostname", "scaleMode": "FILL"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="bun", args=["/path-to-repo/src/talk_to_figma_mcp/server.ts"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               await asyncio.sleep(2)  # let the server open its WebSocket to the relay
               await session.call_tool("join_channel", {"channel": "tofu-poc"})
               result = await session.call_tool("set_image_fill", {"nodeId": "0:1", "imagePath": "/etc/hostname", "scaleMode": "FILL"})
               print(result)

   asyncio.run(main())
   ```
4. In the relay terminal, the `Full message:` block contains `"imageBase64": "<base64>"`; `echo <base64> | base64 -d` prints the machine's hostname. The MCP server's stderr shows the same value in `[DEBUG] Request details: ...`. Without a plugin in the channel, the tool returns `Error setting image fill: Request to Figma timed out` after 30 s, but the file has already been read and relayed. A second WebSocket client that joins `tofu-poc` on `ws://localhost:3055` receives the bytes as a `broadcast` message.

## Expected behavior
The server only reads image files from a directory the user configured, rejects other paths after resolving them, and does not log file contents.

## Actual behavior
The path is opened as given. The fuzzing run shows the raw caller path reaching `open`:

```
Error setting image fill: ENOENT: no such file or directory, open '../../../../etc/passwd'
```

The file did not exist relative to the sandboxed working directory, so that run did not read data. The code path is the same for a path that exists.

## Impact
`imagePath` is chosen by the LLM and can be steered by prompt injection, for example from text in a Figma file or a web page the agent processed. An attacker who can also listen on the relay (any local process, or the network when the README's WSL `hostname: "0.0.0.0"` option is enabled, `socket.ts:44`) receives the file. Even without a listener, file contents end up in the MCP client's server log and the relay console. The tool result itself does not return the bytes to the LLM. If the file is a valid image, such as a screenshot, it is also placed into the Figma document. Moderate in local setups.

## Suggested fix
Add an allowlisted image directory (for example an env var), resolve `imagePath` with `fs.realpath` and reject it unless it stays under that directory. Accept only image extensions and check the magic bytes (PNG/JPEG/GIF/WEBP) before sending. Stop logging request bodies, or truncate `imageBase64` in `sendCommandToFigma`'s debug output and put debug logging behind a flag.

## Status on the default branch
Still present at `ddd90f3` (2026-07-26). The default branch has no commits after the tested commit; `set_image_fill` was added in that commit (#185).

## Prior reports
- #185 "feat: add set_image_fill, create_section, set_parent, rename_node" (PR, closed 2026-07-26): added this tool. It says the path and URL "are resolved **server-side**, so only base64 ever crosses the relay", i.e. reading a local path is intended. It adds no directory or type check.
- #130 "feat: add set_image_fill and set_font commands" (PR, closed 2026-01-28): the earlier version that #185 adapted; it took base64 or a URL only, no local path.
- #189 "fix: stop dumping full message payloads in WebSocket relay logs" (PR, open 2026-08-28): replaces the relay's full message dumps with one-line summaries. If merged it removes the `imageBase64` copy from the relay console only. The MCP server's `[DEBUG] Request details` log, the file read and the broadcast stay. Not merged at `ddd90f3`.
- #163 "Security scan: behavioral override in tool description, unauthenticated WebSocket channels, and bulk delete without confirmation (6 findings)" (issue, open 2026-03-30): a third-party scan whose finding 2 is "Unauthenticated WebSocket channels allow interception" (High). That covers the relay half of this report, not the unchecked file read. No fix.
- Documentation: README.md: "`set_image_fill` - Fill a node with an image from a local file path, URL, or base64 data" (reading a local path is documented; no allowed directory or warning is documented).
- Documentation: README.md: "Uncomment the hostname `0.0.0.0` in `src/socket.ts`" (the documented WSL setup exposes the unauthenticated relay to the network).
- Documentation: DRAGME.md: "bun socket > websocket.log 2>&1" (the setup guide saves relay output to a file, so relayed file contents persist on disk).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal` (input pattern check, "Silent Bug Alert"). Also triggered: `check_reflected_output` (not part of this claim).
- Campaigns and executions: `corpus-sbx` 2,048 execs / 2,027 success (60 s); `e2-0922` 1 / 1.
- Evidence (verbatim, trimmed): input `{'nodeId': 'node-1', 'imagePath': '../../../../etc/passwd', 'imageUrl': '', 'imageBase64': '', 'scaleMode': 'FILL'}`, output `{'content': [{'type': 'text', 'text': "Error setting image fill: ENOENT: no such file or directory, open '../../../../etc/passwd'"}]}`. Input `/etc/passwd\x00` was rejected by Node's null-byte check; `..\\..\\..\\..\\windows\\win.ini` also hit ENOENT.
- Hand-check hints: real: the raw path reaches `readFile` (the ENOENT text proves the open call). No file content was read during fuzzing, and the relay/Figma were not running, so the exfiltration through logs and the relay is from code reading. The tool description says it reads "a local image file", so the maintainer may call reading local files intended; the argument for a fix is the missing root/type check plus full-content logging and the unauthenticated broadcast. Related, not drafted: `imageUrl` goes to `fetch()` with no host restriction (`server.ts:3105-3110`), a possible SSRF.
</details>
