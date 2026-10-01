# Possible log injection in `rename_node`: `nodeId` returns in a plugin error that is logged raw

**Repository:** `sonnylazuardi/cursor-talk-to-figma-mcp` · **Tool:** `rename_node` · **Tested commit:** `ddd90f3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`rename_node` itself logs its arguments only through `JSON.stringify`, which escapes CR/LF. But when the Figma plugin cannot find the node, it builds the error `Node not found with ID: ${nodeId}` from the caller's value. The MCP server then logs that error string raw (`[ERROR] Error from Figma: ...`). A `nodeId` containing CR/LF can therefore add a forged line to the MCP server's stderr log. This needs Figma and the plugin running, and depends on Figma's API returning `null` for a malformed ID, which I could not confirm.

## Details
The plugin echoes the caller's ID in its error (`src/cursor_mcp_plugin/code.js:1143-1146`):

```js
  const node = await figma.getNodeByIdAsync(nodeId);
  if (!node) {
    throw new Error(`Node not found with ID: ${nodeId}`);
  }
```

The plugin forwards `error.message` (`code.js:99-104`) and the UI sends it back as `{id, error, result: {}}` (`src/cursor_mcp_plugin/ui.html:737-752`). Because `result` is `{}` (truthy), the MCP server takes the response branch and logs the error text unchanged (`src/talk_to_figma_mcp/server.ts:2938-2948`):

```ts
      if (
        myResponse.id &&
        pendingRequests.has(myResponse.id) &&
        myResponse.result
      ) {
        const request = pendingRequests.get(myResponse.id)!;
        clearTimeout(request.timeout);

        if (myResponse.error) {
          logger.error(`Error from Figma: ${myResponse.error}`);
```

`logger.error` writes `[ERROR] ${message}\n` straight to stderr (`server.ts:57-63`). The `name` argument does not reach a log raw: the only server-side log of the request is `logger.debug(JSON.stringify(request))` (`server.ts:3059`).

## Steps to reproduce
1. Prerequisites: Bun, a checkout at `ddd90f3` with `bun install`, Figma desktop with the Cursor MCP plugin from `src/cursor_mcp_plugin` (README "Figma Plugin").
2. Start the relay with `bun socket`, open a Figma file, run the plugin and note its channel name. Point the MCP client at `bun /path-to-repo/src/talk_to_figma_mcp/server.ts`.
3. Join the plugin's channel, then call `rename_node` with `{"nodeId": "0:999999\r\n[ERROR] FAKE-LOG-ENTRY", "name": "tofu-poc"}`:

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
               await session.call_tool("join_channel", {"channel": "<channel shown by the plugin>"})
               result = await session.call_tool("rename_node", {"nodeId": "0:999999\r\n[ERROR] FAKE-LOG-ENTRY", "name": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. In the MCP server's stderr, look for `[ERROR] Error from Figma: Node not found with ID: 0:999999` followed by a separate line `[ERROR] FAKE-LOG-ENTRY`. If Figma throws its own error for the malformed ID instead of returning `null`, the plugin error text will differ and may not contain the ID.

## Expected behavior
Error text that comes back from the plugin is escaped before logging, so one event stays on one line.

## Actual behavior
Not observed. During fuzzing no relay or Figma was running, so every call returned `Error renaming node: Not connected to Figma. Attempting to connect...` before anything was sent. The path above comes from reading the code.

## Impact
`nodeId` is chosen by the LLM and can be steered by prompt injection, for example from layer names or text in a Figma file. If the path works as read, an attacker can add fake lines to the MCP server's stderr log. No code execution or data access follows from this alone. Low.

## Suggested fix
Neutralize control characters in `logger` (`server.ts:57-63`), for example by replacing `\r` and `\n` with `\\r` and `\\n`, or log `JSON.stringify(myResponse.error)`. Optionally validate `nodeId` against Figma's ID format (for example `^[0-9]+:[0-9]+(;[0-9]+:[0-9]+)*$`) before sending it.

## Status on the default branch
Still present at `ddd90f3` (2026-07-26). The default branch has no commits after the tested commit.

## Prior reports
None found. Searched all 105 issues and 76 pull requests (fetched 2026-10-01) and the README, AGENTS.md, CLAUDE.md and DRAGME.md on the default branch. PR #185 "feat: add set_image_fill, create_section, set_parent, rename_node" (closed 2026-07-26) added this tool and says nothing about logging. The open PR #189 changes only the relay's logging, not the MCP server's `Error from Figma:` line.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, which only checks the input for `\r`/`\n` ("Silent Bug Alert"); it observed no log.
- Campaigns and executions: `corpus-sbx` 2,048 execs / 2,048 success (60 s); `e2-0922` 512 / 512. "Success" here means the handler returned without throwing; all returned the not-connected error.
- Evidence (verbatim, trimmed): input `{'nodeId': 'validNodeId', 'name': 'nodeName\nInjectedLogEntry'}`, output `{'content': [{'type': 'text', 'text': 'Error renaming node: Not connected to Figma. Attempting to connect...'}]}`. Same for `nodeId` `'"\nnod]"'` and `'\x7f\x7f\x00\x00\x00\n"'`.
- Hand-check hints: unclear. The flagged argument in the first sample (`name`) never reaches a raw log. The only plausible sink is `server.ts:2947` via the plugin's error at `code.js:1145`, which needs Figma running and depends on `figma.getNodeByIdAsync` returning `null` (not throwing) for an ID with CR/LF; I could not verify that. The same sink affects every tool whose plugin handler echoes caller input in an error, so if confirmed it is better filed as one issue about `server.ts:2947` and the logger.
</details>
