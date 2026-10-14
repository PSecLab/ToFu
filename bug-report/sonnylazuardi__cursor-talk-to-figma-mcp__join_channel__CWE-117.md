# Log injection in `join_channel`: CR/LF in `channel` forges lines in the MCP server and relay logs

**Repository:** `sonnylazuardi/cursor-talk-to-figma-mcp` · **Tool:** `join_channel` · **Tested commit:** `ddd90f3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`join_channel` writes the caller's channel name into log lines without neutralizing CR/LF, both in the MCP server (stderr, `[INFO] Joined channel: ...`) and in the WebSocket relay (`bun socket` console output). A channel name such as `tofu\r\n[ERROR] FAKE-LOG-ENTRY` produces a separate, real-looking log line. The relay alone is enough to trigger it; Figma does not need to be open.

## Details
The MCP server's logger writes raw strings to stderr with a level prefix (`src/talk_to_figma_mcp/server.ts:57-63`), and `joinChannel` passes the channel name straight in (`server.ts:2987-2999`):

```ts
async function joinChannel(channelName: string): Promise<void> {
  if (!ws || ws.readyState !== WebSocket.OPEN) {
    throw new Error("Not connected to Figma");
  }

  try {
    await sendCommandToFigma("join", { channel: channelName });
    currentChannel = channelName;
    logger.info(`Joined channel: ${channelName}`);
```

The relay logs the same value before and after the join (`src/socket.ts:81` and `:108`):

```ts
        console.log(`Type: ${data.type}, Channel: ${data.channel || 'N/A'}`);
...
          console.log(`\n✓ Client joined channel "${channelName}" (${channelClients.size} total clients)`);
```

The `join_channel` tool schema (`server.ts:3290-3295`) accepts any string, and the relay accepts any non-empty string as a channel name (`socket.ts:89-97`).

## Steps to reproduce
1. Prerequisites: Bun, a checkout of the repo at `ddd90f3`, `bun install`. Figma is not required.
2. Start the relay as the README describes: `bun socket` (listens on port 3055). Point the MCP client at `bun /path-to-repo/src/talk_to_figma_mcp/server.ts` (README "Local Development Setup"); the script below does that.
3. Call `join_channel` with `{"channel": "tofu\r\n[ERROR] FAKE-LOG-ENTRY"}`:

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
               result = await session.call_tool("join_channel", {"channel": "tofu\r\n[ERROR] FAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. In the MCP server's stderr (printed by `stdio_client`), `[INFO] Joined channel: tofu` is followed by a separate line `[ERROR] FAKE-LOG-ENTRY`. The relay terminal shows the same forged line after `Type: join, Channel: tofu` and after `✓ Client joined channel "tofu`.

## Expected behavior
The channel name is escaped or rejected, so each log call stays one line, for example `[INFO] Joined channel: "tofu\r\n[ERROR] FAKE-LOG-ENTRY"`.

## Actual behavior
A new `[ERROR]` line appears that the server never logged. During fuzzing the relay was not running, so the tool returned `Error joining channel: Not connected to Figma` and this log line was not reached; the result above comes from reading the code.

## Impact
The channel name is chosen by the LLM and can be steered by prompt injection, for example from text inside a Figma file or a web page the agent processed. An attacker can add fake entries to the MCP server log (which clients often save to a file) and to the relay console, which can mislead someone debugging a session. No code execution or data access follows from this alone. Low.

## Suggested fix
Validate channel names in both `join_channel` and the relay, for example `^[A-Za-z0-9_-]{1,64}$`. Independently, make `logger` neutralize control characters, for example `message.replace(/[\r\n]/g, (c) => (c === "\r" ? "\\r" : "\\n"))`, or log values with `JSON.stringify(value)`.

## Status on the default branch
Still present at `ddd90f3` (2026-07-26). The default branch has no commits after the tested commit.

## Prior reports
- #189 "fix: stop dumping full message payloads in WebSocket relay logs" (PR, open 2026-08-28): rewrites the relay's receive log as one line, `recv type=message channel=... size=...`. The body says payload values are not logged but does not say the channel name is escaped, and it does not touch the MCP server's `Joined channel:` log. Not merged at `ddd90f3`; it does not fix this.
- #126 "Fix: Resolve MCP-Figma communication timeout by fixing broadcast logic" (PR, closed 2025-10-28): added the relay's message-flow logging ("Message type and channel identification"), which is where the relay lines in this report come from. Not a report.
- Documentation: DRAGME.md: "bun socket > websocket.log 2>&1" (the setup guide saves relay output to a file, so forged lines persist). AGENTS.md / CLAUDE.md: "All logs go to stderr." No doc mentions escaping.
- No issue or PR reports CR/LF in channel names. Searched all 105 issues and 76 pull requests (fetched 2026-10-01) and the README, AGENTS.md, CLAUDE.md and DRAGME.md on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection`, which only checks the input for `\r`/`\n` ("Silent Bug Alert"); it does not observe any log.
- Campaigns and executions: `corpus-sbx` 2,560 execs / 2,560 success (60 s); `e2-0922` 1 / 1.
- Evidence (verbatim, trimmed): input `{'channel': 'logs\nCRITICAL: injected log entry'}`, output `{'content': [{'type': 'text', 'text': 'Error joining channel: Not connected to Figma'}]}`. Same output for `'"{*\n\t\x7f\x7f'` and `'\x05]]\nc'`.
- Hand-check hints: real by code reading: `server.ts:2995` and `socket.ts:81,108` interpolate the raw channel into log output. Not observed at runtime: every fuzzed call failed at `server.ts:2989` because no relay was running. The `asyncio.sleep(2)` is my addition to avoid that race. The relay's reply path (`socket.ts:117-124` sends `{id, result}`; `server.ts:2938-2951` resolves on it) means the join succeeds without Figma.
</details>
