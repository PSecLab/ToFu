# Log injection in `snapshot_scene`: CR/LF in `name` forges lines in the canvas server log file

**Repository:** `yctimlin/mcp_excalidraw` · **Tool:** `snapshot_scene` · **Tested commit:** `713706e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`snapshot_scene` saves the canvas under a caller-chosen `name`. The canvas server writes that name into its winston log with a template string, and the log format prints the message as is. A name containing `\r\n` therefore starts a new, attacker-written line in the log file, which can imitate a real entry.

## Details
The MCP side logs the name safely as metadata (`src/core/mcp-dispatch.ts:577`, JSON-encoded by the formatter) and forwards it to the canvas server (`src/core/canvas-client.ts:199-205`). The canvas server then logs it inside the message string, `src/server.ts:1182-1200` (tested commit):

```ts
app.post('/api/snapshots', (req: Request, res: Response) => {
  const { name } = req.body;
  if (!name || typeof name !== 'string') { ... }
  ...
  snapshots.set(name, snapshot);
  logger.info(`Snapshot saved: "${name}" with ${snapshot.elements.length} elements`);
```

The formatter in `src/utils/logger.ts:52-61` is `printf(info => \`${info.timestamp} [${info.level}] ${info.message}${extra}\`)`. Only `metadata` is JSON-encoded; `message` is written raw. The file transport logs `info` and above to `~/Library/Logs/excalidraw-mcp.log` (macOS), `$XDG_STATE_HOME/excalidraw-mcp/excalidraw.log` (Linux), or `LOG_FILE_PATH`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. The MCP server auto-starts the canvas on `127.0.0.1:3000`.
2. Start the server: `npx -y mcp-excalidraw-server` (or from source: `npm ci && npm run build && node dist/index.js`). Optionally set `LOG_FILE_PATH=/tmp/tofu-excalidraw.log` to make the file easy to find. The auto-spawned canvas inherits the environment (`src/core/spawn.ts:109-112`); stop any canvas left running from an earlier session first, since it is detached and keeps its own log path.
3. Call the tool with:

   ```json
   {"name": "snap\r\n2026-01-01 00:00:00.000 [error] FAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       env = dict(os.environ, LOG_FILE_PATH="/tmp/tofu-excalidraw.log")
       server = StdioServerParameters(command="npx", args=["-y", "mcp-excalidraw-server"], env=env)
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("snapshot_scene",
                   {"name": "snap\r\n2026-01-01 00:00:00.000 [error] FAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Open the log file. Expect a line ending in `[info] Snapshot saved: "snap` followed by a separate line `2026-01-01 00:00:00.000 [error] FAKE-LOG-ENTRY" with N elements`.

## Expected behavior
CR, LF and other control characters in `name` are rejected, or escaped before logging, so each log record stays on one line.

## Actual behavior
The name is accepted and stored with the raw line break. From the fuzzing run, the tool reply shows the unmodified name:

```
Snapshot "snapshot
CRITICAL: system failure" saved (1 elements)
```

We did not capture the log file during the run; the log line is inferred from `src/server.ts:1200` and the formatter.

## Impact
The LLM chooses `name`, and prompt injection in content the agent reads can steer it. An attacker can add fake records (for example a fake `[error]` line) to the local log, which can mislead someone debugging the server or a tool that parses the log. The log is local to the user's machine, so the severity is low.

## Suggested fix
- Validate snapshot names in both the MCP schema and the `/api/snapshots` route, for example `z.string().regex(/^[\w .-]{1,100}$/)`.
- Log user values as metadata (`logger.info('Snapshot saved', { name, count })`), which the formatter already JSON-encodes, instead of interpolating them into the message. The same pattern appears in other routes of `src/server.ts`.

## Status on the default branch
Still present at `713706e` (2026-09-08). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports this. Searched all 48 issues and 61 pull requests (fetched 2026-10-01); none mentions CR/LF in snapshot names or log-message escaping.
- #74 "security: authentication, path traversal, prompt injection, and hardening fixes" (PR, open 2026-04-16): item M5, "Snapshot name overwrite", keys snapshots by `randomUUID()` and item M6 redacts `data`/`dataURL` in log metadata; neither neutralises `name` in the log message. Not merged.
- #82 "fix(logger): platform-aware default log path instead of CWD" (PR, closed 2026-05-16) and #83 "fix(logger): platform-aware log path with render hardening" (PR, closed 2026-05-16): changed only the log file location; #82 states "No changes to log format, log level, or log content". The follow-ups listed in #83 are a temp-file fallback for the log path and freedraw rendering in the frontend; neither escapes log messages.
- #39 "Security audit: 7 vulnerabilities (2 critical, 3 high, 2 medium)" (issue, open 2026-02-08): the readable part of the body (first 4000 characters) does not mention logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 1024 exec / 620 ok; e2-0922 512 exec / 349 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'name': 'snapshot\nCRITICAL: system failure'}` -> `Snapshot "snapshot\nCRITICAL: system failure" saved (1 elements)\n\n{ "success": true, "name": "snapshot\\nCRITICAL: system failure", ... }`
  - `{'name': '\n'}` -> `Snapshot "\n" saved (1 elements)`
  - `{'name': 'l"}\x7f\x7f\x7f\x7f\r\x7f\x7f'}` -> saved, echoed with raw `\r`.
- Hand-check hints: real. The canvas server writes `name` into the winston message via a template string (`src/server.ts:1200`), and the printf formatter emits `message` unescaped, so CR/LF reach the log file. ToFu's sanitizer only checks for CR/LF in the input; the sink was confirmed by reading source, not by reading the log file from the run. The MCP-side log at `mcp-dispatch.ts:577` is safe (metadata is JSON-stringified). Severity is low (local log file).
</details>
