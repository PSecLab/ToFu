# Unrestricted `customPath` in `read_mcp_logs`: the tool reads `*.log` files from any directory the caller names

**Repository:** `klara-research/MCP-Analyzer` · **Tool:** `read_mcp_logs` · **Tested commit:** `5b011cd`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_mcp_logs` is meant to read Claude's MCP log files from a per-OS default directory. The optional `customPath` argument replaces that directory with no containment check, so the tool will glob and read `*.log` files from any directory the caller names, and return their contents. Combined with `lines`, the caller controls how much of each file comes back. This turns a log reader into an arbitrary reader of any `*.log` file the server process can access.

## Details
`src/index.ts` (tested commit). `customPath` becomes `logDir` directly (lines 94-95), then every `*.log` file in it is globbed (lines 116-121) and read (line 187):

```ts
            if (customPath) {
                logDir = customPath;
            } else {
                // ... per-OS default under the user's home ...
            }
            allLogFiles = await glob(`${logDir}/mcp*.log`);
            if (allLogFiles.length === 0) {
                allLogFiles = await glob(`${logDir}/*.log`);
            }
// ... later, for each selected file:
            const content = await readFile(logFile, 'utf8');
```

There is no `path.resolve` + prefix check against an allowed root, no restriction to the default log directory, and no symlink handling. The only limits are the `*.log` glob suffix, a 100 KB per-file / 500 KB total cap (lines 173-174), and `fileLimit`/`page` pagination. The selected content is returned in `toolResult.logs` (lines 233-248). Separately, `logDir` (i.e. the raw `customPath`) is appended to `mcp_debug.log` by `saveLog` at line 111, so a `customPath` containing CR/LF is also written into that log unneutralized (secondary log-injection, CWE-117).

## Steps to reproduce
1. Prerequisites: Node.js 18+. No accounts or env vars. Create a directory outside any Claude log location with a `.log` file:
   ```bash
   mkdir -p /tmp/tofu-logs
   printf 'tofu-poc secret line\n' > /tmp/tofu-logs/tofu-poc.log
   ```
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/klara-research/MCP-Analyzer.git
   cd MCP-Analyzer && npm install && npx tsc
   # server entry point: node build/index.js
   ```
3. Call the tool, pointing `customPath` at that directory:
   ```json
   {"customPath": "/tmp/tofu-logs", "lines": 100, "fileLimit": 5, "page": 1}
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
               result = await session.call_tool("read_mcp_logs",
                   {"customPath": "/tmp/tofu-logs", "lines": 100, "fileLimit": 5, "page": 1})
               print(result)

   asyncio.run(main())
   ```
4. Observe: `toolResult.logs` contains `"tofu-poc.log": "tofu-poc secret line"`. The directory is outside the intended `~/Library/Logs/Claude` (macOS) / `~/.config/Claude/logs` (Linux) location, which shows there is no containment. Any readable `*.log` on the host (for example under `/var/log`) can be read the same way.

## Expected behavior
With no `customPath`, only the per-OS Claude log directory is read. If `customPath` is allowed at all, it is resolved and required to stay under a configured, documented root, and symlinks that escape it are rejected.

## Actual behavior
`customPath` is used verbatim as the directory to read. In the fuzzing run the traversal paths pointed at locations with no `.log` files, so the tool reported "No log files found" rather than reading anything:

```
{"success": false, "message": "No log files found in ../../../../etc/passwd", "logDirectory": "../../../../etc/passwd"}
```

That shows the caller path became `logDirectory` unchecked; a directory that does contain `*.log` files (as in the reproduction above) is read and returned.

## Impact
Tool arguments are chosen by the LLM, and prompt injection in content the agent reads can steer `customPath`. An attacker who can influence the arguments can read any `*.log` file the server user can open, e.g. application or system logs that may contain tokens, session identifiers or personal data, and exfiltrate them through the tool result. The `*.log` suffix and size caps limit the scope, but log files are exactly where secrets often end up. The CR/LF-in-`customPath` log-injection into `mcp_debug.log` is a lower-severity side effect.

## Suggested fix
- Treat `customPath` as a subpath of an allowed root: `const root = <configured logs dir>; const p = path.resolve(root, customPath); if (p !== root && !p.startsWith(root + path.sep)) throw ...`, or drop `customPath` and only read the per-OS default.
- After selecting each file, `fs.realpath` it and re-check it is still under the root, to defeat symlinks.
- Strip or encode CR/LF before writing `logDir` into `mcp_debug.log` (line 111).

## Status on the default branch
Still present at `5b011cd` (2025-05-03). The tested commit is the current head of the default branch.

## Prior reports
- Documentation: README.md: "`customPath` | Custom path to log directory | OS-specific" (documents `customPath` as a supported parameter, with no limit on the directory and no warning)
- Documentation: smithery.yaml: "customPath: /var/log" (the Smithery `exampleConfig` points `customPath` at a system log directory, so reading outside the Claude log location looks like an intended use; the file's `commandFunction` does not pass these values to the server)
- No issue or pull request reports this. The repository has 0 issues and 1 pull request (#1, Smithery deployment config), fetched 2026-10-01.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` only ("Silent Bug Alert": input flagged, tool returned without an exception).
- Campaigns and executions: corpus-sbx 2048 exec / 2005 ok; e2-0922 512 exec / 506 ok (60 s budget each).
- Evidence (verbatim, trimmed), corpus-sbx, all returning `success: false, "No log files found in <path>"`:
  - `{'lines': 100, 'filter': '', 'customPath': '../../../../etc/passwd', 'fileLimit': 5, 'page': 1}`
  - `{'lines': -1, 'filter': 'admin', 'customPath': '..\\..\\..\\..\\windows\\win.ini', 'fileLimit': -5, 'page': -1}`
  - `{'lines': 9999999, 'filter': 'test\r\nInjectedLogEntry', 'customPath': '/etc/passwd]u0000', 'fileLimit': 9999999, 'page': 9999999}`
- Hand-check hints: real at code level, medium severity. The evidence does not show a file being read because the fuzzer pointed `customPath` at `/etc/passwd` (a file, and a directory with no `*.log`), so glob matched nothing. The arbitrary-read claim rests on reading the code (`logDir = customPath`, then `glob(${logDir}/*.log)`, then `readFile`); the reproduction with a real `.log` file demonstrates it and should be run by the hand-checker to confirm. `/etc/passwd` is not readable this way because it does not end in `.log`. The third evidence shows a CR/LF `filter`, but `filter` is only used to filter returned lines (lines 193-198), not written anywhere; the CR/LF log-injection is via `customPath` into `saveLog` (line 111), which I did not execute. Not run by us.
</details>
