# Log injection in `storeMilestone`: CR/LF in `title` or `importance` forges server log lines

**Repository:** `aurda012/cursor10x-mcp` · **Tool:** `storeMilestone` · **Tested commit:** `0fc2ad7`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`storeMilestone` saves a milestone to long-term memory and then logs `Stored milestone: "<title>" with importance: <importance>`. Both values come from the tool arguments and are written to stderr with no neutralization. Every log line starts with a `[ISO timestamp]` prefix, so a title containing CR/LF followed by a fake timestamp produces a line that looks exactly like a genuine log entry. MCP clients usually save server stderr to their log files.

## Details
The logger, `index.js:661-665`:

```js
function log(message, level = "info") {
  const timestamp = new Date().toISOString();
  const prefix = level === "error" ? "ERROR: " : "";
  console.error(`[${timestamp}] ${prefix}${message}`);
}
```

The call in the handler, `index.js:2572`:

```js
            log(`Stored milestone: "${title}" with importance: ${importance}`);
```

`title` and `importance` are destructured from the arguments at `index.js:2538`. The schema only requires strings (`index.js:1125-1152`). The log call runs after the store, in both the in-memory and the database branch. `description` is not logged, so CR/LF in `description` does not reach this sink.

## Steps to reproduce
1. Prerequisites: Node.js. `TURSO_DATABASE_URL` / `TURSO_AUTH_TOKEN` are optional. Without them the server uses an in-memory store (`index.js:1361-1364`).
2. Start the server as the README describes: `npx -y cursor10x-mcp`. To test the tested commit, run `npm install` in a checkout at `0fc2ad7`, then `node index.js`. In that case the checked-in `.env` points the server at a local SQLite file.
3. Call the tool:

   ```json
   {"title": "tofu-poc\r\n[2026-01-01T00:00:00.000Z] FAKE-LOG-ENTRY", "description": "d", "importance": "low"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "cursor10x-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("storeMilestone", {"title": "tofu-poc\r\n[2026-01-01T00:00:00.000Z] FAKE-LOG-ENTRY", "description": "d", "importance": "low"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr, which the Python client forwards to your terminal by default. One `log()` call prints two lines, and the second looks like its own timestamped entry:

   ```
   [<now>] Stored milestone: "tofu-poc
   [2026-01-01T00:00:00.000Z] FAKE-LOG-ENTRY" with importance: low
   ```

## Expected behavior
CR, LF and other control characters in `title` and `importance` are escaped before logging. One call produces one log line.

## Actual behavior
The values are logged unchanged. The tool itself reports success, for example with this fuzzing input, where the title contained a raw `\r`:

```
input:  {'title': '"title": "Sensitive Data Leak", [...] "im\x10\x10\r\x08ance": "high",$"metadata": {', 'description': '', 'importance': '', 'metadata': {}}
output: {"status":"ok","title":"\"title\": \"Sensitive Data Leak\", [...] \"im\u0010\u0010\r\bance\": \"high\",$\"metadata\": {","timestamp":1790453195447}
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content (for example, a file the agent is summarising into a milestone) can steer them. An attacker can then add fake, correctly timestamped lines to the MCP server log kept by Cursor or another client. That can mislead someone reading the log while debugging. Low severity.

## Suggested fix
- In `log()`, neutralize control characters once for every caller: `message.replace(/[\r\n]/g, (c) => (c === '\r' ? '\\r' : '\\n'))`.
- Or log untrusted values with `JSON.stringify(title)`. The same pattern appears in other handlers, for example `storeDecision` at `index.js:2617`.

## Status on the default branch
Still present at `0fc2ad7` (2025-05-07). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 7 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Only `check_log_injection` fired.
- Campaigns and executions: `corpus-sbx` 2560 executions / 2552 successful; `e2-0922` 1536 / 1528; 60 s budget each.
- Evidence (verbatim, trimmed):
  - input `{'title': 'Normal Title', 'description': 'Testing log injection\nINFO: User admin logged in', 'importance': 'low', 'metadata': {}}`, output `{"status":"ok","title":"Normal Title","timestamp":1790453193809}`
  - input `{'title': '"title": "Sensitive Data Leak", "description": "Error: password\x7f[...]=secret1234", "im\x10\x10\r\x08ance": "high",$"metadata": {', 'description': '', 'importance': '', 'metadata': {}}`, output as quoted above. The `secret1234` is the fuzzer's own payload text, not a repo secret.
- Hand-check hints: **real, low severity**. Evidence rows 1 and 2 put the newline in `description`, which is **not** logged (`index.js:2572` logs only `title` and `importance`). Those rows on their own would be false positives. Row 3 puts a raw `\r` in `title`, which does reach `console.error` unneutralized. The sink is clear from the code. The expected stderr in step 4 is derived from the template string and has not been observed. ToFu's tracer output for the stderr write was not included in the evidence.
</details>
