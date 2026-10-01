# `search_crates` puts the raw `query` into a log message (pino escapes CR/LF, so no forged lines)

**Repository:** `laptou/rust-docs-mcp-server` · **Tool:** `search_crates` · **Tested commit:** `b05dedd`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`search_crates` builds its log message by string interpolation of the caller's `query`. The server logs through pino, which writes one JSON object per line and JSON-escapes control characters in the message, so a `query` with CR/LF does not create a new log line in the server's own output. The remaining risk is small: it applies only if the stderr stream is later printed through a formatter that unescapes the message. This is a hardening note, not a confirmed log injection.

## Details
The query goes into the message text at `src/service.ts:25`:

```ts
export async function searchCrates(
	options: SearchOptions,
): Promise<CrateSearchResult> {
	try {
		logger.info(`searching for crates with query: ${options.query}`);
```

The tool handler passes `query` through after only `z.string().min(1)` (`src/index.ts:53-66`). The logger is pino writing raw records to stderr (`src/utils/logger.ts:4-16`):

```ts
export const logger = pino({
	level: process.env.LOG_LEVEL || "warn",
	transport: {
		target: "pino/file",
		options: { destination: 2 }, // stderr
	},
```

Two things limit the effect. The default level is `warn`, so the `info` line at `service.ts:25` is not written unless `LOG_LEVEL` is `info` or lower. When it is written, pino serializes the message as a JSON string, which turns CR and LF into the escape sequences `\r` and `\n`. The same pattern (template-string interpolation of caller input into `info`/`error` messages) is used for `crateName` and `path` throughout `src/service.ts`.

## Steps to reproduce
1. Prerequisites: Bun (for install and build) and Node.js 18+. The tool calls crates.io, but the log line is written before that request, so network access is not needed to see it.
2. Install and build as the README describes: `git clone https://github.com/laptou/rust-docs-mcp-server.git && cd rust-docs-mcp-server && bun install && bun run build`. The built server is `build/index.js`.
3. Call the tool with `LOG_LEVEL=info` and `{"query": "tofu-poc\r\nFAKE-LOG-ENTRY", "page": 1, "perPage": 10}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"], env={"LOG_LEVEL": "info"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("search_crates", {"query": "tofu-poc\r\nFAKE-LOG-ENTRY", "page": 1, "perPage": 10})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr. Expected by code reading: a single JSON line whose `msg` is `"searching for crates with query: tofu-poc\r\nFAKE-LOG-ENTRY"` with the CR/LF escaped, and no separate `FAKE-LOG-ENTRY` line.

## Expected behavior
Caller input is passed as a structured field (for example `logger.info("searching for crates", { query })`) rather than spliced into the message, so it stays escaped no matter how the log is later formatted.

## Actual behavior
The raw query is part of the message string. In the server's own NDJSON output it is escaped, so no line is forged. The fuzzing run's call returned normal search results:

```
input:  {'query': 'test\nCRITICAL: leaked secret', 'page': 1, 'perPage': 10}
output: {'content': [{'type': 'text', 'text': '{\n  "crates": [\n    {\n      "name": "asupersync", ...
```

## Impact
`query` is chosen by the LLM and can be steered by prompt injection. With the current pino setup an attacker cannot add log lines. If someone views the log through a pretty-printer that writes the message as plain text, embedded line breaks could show up as extra lines. Very low severity.

## Suggested fix
Pass caller values as fields instead of interpolating them: `logger.info("searching for crates", { query: options.query })`, and the same for `crateName` and `path` in `src/service.ts`. This keeps the message constant and leaves escaping to pino in every output mode.

## Status on the default branch
Still present at `b05dedd` (2025-03-02). The default branch has no commits after the tested commit.

## Prior reports
None found. Searched all 4 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The only items that mention security are #5 "Add MseeP.ai badge to README" and #7 "Add MseeP.ai badge" (PRs, open 2025-04-25 and 2025-07-17), third-party badge PRs reporting an automated scan score of 100/100 with no findings; the README does not mention logging or `LOG_LEVEL`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_log_injection` only (static input-pattern check: "flagged this input as malicious, but the target tool executed successfully"). No introspection log check fired; this is a Node target. Also triggered: `check_resource_exhaustion` (not part of this claim).
- Campaigns and executions: `e2-0922` 1 exec / 0 success (60 s). The single evidence call did return results, so the 0 success count is odd; possibly the large output was counted as a failure.
- Evidence (verbatim, trimmed): input `{'query': 'test\nCRITICAL: leaked secret', 'page': 1, 'perPage': 10}`, output a normal crates.io result list (first entry `asupersync` 0.5.0).
- Hand-check hints: weak, likely a false positive; recommend not filing, or filing only as a low-priority hardening note. Caller input does reach `logger.info` unescaped at the call site (`service.ts:25`), but pino's `asString` falls back to `JSON.stringify` for any string containing a character below 0x20, so CR/LF are escaped in the output. I checked this in a local pino 8.21.0 (`lib/tools.js:81-104`, from another target's `node_modules`), not in the 9.6.0 pinned in `bun.lock`; I believe the behavior is the same but did not confirm. The info line is also off by default (`LOG_LEVEL` defaults to `warn`). Step 4 is derived from code, not run.
</details>
