# Control characters in `log_activity` fields are stored unfiltered (JSON-escaped in the file; low impact)

**Repository:** `annenpolka/roo-logger` · **Tool:** `log_activity` · **Tested commit:** `6ebede5`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`log_activity` appends an entry to `<logsDir>/roo-activity-YYYY-MM-DD.json`. The text fields (`summary`, `intention`, `context`, `details`) are stored as given, with no filtering of CR, LF or other control characters. The file is written with `JSON.stringify`, which escapes those characters (`\r`, `\n`, `\u0013`), so a caller cannot break the JSON or forge a separate entry in the file. The remaining risk is downstream: a viewer or script that prints these fields raw to a terminal or a line-based log would show the injected line breaks and escape sequences.

## Details
The schema (`src/schemas/zod-schemas.ts:17-28`) only requires non-empty strings:

```ts
export const LogActivitySchema = z.object({
  type: ActivityTypeEnum,
  summary: z.string().min(1),
  intention: z.string().min(1),
  context: z.string().min(1),
  logsDir: z.string().min(1),
  ...
```

`createActivityLog` (`src/functions/log-entry.ts:16-33`) copies the fields unchanged. `appendToJsonFile` (`src/functions/file-io.ts:92-108`) writes the whole array:

```ts
fs.writeFile(filePath, JSON.stringify(updatedLogs, null, 2), 'utf-8')
```

`JSON.stringify` escapes control characters, so the stored file stays well-formed. `search_logs` also returns entries through `JSON.stringify` (`src/index.ts:82-92`), so the server itself never prints the raw values.

## Steps to reproduce
1. Prerequisites: Node.js 18+.
2. Install and start as the README describes (`npx -y github:annenpolka/roo-logger`), or from a clone: `npm install && npm run build`, then `node dist/index.js`.
3. Call the tool:
   ```json
   {"type": "conversation", "summary": "tofu-poc\r\nFAKE-LOG-ENTRY", "intention": "test", "context": "test", "logsDir": "/tmp/tofu-logs"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/roo-logger/dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("log_activity", {
                   "type": "conversation",
                   "summary": "tofu-poc\r\nFAKE-LOG-ENTRY",
                   "intention": "test",
                   "context": "test",
                   "logsDir": "/tmp/tofu-logs",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-logs/roo-activity-<date>.json` contains `"summary": "tofu-poc\r\nFAKE-LOG-ENTRY"` as an escaped JSON string. The file is still valid JSON with one entry. A consumer that prints `summary` raw (for example `jq -r '.[].summary'`) shows `FAKE-LOG-ENTRY` on its own line.

## Expected behavior
Either the server strips or escapes control characters in single-line fields (`summary`, `intention`, `context`) on input, or it documents that stored values are untrusted and must be escaped when displayed.

## Actual behavior
The call succeeds and the control characters are stored (escaped by JSON). From the fuzzing run, a `summary` containing `\x13\x10` and `\r` was accepted:

```
{"success": true, "logId": "84926b30-f770-4d41-8880-780f3547b396", "filePath": "+far/log/app/roo-activity-2026-09-26.json"}
```

## Impact
These fields are written by the LLM from the conversation, which can contain injected text. Inside the log file the JSON encoding neutralizes CR/LF, so entries cannot be forged there. The risk exists only for tools that later render the values raw: misleading lines in a terminal view, or terminal escape sequences (ESC is stored as `\u001b`). Low severity.

## Suggested fix
- Strip or replace `\r`, `\n` and other C0 control characters (except perhaps `\n` in `details`) in `summary`, `intention` and `context`. A zod `.transform()` or `.regex()` on the schema can do this.
- Note in the README that log values are untrusted input for any viewer that prints them raw.

## Status on the default branch
Still present at `6ebede5` (2025-07-05). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 3 issues and 6 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README (English, Japanese, Chinese) documents the fields of `log_activity` and requires `logsDir` to be an absolute path, but says nothing about control characters or about escaping stored values when they are displayed.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` only.
- Campaigns and executions: corpus-sbx 2560 exec / 242 ok; e2-0922 1536 exec / 215 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'type': 'conversation', 'summary': '"tention": "Testing \x13\x10r deadlock", "context": "Simulate nolg operat\x17\rn", "logsDir": "+far/log/app", "level": "info", "de', 'intention': '\U00056961...', 'context': 'Simulate nolg operatn', 'logsDir': '+far/log/app', ...}` -> `{"success": true, "logId": "84926b30-...", "filePath": "+far/log/app/roo-activity-2026-09-26.json"}`
  - Two near-identical variants -> same success output with different `logId`s.
- Hand-check hints: weak, likely a false positive for log forging. The sink is `JSON.stringify` (`src/functions/file-io.ts:104`), which escapes CR/LF, so the stored log cannot be split or forged. ToFu flagged control characters in the input of a call that succeeded. It did not observe an unescaped write. Separately, `logsDir` is caller-controlled with no containment (`path.join(logsDir, fileName)` plus `mkdir -p`, `src/tools/mcp-tools.ts:24`, `src/functions/file-io.ts:97-99`): the evidence call created `+far/log/app/` under the cwd. The file name is fixed (`roo-activity-YYYY-MM-DD.json`) and a non-array existing file is replaced, not appended to (`file-io.ts:88`). The README presents per-activity directories as a feature, so this is by design. I recommend not filing, or filing only as a hygiene note. The reproduction above was derived from the code and has not been run.
</details>
