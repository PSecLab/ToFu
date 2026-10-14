# Log injection in `track_progress`: CR/LF in `action` or `description` forges entries in `progress.md`

**Repository:** `movibe/memory-bank-mcp` · **Tool:** `track_progress` · **Tested commit:** `7851e06`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`track_progress` appends a one-line, timestamped and user-attributed entry to the "Update History" section of `progress.md` and to "Current Session Notes" in `active-context.md`. The `action` and `description` strings are inserted as-is, so a CR or LF in either one ends the entry early and lets the caller add lines that look like separate history entries or new Markdown headings. Readers of the history (people or a later model session) cannot tell forged lines from real ones.

## Details
The handler passes both arguments straight to the tracker (`src/server/tools/ProgressTools.ts:44`). The entry is built by string interpolation (`src/core/ProgressTracker.ts:160-178`):

```ts
const timestamp = new Date().toISOString().split('T')[0];
const time = new Date().toLocaleTimeString();
...
const newEntry = `- [${timestamp} ${time}] [${formattedUserId}] - ${action}: ${details.description}`;
const updateHistoryRegex = /## Update History\s+/;
if (updateHistoryRegex.test(progressContent)) {
  progressContent = progressContent.replace(
    updateHistoryRegex,
    `## Update History\n\n${newEntry}\n`
  );
```

The same pattern writes `active-context.md` at `ProgressTracker.ts:206-218`. Neither path strips or escapes `\r`, `\n` or other control characters. Side note: the `updateActiveContext` argument in the tool schema is never read by the handler (`src/server/tools/index.ts:179-189`), so `active-context.md` is always updated.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. `mkdir -p /tmp/tofu-poc/project`.
2. Start the server as the README describes (`npx @movibe/memory-bank-mcp`; the tested commit is the 0.4.1 release commit), with `/tmp/tofu-poc/project` as the working directory. From a source checkout: `bun install && bun run build`, then `node build/index.js`.
3. Create a memory bank, then track progress with a CR/LF in `description`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="npx",
           args=["-y", "@movibe/memory-bank-mcp@0.4.1", "--path", "/tmp/tofu-poc/project"],
           cwd="/tmp/tofu-poc/project",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               await session.call_tool("initialize_memory_bank", {"path": "/tmp/tofu-poc/project"})
               result = await session.call_tool("track_progress", {
                   "action": "Fixed bug",
                   "description": "done\r\nFAKE-LOG-ENTRY forged history line",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `grep -n FAKE-LOG-ENTRY /tmp/tofu-poc/project/memory-bank/progress.md /tmp/tofu-poc/project/memory-bank/active-context.md` shows `FAKE-LOG-ENTRY forged history line` on its own line in both files, with no timestamp or user prefix and directly under the real entry.

## Expected behavior
Each call produces exactly one history line. CR, LF and other control characters in `action` and `description` are removed, replaced with a space, or escaped before the entry is written.

## Actual behavior
The entry is split across lines and the caller's text becomes a separate line in the history. The tool reply echoes the raw text, for example from fuzzing:

```
Progress tracked: Injected log entry
[ERROR] Unauthorized access detected - Testing log injection vulnerability.
```

## Impact
Tool arguments come from the model and can be steered by prompt injection. Forged lines can mimic entries with a different date or user (`[@name](...)`), or insert `## ...` headings that change how later regex-based updates of `active-context.md` find their sections. The severity is low: the same client can already rewrite `progress.md` in full with `write_memory_bank_file`, so this does not cross a privilege boundary. It matters mainly for the integrity of the history as an audit trail.

## Suggested fix
Normalise both fields before building the entry, for example:

```ts
const oneLine = (s: string) => s.replace(/[\r\n  ]+/g, ' ').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/g, '');
const newEntry = `- [${timestamp} ${time}] [${formattedUserId}] - ${oneLine(action)}: ${oneLine(details.description)}`;
```

Apply the same helper in `updateActiveContextFile` and in the decision log writer.

## Status on the default branch
Still present at `7851e06` (2025-03-17). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 9 pull requests (fetched 2026-10-01); none mentions `track_progress`, newline or control-character handling, or log injection. #8 "feat: Improvements in documentation, tests, and logging system for Memory Bank MCP" (PR, closed 2025-03-09) describes a centralized debug logger for the server, not the `progress.md` entry builder; it is not a fix.
- Documentation: README.md: "`progress.md`: History of project updates and milestones" (the file is presented as a history record; no note about input sanitization).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; `check_log_injection`.
- Campaigns and executions: corpus-sbx 1024 exec / 241 success; e2-0922 512 / 60.
- Evidence (verbatim, trimmed):
  - `{'action': 'Injected log entry\n[ERROR] Unauthorized access detected', 'description': 'Testing log injection vulnerability.', 'updateActiveContext': False}` -> `Progress tracked: Injected log entry\n[ERROR] Unauthorized access detected - Testing log injection vulnerability.`
  - `{'action': '"actiomn: ""Iplemented feature", "description":_', 'description': '\n\x1a', ...}` -> echoed with `\n\x1a`.
  - `{'action': '"action": \x00\x00mpl...\x1d\r\x16...', 'description': '㨢', ...}` -> echoed with NUL and CR.
- Hand-check hints: weak. The newline does reach `progress.md` / `active-context.md` unneutralised (`ProgressTracker.ts:164`, `206`), but these are Markdown notes files, not a security log, and the same caller can write them freely via `write_memory_bank_file`. ToFu's evidence only shows the echoed tool reply; the file contents after the call were not captured, so the on-disk effect is derived from code. Not run.
</details>
