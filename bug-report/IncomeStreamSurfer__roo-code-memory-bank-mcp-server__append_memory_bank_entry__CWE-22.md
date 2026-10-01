# Path traversal in `append_memory_bank_entry`: `file_name` can create or modify files outside `memory-bank/`

**Repository:** `IncomeStreamSurfer/roo-code-memory-bank-mcp-server` · **Tool:** `append_memory_bank_entry` · **Tested commit:** `9dcb2fb`
**Weakness:** CWE-22 Path Traversal

## Summary
`append_memory_bank_entry` is meant to append a timestamped entry to one of the Markdown files in the `memory-bank/` directory under the server's working directory. It joins the caller's `file_name` onto that directory and writes to the result, with no check that the path stays inside it. A `file_name` with `../` segments creates or appends to any file the server process can write, and with `section_header` set it rewrites the whole file. The README's sample configuration puts this tool in `autoApprove`, so such a call runs without user confirmation.

## Details
`src/index.ts:190-192` and the writes at `src/index.ts:200-227` (tested commit):

```ts
     const filePath = path.join(MEMORY_BANK_PATH, fileName);
     const timestamp = getCurrentTimestamp();
     const formattedEntry = `\n[${timestamp}] - ${entry}\n`;
     ...
       if (sectionHeader && typeof sectionHeader === 'string') {
         // reads filePath, inserts the entry, then:
           await fs.writeFile(filePath, updatedContent);        // line 219
         // or, if the header is not found:
           await fs.appendFile(filePath, `\n${sectionHeader}\n${formattedEntry}`);  // line 223
       } else {
         await fs.appendFile(filePath, formattedEntry);         // line 227
       }
```

`MEMORY_BANK_PATH` is `path.join(process.cwd(), "memory-bank")` (`src/index.ts:16-19`). `path.join` resolves `..` segments, so `memory-bank/../../x` points outside the directory. The only checks are that `file_name` and `entry` are non-empty strings (`src/index.ts:183-188`). `entry` may contain newlines, so the caller controls whole lines of what is written.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials needed.
2. Install and start: `git clone https://github.com/IncomeStreamSurfer/roo-code-memory-bank-mcp-server.git && cd roo-code-memory-bank-mcp-server && npm install && npm run build`, then the server is `node dist/index.js` (run from the repo directory; `memory-bank/` is resolved against the working directory).
3. Call the tool with:

   ```json
   {"file_name": "../../../../../../../../../../tmp/tofu-poc.txt", "entry": "TOFU-POC"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("append_memory_bank_entry", {"file_name": "../../../../../../../../../../tmp/tofu-poc.txt", "entry": "TOFU-POC"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the reply says `Appended entry to ../../../../../../../../../../tmp/tofu-poc.txt` and that `/tmp/tofu-poc.txt` now exists with a line like `[2026-10-01 12:00:00] - TOFU-POC`. Extra `../` segments past the filesystem root are harmless. Delete `/tmp/tofu-poc.txt` afterwards.

## Expected behavior
The tool rejects any `file_name` whose resolved path is not inside `memory-bank/` (and ideally anything that is not a plain `*.md` file name).

## Actual behavior
The resolved path is written without restriction. Our fuzzer ran on Linux with a Windows-style payload and got:

```
{
  "status": "success",
  "message": "Appended entry to ..\\..\\..\\..\\windows\\win.ini"
}
```

On Linux `\` is not a separator, so that call created a file literally named `..\..\..\..\windows\win.ini` inside `memory-bank/`. On Windows, `path.join` treats `\` as a separator and the same payload would leave the directory. On Linux and macOS the `../` form above does.

## Impact
The LLM chooses `file_name` and `entry`, and prompt injection from any content it reads can steer it. An attacker can create files or append attacker-chosen lines to any file the server's user can write, for example shell startup files or `~/.ssh/authorized_keys`, which can lead to code execution or persistent access. With `section_header` set, the tool reads and rewrites the target file. With the README's `autoApprove` configuration there is no confirmation step.

## Suggested fix
Resolve the path and reject it unless it stays under the memory bank directory:

```ts
const filePath = path.resolve(MEMORY_BANK_PATH, fileName);
const rel = path.relative(MEMORY_BANK_PATH, filePath);
if (rel.startsWith('..') || path.isAbsolute(rel)) {
  return { /* error: invalid file name */ };
}
```

Simpler still: accept only `path.basename(fileName) === fileName` and `fileName.endsWith('.md')`. Apply the same check in `readMemoryBankFile`.

## Status on the default branch
Still present at `9dcb2fb` (2025-04-29). The tested commit is the current default branch head.

## Prior reports
- #7 "Path Traversal Arbitrary File Read/Write Vulnerability in IncomeStreamSurfer/roo-code-memory-bank-mcp-server" (issue, open 2026-04-26): reports this exact bug, `path.join(MEMORY_BANK_PATH, fileName)` with no containment in `read_memory_bank_file` and `append_memory_bank_entry`, with the same recommended fix. Still open; the default branch head (`9dcb2fb`, 2025-04-29) predates it, so it is not fixed.
- #6 "Major Enhancement: Enterprise-Grade MCP Server v0.2.0" (PR, open 2025-10-20): unmerged rewrite that claims "Stricter validation for all tool inputs"; the fetched body (cut at 4000 characters) does not say it confines `file_name`, so it is not known to fix this.
- Documentation: README.md: "Appends a new, timestamped entry to a specified file ... Creates the file if it doesn't exist." (meant for memory bank files; nothing documents writing outside `memory-bank/`)
- Documentation: README.md: the sample client config lists `"append_memory_bank_entry"` under `"autoApprove"` (calls run without user confirmation)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: DUPLICATE: already reported in #7 (open issue, 2026-04-26, covers both read_memory_bank_file and append_memory_bank_entry); not fixed on the default branch. Consider commenting on #7 with the reproduction instead of filing a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); evidence fired `check_path_traversal` ("Silent Bug Alert": input flagged, tool returned success). Also triggered for this tool: `check_reflected_output`.
- Campaigns and executions: corpus-sbx 3584 exec / 657 ok (60 s); repo24-b 286208 / 59460 (4200 s); e2-0922 1536 / 160 (60 s).
- Evidence (verbatim, trimmed):
  - `{'file_name': '..\\..\\..\\..\\windows\\win.ini', 'entry': 'test', 'section_header': 'test'}` -> `{"status": "success", "message": "Appended entry to ..\\..\\..\\..\\windows\\win.ini"}`.
  - `{'file_name': '..\\..\\..\\..\\windows\\win.ini', 'entry': 'Windows path traversal attempt', 'section_header': '## Logs'}` -> same success message.
- Hand-check hints: real by code: `path.join(MEMORY_BANK_PATH, fileName)` then `fs.appendFile` / `fs.writeFile`, no containment (`src/index.ts:190-227`). But the logged evidence is not itself an escape: on the Linux fuzzing host the backslash payload created a backslash-named file inside `memory-bank/` (the sibling `read_memory_bank_file` evidence reads it back). Confirm with the `../` payload above, which writes only `/tmp/tofu-poc.txt`. The fuzzing may have left such files in the harness's scratch `memory-bank/`. README config (`autoApprove` for all four tools) is quoted from `README.md`.
</details>
