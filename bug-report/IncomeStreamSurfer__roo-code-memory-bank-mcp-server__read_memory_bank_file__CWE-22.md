# Path traversal in `read_memory_bank_file`: `file_name` can read files outside `memory-bank/`

**Repository:** `IncomeStreamSurfer/roo-code-memory-bank-mcp-server` · **Tool:** `read_memory_bank_file` · **Tested commit:** `9dcb2fb`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_memory_bank_file` is meant to read one of the Markdown files in the `memory-bank/` directory under the server's working directory. It joins the caller's `file_name` onto that directory and reads the result, with no check that the path stays inside it. A `file_name` with `../` segments reads any file the server process can read and returns its content. The README's sample configuration puts this tool in `autoApprove`, so such a call runs without user confirmation.

## Details
`src/index.ts:16-19` and `src/index.ts:165-173` (tested commit):

```ts
const MEMORY_BANK_DIR_NAME = "memory-bank";
const BASE_PATH = process.cwd();
const MEMORY_BANK_PATH = path.join(BASE_PATH, MEMORY_BANK_DIR_NAME);
...
  async readMemoryBankFile(input: any) {
    const fileName = input?.file_name;
    if (!fileName || typeof fileName !== 'string') { /* error */ }
    const filePath = path.join(MEMORY_BANK_PATH, fileName);
    try {
      const fileContent = await fs.readFile(filePath, 'utf-8');
      return { content: [{ type: "text", text: JSON.stringify({ content: fileContent }, null, 2) }] };
```

`path.join` resolves `..` segments, so `memory-bank/../../x` points outside the directory. The only check is that `file_name` is a non-empty string. Nothing compares the resolved path against `MEMORY_BANK_PATH`, and the extension is not restricted to `.md`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials needed.
2. Install and start: `git clone https://github.com/IncomeStreamSurfer/roo-code-memory-bank-mcp-server.git && cd roo-code-memory-bank-mcp-server && npm install && npm run build`, then the server is `node dist/index.js` (run from the repo directory; `memory-bank/` is resolved against the working directory).
3. Call the tool with:

   ```json
   {"file_name": "../../../../../../../../../../etc/hostname"}
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
               result = await session.call_tool("read_memory_bank_file", {"file_name": "../../../../../../../../../../etc/hostname"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the reply is `{"content": "<the machine's hostname>\n"}`, the content of `/etc/hostname`, which is outside `memory-bank/`. Extra `../` segments past the filesystem root are harmless, so the count does not need to match the checkout depth.

## Expected behavior
The tool rejects any `file_name` whose resolved path is not inside `memory-bank/` (and ideally anything that is not a plain `*.md` file name).

## Actual behavior
The resolved path is read without restriction. Our fuzzer ran on Linux with a Windows-style payload, `..\..\..\..\windows\win.ini`. On Linux `\` is not a path separator, so that call read a file literally named `..\..\..\..\windows\win.ini` inside `memory-bank/` (created by earlier fuzzed `append_memory_bank_entry` calls) and returned its entries:

```
{
  "content": "\ntest\n\n[2026-09-16 13:46:39] - test\n\n[2026-09-16 13:46:39] - test\n..."
}
```

On Windows, `path.join` treats `\` as a separator and the same payload would leave the directory. On Linux and macOS the `../` form above does.

## Impact
The LLM chooses `file_name`, and prompt injection from any content it reads can steer it. An attacker can read any file the server's user can read (source code, `.env` files, SSH keys, cloud credentials) and get it back in the tool result, where it can be exfiltrated through later tool calls or the model's reply. With the README's `autoApprove` configuration there is no confirmation step.

## Suggested fix
Resolve the path and reject it unless it stays under the memory bank directory:

```ts
const filePath = path.resolve(MEMORY_BANK_PATH, fileName);
const rel = path.relative(MEMORY_BANK_PATH, filePath);
if (rel.startsWith('..') || path.isAbsolute(rel)) {
  return { /* error: invalid file name */ };
}
```

Simpler still: accept only `path.basename(fileName) === fileName` and `fileName.endsWith('.md')`. Apply the same check in `appendMemoryBankEntry`.

## Status on the default branch
Still present at `9dcb2fb` (2025-04-29). The tested commit is the current default branch head.

## Prior reports
- #7 "Path Traversal Arbitrary File Read/Write Vulnerability in IncomeStreamSurfer/roo-code-memory-bank-mcp-server" (issue, open 2026-04-26): reports this exact bug, `path.join(MEMORY_BANK_PATH, fileName)` with no containment in `read_memory_bank_file` and `append_memory_bank_entry`, with the same recommended fix. Still open; the default branch head (`9dcb2fb`, 2025-04-29) predates it, so it is not fixed.
- #6 "Major Enhancement: Enterprise-Grade MCP Server v0.2.0" (PR, open 2025-10-20): unmerged rewrite that claims "Stricter validation for all tool inputs"; the fetched body (cut at 4000 characters) does not say it confines `file_name`, so it is not known to fix this.
- Documentation: README.md: "Reads the full content of a specified memory bank file." (scope is the memory bank; nothing documents reading other files)
- Documentation: README.md: the sample client config lists `"read_memory_bank_file"` under `"autoApprove"` (calls run without user confirmation)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: DUPLICATE: already reported in #7 (open issue, 2026-04-26, covers both read_memory_bank_file and append_memory_bank_entry); not fixed on the default branch. Consider commenting on #7 with the reproduction instead of filing a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); evidence fired `check_path_traversal` ("Silent Bug Alert": input flagged, tool returned success). Also triggered for this tool: `check_reflected_output`.
- Campaigns and executions: corpus-sbx 2560 exec / 43 ok (60 s); repo24-b 286208 / 22742 and 265728 / 23555 (4200 s); e2-0922 1536 / 23 (60 s).
- Evidence (verbatim, trimmed): `{'file_name': '..\\..\\..\\..\\windows\\win.ini'}` -> `{"content": "\ntest\n\n[2026-09-16 13:46:39] - test\n\n[2026-09-16 13:46:39] - test\n\n[2026-09-16 13:46:41] - test\n[2026-09-16 13:46:50] - vest\n..."}`.
- Hand-check hints: real by code: `path.join(MEMORY_BANK_PATH, fileName)` then `fs.readFile`, no containment (`src/index.ts:170-172`). But the logged evidence is not itself an escape: on the Linux fuzzing host the backslash payload named a file inside `memory-bank/` that ToFu's own append calls had created (the returned content is those appended `test` entries). Confirm with the `../` payload above before filing. README config (`autoApprove` for all four tools) is quoted from `README.md`.
</details>
