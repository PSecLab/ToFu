# Path traversal in `set_memory_bank_path`: `path` is not confined to the project directory

**Repository:** `aakarsh-sasi/memory-bank-mcp` · **Tool:** `set_memory_bank_path` · **Tested commit:** `0813435`
**Weakness:** CWE-22 Path Traversal

## Summary
`set_memory_bank_path` points the server at an existing `memory-bank/` folder under the caller's `path`. The path is resolved but never checked against the project directory, so the tool accepts `../` and absolute paths anywhere. At this commit the lookup goes through `LocalFileSystem`, which appends the absolute path to the project path, so in the default setup a path outside the project is usually not found. When the server's project path is `/`, the tool can re-point the memory bank at any existing memory bank on the host, and the read and write tools then operate there. The tool's reply also reports a stale directory when the lookup fails.

## Details
`src/server/tools/CoreTools.ts:136-172` (tested commit):

```ts
const basePath = customPath || memoryBankManager.getProjectPath();
const absolutePath = path.isAbsolute(basePath) ? basePath : path.resolve(process.cwd(), basePath);
await memoryBankManager.setCustomPath(absolutePath);
const memoryBankDir = memoryBankManager.getMemoryBankDir();
if (memoryBankDir) {
  return { content: [{ type: 'text', text: `Memory Bank path set to ${memoryBankDir}` }] };
}
```

`setCustomPath` (`src/core/MemoryBankManager.ts:578-598`) calls `findMemoryBankDir`, which checks `path.join(startDir, 'memory-bank')` through `this.fileSystem` and, if it holds `.md` files, calls `setMemoryBankDir(mbDir)`. `LocalFileSystem.getFullPath` (`src/utils/storage/LocalFileSystem.ts:28-30`) is `path.join(baseDir, p)`. With `baseDir` `/` (server started from `/` without `--path`, or with `--path /`) the join is a no-op and any absolute path is used as is. After that, `write_memory_bank_file` writes `path.join(memoryBankDir, filename)` (`MemoryBankManager.ts:461-462`), and the progress tools write via `FileUtils` on the same directory.

If the lookup fails, `memoryBankDir` keeps its previous value and the reply still says "Memory Bank path set to <old dir>", which misreports what happened.

## Steps to reproduce
1. Prerequisites: Node.js 18+. Create a memory bank outside any project: `mkdir -p /tmp/tofu-other/memory-bank && printf '# Progress\n' > /tmp/tofu-other/memory-bank/progress.md`.
2. Start the server with project path `/` (equivalent to launching it from `/` without `--path`): `npx @aakarsh-sasi/memory-bank-mcp --path /`.
3. Call `set_memory_bank_path`, then write a file:

   ```json
   {"path": "/tmp/tofu-other"}
   ```
   ```json
   {"filename": "tofu-poc.md", "content": "FAKE-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx",
           args=["-y", "@aakarsh-sasi/memory-bank-mcp", "--path", "/"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("set_memory_bank_path", {"path": "/tmp/tofu-other"}))
               print(await session.call_tool("write_memory_bank_file",
                   {"filename": "tofu-poc.md", "content": "FAKE-ENTRY"}))

   asyncio.run(main())
   ```
4. Observe the reply `Memory Bank path set to /tmp/tofu-other/memory-bank` and the new file `/tmp/tofu-other/memory-bank/tofu-poc.md`. Repeat with `--path /tmp/tofu-proj` (an empty project dir): the lookup fails and the reply shows whatever directory was set before.

## Expected behavior
The tool rejects any `path` whose resolved real path is outside the configured project directory, and reports an error (not a stale directory) when no memory bank is found.

## Actual behavior
Any path is accepted. From the fuzzing run:

```
{'path': '../../../../etc/passwd'}  ->  Memory Bank path set to /home/mza6485/etc/passwd/memory-bank
{'path': '/etc/passwd\x00'}         ->  Memory Bank path set to /dev/null/memory-bank
```

The second reply does not match the input, which shows the reported directory is left over from earlier calls in the same session, not the result of this call.

## Impact
The LLM chooses `path`, and prompt injection can steer it. With project path `/`, an attacker can switch the session to another project's memory bank and read or modify its files through the normal memory-bank tools. In the default setup the lookup is contained by the base-path join, and the main effect is a misleading reply. Low.

## Suggested fix
Resolve `path` with `fs.realpathSync` and reject it unless it equals the project root or starts with `projectRoot + path.sep`. Return an error when `findMemoryBankDir` finds nothing instead of echoing the previous `memoryBankDir`. Fix `LocalFileSystem.getFullPath` so absolute inputs are handled consistently with the containment check.

## Status on the default branch
Still present at `0813435` (2025-06-25). The tested commit is the current default branch head.

## Prior reports
- #2 "fix(core): resolve nested directory creation with absolute paths" (PR, open 2026-02-06): fixes the double join in `LocalFileSystem` operations (absolute memory-bank path appended to the project path), which is what currently keeps the memory-bank lookup under the project path. It adds no containment check, so it does not fix this, and merging it could make the escape more direct; check it against this report before merging.
- Documentation: docs/memory-bank-path-changes.md: "Absolute paths are used as-is." (custom paths through the `path` parameter are a documented feature, with examples such as `set_memory_bank_path path=/path/to/custom/memory-bank`; no limit to the project is documented)
- Documentation: README.md: "the Memory Bank will be created or accessed at `<project_path>/memory-bank`" (describes the `--path` project directory; it does not say the tool `path` may leave it)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` only.
- Campaigns and executions: corpus-sbx 1536 exec / 1536 ok; e2-0922 1024 exec / 1024 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'path': '/etc/passwd\x00'}` -> `Memory Bank path set to /dev/null/memory-bank`
  - `{'path': '../../../../etc/passwd'}` -> `Memory Bank path set to /home/mza6485/etc/passwd/memory-bank`
  - `{'path': '["../../../../etc/passwd"]'}` -> `Memory Bank path set to /home/mza6485/etc/passwd/memory-bank`
- Hand-check hints: weak. The evidence replies are stale `memoryBankDir` values from earlier calls (the `/dev/null` reply for a `/etc/passwd\x00` input proves it), so the run does not show this tool reaching any file outside the cwd. Per source, the lookup is joined under the project path and fails for outside paths unless the project path is `/`. Missing containment is real; the impact in the default configuration is small. Repro not run. Consider merging with the `initialize_memory_bank` report.
</details>
