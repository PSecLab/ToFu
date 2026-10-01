# Path traversal in `initialize_memory_bank`: `path` creates and overwrites memory bank files outside the project

**Repository:** `movibe/memory-bank-mcp` · **Tool:** `initialize_memory_bank` · **Tested commit:** `7851e06`
**Weakness:** CWE-22 Path Traversal

## Summary
`initialize_memory_bank` creates `<path>/memory-bank/` and writes the five core template files into it. The `path` argument is used as given: absolute paths and `../` segments are accepted, and nothing ties the result to the project directory the server was started with (`--path` or the working directory). Existing core files at the target are overwritten without a check, and the session's memory bank is re-pointed to the new location, so later `read_memory_bank_file` / `write_memory_bank_file` calls work there.

## Details
The handler resolves the argument against `process.cwd()` and passes it on unchanged (`src/server/tools/CoreTools.ts:186-194`):

```ts
const basePath = dirPath || memoryBankManager.getProjectPath();
const absolutePath = path.isAbsolute(basePath) ? basePath : path.resolve(process.cwd(), basePath);
...
await memoryBankManager.initializeMemoryBank(absolutePath);
```

`initializeMemoryBank` then creates the directory and writes the templates (`src/core/MemoryBankManager.ts:227-261`):

```ts
const memoryBankPath = path.join(dirPath, this.folderName);
await FileUtils.ensureDirectory(memoryBankPath);
...
for (const file of initialFiles) {
  await FileUtils.writeFile(file.path, file.content);
}
this.memoryBankDir = memoryBankPath;
```

`FileUtils.ensureDirectory` is `fs.ensureDir` (recursive) and `FileUtils.writeFile` is a plain `fs.writeFile` that replaces existing files (`src/utils/FileUtils.ts:17-19`, `68-70`). There is no comparison of the resolved path against the project root, and no "already exists" check before writing. The fallback branch at `CoreTools.ts:214-218` also uses `absolutePath` directly as the memory bank directory.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package for the client. Create a scratch layout and a marker file:
   ```bash
   mkdir -p /tmp/tofu-poc/project /tmp/tofu-poc/memory-bank
   echo marker > /tmp/tofu-poc/memory-bank/progress.md
   ```
2. Start the server as the README describes (`npx @movibe/memory-bank-mcp`; the tested commit is the 0.4.1 release commit). From a source checkout: `bun install && bun run build`, then `node build/index.js`. Run it with `/tmp/tofu-poc/project` as the working directory. On start it may create `.clinerules-*` files in that directory.
3. Call the tool with `{"path": ".."}`:

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
               result = await session.call_tool("initialize_memory_bank", {"path": ".."})
               print(result)

   asyncio.run(main())
   ```
4. Observe: `cat /tmp/tofu-poc/memory-bank/progress.md` no longer prints `marker`; it holds the progress template. `product-context.md`, `active-context.md`, `decision-log.md` and `system-patterns.md` now also exist in `/tmp/tofu-poc/memory-bank/`, outside the project directory.

## Expected behavior
The tool refuses a `path` that resolves outside the configured project directory, and it does not replace existing memory bank files without an explicit request.

## Actual behavior
The server creates `/tmp/tofu-poc/memory-bank/`, overwrites the marker `progress.md`, and reports `Memory Bank initialized at /tmp/tofu-poc/memory-bank`. During fuzzing the server tried to create directories at whatever the argument resolved to, for example (user name redacted):

```
Failed to create directory /home/<user>/etc/passwd/memory-bank: ENOENT: no such file or directory, mkdir '/home/<user>/etc'
```

That mkdir failed inside the fuzzing sandbox (ENOENT), but the path it attempted lies outside the server's working directory.

## Impact
In MCP the model picks tool arguments, and prompt injection in content the model reads can steer it. A steered call can create a `memory-bank/` directory in any directory the server user can write, and can replace the five core files of any other existing memory bank (another project's notes, progress and decision log) with the default templates. The written content is fixed template text, so this is data loss and re-pointing of the session, not arbitrary file content. Because the session's memory bank moves to the new location, follow-up `read_memory_bank_file` / `write_memory_bank_file` calls also operate there.

## Suggested fix
- Resolve `path` against the configured project path and reject it when `path.relative(projectRoot, resolved)` starts with `..` or is absolute.
- Before writing a template, skip files that already exist (for example `fs.writeFile(p, c, { flag: 'wx' })` and ignore `EEXIST`).
- Apply the same check in the `.clinerules` fallback branch in `CoreTools.ts`.

## Status on the default branch
Still present at `7851e06` (2025-03-17). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 9 pull requests (fetched 2026-10-01); none mentions path validation, traversal or overwriting existing memory bank files. #6 "feat: Enhance Memory Bank MCP with Environment Variables and Roo Code Integration" (PR, closed 2025-03-08) describes fallback initialization and error handling; it is not a fix, and the default branch has no containment check.
- Documentation: docs/memory-bank-path-changes.md: "Custom paths are supported for Memory Bank initialization through the `path` parameter" and "Absolute paths are used as-is." (choosing any directory is documented as intended; the docs do not mention that existing core files are overwritten).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` (only sanitizer that fired for this tool).
- Campaigns and executions: corpus-sbx 512 exec / 470 "success"; e2-0922 512 / 496. "Success" means the call returned without an MCP error; the tool returns failures as plain text without `isError`.
- Evidence (verbatim, trimmed):
  - `{'path': '../../../../etc/passwd'}` -> `Failed to initialize Memory Bank: Error: Failed to initialize Memory Bank: Error: Failed to create directory /home/mza6485/etc/passwd/memory-bank: ENOENT: no such file or directory, mkdir '/home/mza6485/etc'`
  - `{'path': '/var/run/../../root/.ssh/id_rsa'}` -> `... Failed to create directory /root/.ssh/id_rsa/memory-bank: EACCES: permission denied, mkdir '/root/.ssh/id_rsa/memory-bank'`
  - `{'path': '/etc/passwd\x00'}` -> rejected by Node for the NUL byte.
- Hand-check hints: weak. (npm version `0.4.1` matches `package.json` at the tested commit; I could not check the registry.) Taking a caller-chosen directory is the documented purpose of this tool, so "no containment" is a design choice the maintainer may defend. The concrete harm is (a) silent overwrite of existing core files in any `memory-bank/` folder and (b) directory creation outside `--path`. All three logged outputs are failed mkdirs (sandbox blocked them or NUL rejected); no successful out-of-root write is in the evidence. The reproduction is derived from code, not from a logged success. Not run.
</details>
