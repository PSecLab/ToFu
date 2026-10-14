# Path traversal in `initialize_memory_bank`: `path` is not confined to the project, and later writes follow it

**Repository:** `aakarsh-sasi/memory-bank-mcp` · **Tool:** `initialize_memory_bank` · **Tested commit:** `0813435`
**Weakness:** CWE-22 Path Traversal

## Summary
`initialize_memory_bank` creates a `memory-bank/` folder with template Markdown files at the caller's `path`. The path is resolved but never checked against the project directory. At this commit the template files go through `LocalFileSystem`, which joins the absolute path under the project path, so in the default setup they land in `<project>/<path>/memory-bank` while the reply reports `<path>/memory-bank`. Two routes bypass that accidental join: when the project path is `/`, files are created at the caller's absolute path, and the progress tools (`track_progress`, `update_active_context`, `log_decision`) read and rewrite files at the raw, unjoined path.

## Details
`src/server/tools/CoreTools.ts:186-206` (tested commit):

```ts
const basePath = dirPath || memoryBankManager.getProjectPath();
const absolutePath = path.isAbsolute(basePath) ? basePath : path.resolve(process.cwd(), basePath);
await memoryBankManager.setCustomPath(absolutePath);
await memoryBankManager.initialize(true);
const memoryBankDir = memoryBankManager.getMemoryBankDir();
return { content: [{ type: 'text', text: `Memory Bank initialized at ${memoryBankDir}` }] };
```

`src/core/MemoryBankManager.ts:328-395` sets `memoryBankPath = path.join(this.customPath, 'memory-bank')`, creates it with `this.fileSystem.ensureDirectory(...)` and `writeFile(...)`, and then calls `setMemoryBankDir(memoryBankPath)`. `LocalFileSystem.getFullPath` (`src/utils/storage/LocalFileSystem.ts:28-30`) is `path.join(this.baseDir, relativePath)`, so an absolute `memoryBankPath` is appended to the project path rather than escaping it.

`setMemoryBankDir` also creates a `ProgressTracker` on the raw `memoryBankPath`. `ProgressTracker` uses `FileUtils` directly (`src/core/ProgressTracker.ts:155-178`):

```ts
const progressPath = path.join(this.memoryBankDir, 'progress.md');
let progressContent = await FileUtils.readFile(progressPath);
...
await FileUtils.writeFile(progressPath, progressContent);
```

So after `initialize_memory_bank` with `path: "/some/other/project"`, `track_progress` rewrites `/some/other/project/memory-bank/progress.md` and `active-context.md` if they exist, outside the configured project.

## Steps to reproduce
1. Prerequisites: Node.js 18+. Prepare a second, unrelated memory bank: `mkdir -p /tmp/tofu-other/memory-bank && printf '# Progress\n\n## Update History\n' > /tmp/tofu-other/memory-bank/progress.md && printf '# Active Context\n' > /tmp/tofu-other/memory-bank/active-context.md`, and a project dir `mkdir -p /tmp/tofu-proj`.
2. Start the server as the README describes, with the project path: `npx @aakarsh-sasi/memory-bank-mcp --path /tmp/tofu-proj`.
3. Call `initialize_memory_bank`, then `track_progress`:

   ```json
   {"path": "/tmp/tofu-other"}
   ```
   ```json
   {"action": "FAKE-ENTRY", "description": "written outside the project"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx",
           args=["-y", "@aakarsh-sasi/memory-bank-mcp", "--path", "/tmp/tofu-proj"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("initialize_memory_bank", {"path": "/tmp/tofu-other"}))
               print(await session.call_tool("track_progress",
                   {"action": "FAKE-ENTRY", "description": "written outside the project"}))

   asyncio.run(main())
   ```
4. Observe: `/tmp/tofu-other/memory-bank/progress.md` now contains a `FAKE-ENTRY` line, although the project is `/tmp/tofu-proj`. The template files from step 3 are in `/tmp/tofu-proj/tmp/tofu-other/memory-bank/`, while the reply says `Memory Bank initialized at /tmp/tofu-other/memory-bank`. If the server instead runs with working directory `/` and no `--path`, `initialize_memory_bank` itself creates `<path>/memory-bank/*.md` at any writable location.

## Expected behavior
`path` is resolved (`fs.realpath`) and rejected unless it is the project path or inside it. All file access then uses one consistent, contained base.

## Actual behavior
Any path is accepted. From the fuzzing run:

```
{'path': '/tmp/../tmp/./../etc/shadow'}  ->  Memory Bank initialized at /etc/shadow/memory-bank
{'path': '../../../../etc/passwd'}       ->  Memory Bank initialized at /home/mza6485/etc/passwd/memory-bank
```

The reported locations are the logical paths. Per the code, the template files were created under the server's working directory (`<cwd>/etc/shadow/memory-bank`), not in `/etc`.

## Impact
The LLM chooses `path`, and prompt injection in content the agent reads can steer it. An attacker can redirect the memory bank to another project's memory bank and have the progress tools append or rewrite its `progress.md`, `active-context.md` and `decision-log.md`, or create directories and template files at arbitrary locations when the server runs with project path `/`. Existing files are not overwritten by the templates (they are only written if missing). Low to medium.

## Suggested fix
- In `handleInitializeMemoryBank` and `handleSetMemoryBankPath`, resolve the path and reject it unless `resolved === projectRoot || resolved.startsWith(projectRoot + path.sep)` (after `realpath`).
- Make `ProgressTracker` use the same `FileSystemInterface` as `MemoryBankManager` instead of `FileUtils`, and fix `LocalFileSystem.getFullPath` to treat absolute inputs consistently (for example `path.resolve(base, p)` plus the containment check), so the reported and actual locations match.

## Status on the default branch
Still present at `0813435` (2025-06-25). The tested commit is the current default branch head.

## Prior reports
- #2 "fix(core): resolve nested directory creation with absolute paths" (PR, open 2026-02-06): fixes the double join in `LocalFileSystem` operations (absolute memory-bank path appended to the project path), which is what currently keeps the template files under the project path. It adds no containment check, so it does not fix this, and merging it could make the escape more direct; check it against this report before merging.
- Documentation: docs/memory-bank-path-changes.md: "Absolute paths are used as-is." (custom paths through the `path` parameter are a documented feature, with examples such as `initialize_memory_bank path=/path/to/custom/memory-bank`; no limit to the project is documented)
- Documentation: README.md: "the Memory Bank will be created or accessed at `<project_path>/memory-bank`" (describes the `--path` project directory; it does not say the tool `path` may leave it)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, also `check_reflected_output` on this tool.
- Campaigns and executions: corpus-sbx 1024 exec / 902 ok; e2-0922 512 exec / 498 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'path': '/etc/passwd\x00'}` -> `Failed to initialize Memory Bank: ... Failed to create directory /home/mza6485/toolfuzzer/eval/targets/aakarsh-sasi__memory-bank-mcp/etc/passwd\x00/memory-bank: ... without null bytes ...`
  - `{'path': '../../../../etc/passwd'}` -> `Memory Bank initialized at /home/mza6485/etc/passwd/memory-bank`
  - `{'path': '/tmp/../tmp/./../etc/shadow'}` -> `Memory Bank initialized at /etc/shadow/memory-bank`
- Hand-check hints: real, but not in the way the evidence suggests. The NUL-byte error proves the base-path join (`<cwd>/etc/passwd\x00/memory-bank`), so the fuzzed writes stayed under the server cwd and the "initialized at /etc/shadow" text is the logical path only. The real escapes are (a) `ProgressTracker` using `FileUtils` on the raw path, needing pre-existing files, and (b) project path `/`. Both are from source reading; the repro was not run. I did not confirm what working directory common MCP clients use. The same double-join also means normal use writes to `<project>/<project>/memory-bank`, which looks like a functional bug worth mentioning.
</details>
