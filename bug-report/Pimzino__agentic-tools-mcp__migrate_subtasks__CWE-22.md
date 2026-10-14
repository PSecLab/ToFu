# Path traversal in `migrate_subtasks`: relative `workingDirectory` such as `../` creates task storage outside the server's directory

**Repository:** `Pimzino/agentic-tools-mcp` · **Tool:** `migrate_subtasks` · **Tested commit:** `a32e209`
**Weakness:** CWE-22 Path Traversal

## Summary
`migrate_subtasks` opens the task store under `<workingDirectory>/.agentic-tools-mcp/tasks/tasks.json` and converts old subtasks. The parameter description says the path "MUST be an absolute path" and lists `..` as forbidden, but the server never checks this. A relative value such as `../` resolves against the server process's current directory, and the tool creates the `.agentic-tools-mcp/tasks/` directory and an empty `tasks.json` there. The server also has no option to restrict which directories may be used.

## Details
The tool passes the argument straight to storage (`src/server.ts:376-384`):

```ts
server.tool(
  'migrate_subtasks',
  '...',
  {
    workingDirectory: z.string().describe(getWorkingDirectoryDescription(config))
  },
  async ({ workingDirectory }: { workingDirectory: string }) => {
    try {
      const storage = await createStorage(workingDirectory, config);
```

`resolveWorkingDirectory` returns the value unchanged unless `--claude` is set (`src/utils/storage-config.ts:41-47`). `FileStorage` joins it with a fixed subpath and, on `initialize()`, creates the directory and writes `tasks.json` when it is missing or not valid JSON (`src/features/task-management/storage/file-storage.ts:21-22`, `:36-75`):

```ts
this.storageDir = join(workingDirectory, '.agentic-tools-mcp', 'tasks');
this.dataFile = join(this.storageDir, 'tasks.json');
...
await fs.mkdir(this.storageDir, { recursive: true });
const fileContent = await fs.readFile(this.dataFile, 'utf-8');
...
} catch (error) {
  // File doesn't exist or is invalid, start with empty data
  await this.save();
}
```

The only check is `fs.access(workingDirectory)` (`file-storage.ts:39`). There is no `path.isAbsolute` test, no rejection of `..`, and no allowed-root comparison. The same `createStorage` path is used by the other task tools in `src/server.ts`.

## Steps to reproduce
1. Prerequisites: Node.js and npm, and the `mcp` Python package for the client script. Create a directory to act as the server's working directory:

   ```bash
   mkdir -p /tmp/tofu-poc/root
   ```
2. Install and build from a checkout (the README's `npx -y @pimzino/agentic-tools-mcp` runs the published package; to test this commit, build it):

   ```bash
   git clone https://github.com/Pimzino/agentic-tools-mcp && cd agentic-tools-mcp
   git checkout a32e209
   npm install && npm run build
   ```
3. Start the server with its working directory set to `/tmp/tofu-poc/root` and call the tool with `../`:

   ```json
   {"workingDirectory": "../"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/agentic-tools-mcp/dist/index.js"], cwd="/tmp/tofu-poc/root")
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("migrate_subtasks", {"workingDirectory": "../"})
               print(result)

   asyncio.run(main())
   ```
4. Run `ls -la /tmp/tofu-poc/.agentic-tools-mcp/tasks/`. It now contains `tasks.json`, created one level above the server's working directory.

## Expected behavior
Relative paths and `..` segments are rejected, as the parameter description promises, and optionally paths outside an operator-configured root are refused.

## Actual behavior
The call succeeds and the store is created at the resolved location. Output from our run for `{'workingDirectory': '../'}` (also for `'..//'` and `'../.'`):

```
✅ **Migration Status: Complete**

No migration needed! Your task management system is already using the unified task model.
...
• Version: 1.8.1
• Subtasks remaining: 0
```

## Impact
The LLM picks `workingDirectory`, and prompt injection from untrusted content can steer it. Because the server enforces neither "absolute only" nor a root, a steered call can create `.agentic-tools-mcp/tasks/tasks.json` in any directory the server user can write, read task data stored in other directories, or replace a `tasks.json` there that fails to parse with an empty one. File names and content are fixed by the server, so this does not give arbitrary file write. Relative paths also make the location depend on the host's process directory, which users do not control. Severity is low.

## Suggested fix
In `createStorage` (and `createMemoryStorage`), reject values for which `path.isAbsolute()` is false or that contain `..` segments, then `path.resolve` the value. Optionally add a setting (CLI flag or env var) listing allowed roots and refuse resolved paths outside them, after resolving symlinks with `fs.realpath`.

## Status on the default branch
The tested commit `a32e209` (2025-06-20) is the current head of the default branch, so the code above is unchanged.

## Prior reports
- #2 "Fix --claude flag implementation: Make workingDirectory optional when using global directory mode" (PR, merged/closed 2025-06-04): reworked `resolveWorkingDirectory()` and the parameter descriptions ("Full path requirements"). The validation it added only handles a missing `workingDirectory`; it does not reject relative paths or `..`. Not a report of this bug and not a fix.
- No other related issue or PR among the 3 issues and 6 pull requests (fetched 2026-10-01).
- Documentation: `README.md`: "All tools require a `workingDirectory` parameter to specify where the data should be stored" (the caller choosing the location is by design) and "Use absolute paths for reliability" (advice only, not enforced). The README also documents that with `--claude` "the `workingDirectory` parameter in all tools is ignored and the global directory is used instead", which is the only built-in way to stop callers choosing the directory. No SECURITY.md.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; only `check_path_traversal` fired, as an input-pattern "Silent Bug Alert" (input flagged, tool did not raise).
- Campaigns and executions: `repo24-b` 274944 exec / 9312 ok and 261632 / 9279 (4200 s each), `e2-0922` 2048 / 30 (300 s).
- Evidence (verbatim, trimmed): inputs `{'workingDirectory': '..//'}`, `{'workingDirectory': '../.'}`, `{'workingDirectory': '../'}` all returned the "Migration Status: Complete ... Version: 1.8.1, Subtasks remaining: 0" text.
- Hand-check hints: weak. `workingDirectory` is caller-chosen by design, so there is no fixed root to escape; the real gap is that the documented "absolute path only, no `..`" rule is not enforced. The evidence shows success, not where the file landed; that `tasks.json` was created one level up is derived from `file-storage.ts:36-75`. The reproduction was not executed here; `cwd` on `StdioServerParameters` needs a recent `mcp` Python SDK. The same pattern applies to every tool that takes `workingDirectory` (tasks and memories), so one issue for the whole server fits better.
</details>
