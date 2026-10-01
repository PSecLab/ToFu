# Path traversal in `update_context`: `projectPath` appends to `activeContext.md` in any directory

**Repository:** `dazeb/cline-mcp-memory-bank` · **Tool:** `update_context` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`update_context` appends a session update to `<projectPath>/memory-bank/activeContext.md`. `projectPath` is used as given, with no check against the configured `PROJECT_PATH` or any other root. Absolute paths and `..` segments both work. A tool call can append caller-written text to the active-context file of any project on disk that has a memory bank. Agents load that file as their current working context.

## Details
`src/index.ts:675-688` (tested commit):

```ts
private async handleUpdateContext(args: any) {
  const { projectPath, content } = args;
  if (!projectPath || !content) {
    throw new McpError(ErrorCode.InvalidParams, 'Project path and content are required');
  }
  try {
    const filePath = path.join(projectPath, this.memoryBankPath, 'activeContext.md');
    const currentContent = await fs.readFile(filePath, 'utf8');
    const updatedContent = this.mergeContext(currentContent, content);
    await fs.writeFile(filePath, updatedContent, 'utf8');
```

`mergeContext` (lines 856-859) appends `currentSession.mode` and `currentSession.task` verbatim. The file name is fixed, so only existing `memory-bank/activeContext.md` files are reachable. The server's `PROJECT_PATH` (line 303) is not consulted.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and pnpm.
2. Install and build as the README describes: `git clone https://github.com/dazeb/cline-mcp-memory-bank && cd cline-mcp-memory-bank && pnpm install && pnpm run build`.
3. Create a stand-in project outside the working directory:

   ```sh
   mkdir -p /tmp/tofu-poc-project/memory-bank
   printf '# Active Context\n' > /tmp/tofu-poc-project/memory-bank/activeContext.md
   ```

   Then call the tool with:

   ```json
   {"projectPath": "../../../../../../../../tmp/tofu-poc-project",
    "content": {"currentSession": {"date": "2026-10-01", "mode": "tofu-poc", "task": "tofu-poc"}}}
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
               result = await session.call_tool("update_context", {
                   "projectPath": "../../../../../../../../tmp/tofu-poc-project",
                   "content": {"currentSession": {"date": "2026-10-01", "mode": "tofu-poc", "task": "tofu-poc"}}})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Active context updated successfully`, and a `## Session Update (...)` block with `Mode: tofu-poc` in `/tmp/tofu-poc-project/memory-bank/activeContext.md`.

## Expected behavior
`projectPath` must resolve inside the configured project root, or the call is rejected.

## Actual behavior
Any path whose `memory-bank/activeContext.md` exists is accepted. In the fuzzing run:

```
input:  {'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'content': {'currentSession': {'date': '2024-06-01', 'mode': 'review', 'task': 'read'}}}
output: Active context updated successfully
```

The backslash path is a literal directory name on the Linux test host. An earlier `initialize_memory_bank` call had created it in the working directory. The `/`-separated form above leaves the working directory.

## Impact
The LLM picks `projectPath` and the session text, and prompt injection can steer both. An attacker can append instructions to another project's active context. That file is meant to be read back by the agent at the start of a session, so it gives a persistent prompt-injection foothold. Writes are append-only and limited to existing `memory-bank/activeContext.md` files. Low to medium severity.

## Suggested fix
Use one containment helper for all four tools: resolve `projectPath` with `path.resolve` and `fs.realpath`, then reject it unless it equals `PROJECT_PATH` or starts with `PROJECT_PATH + path.sep`. Alternatively, ignore the argument and use `PROJECT_PATH`.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the current default branch head.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): reports the same unchecked `projectPath` reaching `fs.readFile`/`fs.writeFile` in `handleInitializeMemoryBank`, `handleUpdateContext`, `handleRecordDecision` and `handleTrackProgress` at the same commit `55c81b9`. Still open, and the default branch has no commit after 2025-07-17, so it is unfixed; this draft duplicates it.
- Documentation: README.md: the tool examples pass `projectPath: '/path/to/project'`, so absolute paths are the documented usage. No allowed root or warning is documented.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in #5 (open, unfixed at 55c81b9). File only as a comment on #5, or not at all.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, `check_invalid_json`.
- Campaigns and executions: corpus-sbx 2560 exec / 112 ok; repo24-b 353792 / 46771; e2-0922 1024 / 58.
- Evidence (verbatim, trimmed):
  - `{'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'content': {'currentSession': {'date': '2024-06-01', 'mode': 'review', 'task': 'read'}}}` -> `Active context updated successfully`
  - same with dates `1012-06-01`, `2924-06-01` -> same output
- Hand-check hints: real but low. Same unchecked `path.join(projectPath, ...)` pattern. Logged inputs stayed in cwd on Linux; escape from code reading; repro not run. File with the other memory-bank tools.
</details>
