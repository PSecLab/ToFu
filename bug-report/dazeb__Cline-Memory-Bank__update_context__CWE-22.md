# Unrestricted `projectPath` in `update_context`: appends to `memory-bank/activeContext.md` in any directory

**Repository:** `dazeb/Cline-Memory-Bank` · **Tool:** `update_context` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`update_context` appends a session update to `<projectPath>/memory-bank/activeContext.md`. `projectPath` is used as given: relative paths resolve against the server's working directory, `..` segments are accepted, and nothing limits it to the configured project (`PROJECT_PATH`). Any existing `memory-bank/activeContext.md` the user can write can be modified. The file name is fixed, so the reach is limited to files with that name.

## Details
`src/index.ts:675-688` at `55c81b9`:

```ts
  private async handleUpdateContext(args: any) {
    const { projectPath, content } = args;
    if (!projectPath || !content) { ... }
    try {
      const filePath = path.join(projectPath, this.memoryBankPath, 'activeContext.md');
      const currentContent = await fs.readFile(filePath, 'utf8');
      const updatedContent = this.mergeContext(currentContent, content);
      await fs.writeFile(filePath, updatedContent, 'utf8');
```

`mergeContext` (`src/index.ts:856-859`) appends `content.currentSession.mode` and `content.currentSession.task` as Markdown. There is no `path.resolve` plus prefix check against `PROJECT_PATH` or any other root, although the resource handler (`src/index.ts:302-316`) already reads from `PROJECT_PATH`.

## Steps to reproduce
1. Prerequisites: Node.js 16 or later. No accounts or keys. Create a working directory for the server and a marker file one level above it:
   ```
   mkdir -p /tmp/tofu-poc/root /tmp/tofu-poc/memory-bank
   echo marker > /tmp/tofu-poc/memory-bank/activeContext.md
   ```
2. Install the server:
   ```
   git clone https://github.com/dazeb/Cline-Memory-Bank.git
   cd Cline-Memory-Bank && git checkout 55c81b9cf6c16700983c84dc4cdea3cafa19a75f
   npm install && npm run build
   ```
3. Start it with working directory `/tmp/tofu-poc/root` and call the tool with a relative path that leaves that directory:
   ```json
   {"projectPath": "../", "content": {"currentSession": {"date": "2025-01-01", "mode": "tofu-poc", "task": "tofu-poc"}}}
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
               result = await session.call_tool("update_context", {
                   "projectPath": "../",
                   "content": {"currentSession": {"date": "2025-01-01",
                                                  "mode": "tofu-poc", "task": "tofu-poc"}}})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is `Active context updated successfully`, and `/tmp/tofu-poc/memory-bank/activeContext.md`, outside the server's working directory, now ends with `## Session Update (<today>)`, `- Mode: tofu-poc` and `- Task: tofu-poc` after the `marker` line.

## Expected behavior
The tool should resolve `projectPath` and refuse it unless it is the configured project (`PROJECT_PATH`) or inside an allow-listed root.

## Actual behavior
The write goes to whatever directory the argument names. All logged calls returned success:

```
Active context updated successfully
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. An attacker can add arbitrary Markdown to the active context of any other project on the machine that has a memory bank. That file is read back as assistant context at the start of later sessions, so injected instructions can persist. The file name is fixed and must already exist, so this cannot write arbitrary files. Severity is low.

## Suggested fix
Resolve `projectPath` with `path.resolve` and reject it unless it equals, or is inside, `process.env.PROJECT_PATH` (or a list of allowed roots). Better, drop the per-call `projectPath` and use `PROJECT_PATH`, as the resource handler does. Apply the same check in the other three tools.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): same bug at the same commit `55c81b9`. It names `handleUpdateContext`, `handleRecordDecision` and `handleTrackProgress` and the unchecked `path.join(projectPath, this.memoryBankPath, ...)` before `readFile`/`writeFile`. Still open; the code is unchanged on the default branch.
- Documentation: README.md shows `projectPath: '/path/to/project'` as a free caller argument; it has no allowed-root setting and no warning about untrusted paths.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: duplicate of open issue #5 (2026-04-27), which names this handler at the same commit. Not fixed. Do not file separately.
- ToFu class / sanitizers: path-traversal via `check_path_traversal`. `check_invalid_json` also fired for this tool.
- Campaigns and executions: corpus-sbx 2,560 exec / 136 ok (60 s); e2-0922 1,024 exec / 28 ok (60 s).
- Evidence (verbatim, trimmed): `{'projectPath': '..\\..\\..\\..\\windows\\win.ini', 'content': {'currentSession': {'date': '2024-06-01', 'mode': 'review', 'task': 'read'}}}` -> `{'content': [{'type': 'text', 'text': 'Active context updated successfully'}]}`. Two more inputs of the same shape gave the same output.
- Hand-check hints: weak. On the Linux fuzzing hosts the logged `projectPath` is one literal directory name under the server's cwd, not a traversal. The call succeeded because an earlier fuzzed `initialize_memory_bank` call had created `activeContext.md` inside that directory. The `../` reproduction is derived from the code, not from a logged run. The missing check against `PROJECT_PATH` is real, but the file name is fixed and the file must exist. `date` is required by the schema but `mergeContext` ignores it and uses today's date.
</details>
