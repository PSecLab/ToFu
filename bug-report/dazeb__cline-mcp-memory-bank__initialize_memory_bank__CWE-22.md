# Path traversal in `initialize_memory_bank`: `projectPath` writes files in any directory and rewrites Cline's MCP settings

**Repository:** `dazeb/cline-mcp-memory-bank` · **Tool:** `initialize_memory_bank` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`initialize_memory_bank` creates `<projectPath>/memory-bank/` and writes four Markdown files there. It also reads `<projectPath>/package.json`, lists `<projectPath>` recursively, and rewrites Cline's `cline_mcp_settings.json` so the `memory-bank` server entry runs `node <projectPath>/build/index.js`. `projectPath` is used exactly as the caller gives it. Absolute paths and `..` segments are accepted, and there is no allowed root, even though the server already reads a `PROJECT_PATH` setting for its resources. A tool call can therefore create or overwrite memory-bank files in any directory the user can write, and repoint the user's Cline configuration at a script in that directory.

## Details
`src/index.ts:546-559` (tested commit):

```ts
public async handleInitializeMemoryBank(args: any) {
  const projectPath = args.projectPath;
  if (!projectPath) {
    throw new McpError(ErrorCode.InvalidParams, 'Project path is required');
  }
  // Convert to absolute path if not already
  const absoluteProjectPath = path.isAbsolute(projectPath)
    ? projectPath
    : path.resolve(process.cwd(), projectPath);
  try {
    const memoryBankPath = path.join(projectPath, this.memoryBankPath);
    await fs.mkdir(memoryBankPath, { recursive: true });
```

The four files are then written with `fs.writeFile(path.join(memoryBankPath, file.path), ...)` at lines 648-654, which overwrites existing files of the same name. `detectTechStack` runs `fs.readdir(projectPath, { recursive: true })` at line 407. Line 657 calls `updateMcpSettings(absoluteProjectPath)`, which writes this entry into `~/<platform path>/cline_mcp_settings.json` (lines 768-786):

```ts
settings.mcpServers['memory-bank'] = {
  command: 'node',
  args: [path.join(projectPath, 'build', 'index.js')],
  env: { PROJECT_PATH: projectPath },
  disabled: false,
  autoApprove: []
};
```

Nothing checks that `projectPath` is the intended project, stays under `PROJECT_PATH`, or is a sensible directory at all.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and pnpm. Run the server with `HOME` pointed at a scratch directory so the real Cline settings file is not touched.
2. Install and build as the README describes: `git clone https://github.com/dazeb/cline-mcp-memory-bank && cd cline-mcp-memory-bank && pnpm install && pnpm run build`.
3. Create the scratch home with `mkdir -p /tmp/tofu-home`. Then call the tool with a `..` path that leaves the working directory:

   ```json
   {"projectPath": "../../../../../../../../tmp/tofu-poc-project"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"],
                                      env={"HOME": "/tmp/tofu-home", "PATH": os.environ["PATH"]})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("initialize_memory_bank", {"projectPath": "../../../../../../../../tmp/tofu-poc-project"})
               print(result)

   asyncio.run(main())
   ```
4. Observe:
   - `/tmp/tofu-poc-project/memory-bank/` now holds `projectContext.md`, `activeContext.md`, `progress.md` and `decisionLog.md`.
   - The settings file under `/tmp/tofu-home` (`.config/Code - Insiders/...` on Linux, `Library/Application Support/Code - Insiders/...` on macOS) has a `memory-bank` entry with `"args": ["/tmp/tofu-poc-project/build/index.js"]`.
   - An absolute path such as `/tmp/tofu-poc-project` behaves the same way.

## Expected behavior
`projectPath` resolves to a directory under the configured project root (`PROJECT_PATH`), or the call is rejected. A tool call does not rewrite the client's MCP settings with a path chosen by the caller.

## Actual behavior
Any path is accepted, and the tool reports success. In the fuzzing run:

```
input:  {'projectPath': '..\\..\\..\\..\\windows\\win.ini'}
output: Memory Bank initialized successfully and MCP settings configured
```

The fuzzer used Windows separators. On the Linux test host those are ordinary filename characters, so that call created an oddly named directory inside the working directory. The same code path takes `/`-separated `..` or absolute paths outside it, as in the steps above.

## Impact
The LLM picks `projectPath`, and prompt injection can steer it, for example through a README or issue text the agent reads. An attacker can then:
- overwrite the memory-bank files of another project the user has on disk;
- create `memory-bank/` directories anywhere the user can write;
- replace the user's `memory-bank` entry in Cline's settings with `node <chosen dir>/build/index.js`. If that directory holds a `build/index.js` (a cloned untrusted repository, or a shared directory such as `/tmp`), Cline would start that script the next time it loads its MCP servers. The tool cannot write `build/index.js` itself, so this needs a second foothold. We did not test it end to end with Cline.
- make the server walk a very large tree (for example `/`) with the recursive `readdir`, which can stall it.

Medium severity.

## Suggested fix
- Resolve the path with `path.resolve` and `fs.realpath`. When `PROJECT_PATH` is set, reject the call unless the result equals that root or starts with `root + path.sep`. Otherwise require an existing directory and refuse `/` and the home directory.
- Do not call `updateMcpSettings` from the MCP tool handler. Keep it in the `initialize_memory_bank` CLI command, where the user runs it on purpose.
- Point the settings entry at this server's own entry file (derived from `import.meta.url`), not at `<projectPath>/build/index.js`.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the current default branch head.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): reports the same unchecked `projectPath` in `handleInitializeMemoryBank`, `handleUpdateContext`, `handleRecordDecision`, `handleTrackProgress` and `detectTechStack` at the same commit `55c81b9`. It does not mention the `cline_mcp_settings.json` rewrite. Still open, and the default branch has no commit after 2025-07-17, so it is unfixed; this draft would duplicate it apart from the settings angle.
- #3 "initialize_memory_bank failed" (issue, closed 2025-04-04): a user's tool call failed with `Failed to update MCP settings: Could not determine user home directory`, which shows the MCP tool handler rewriting the Cline settings file. Not a security report.
- Documentation: README.md: "This automatically creates the memory bank files and configures the Cline MCP settings for you" (said of the CLI command; the README then says Cline can run the same tool). The tool examples pass `projectPath: '/path/to/project'`, so absolute paths are the documented usage. No allowed root or warning is documented.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: path traversal already reported in #5 (open, unfixed at 55c81b9). The Cline settings rewrite is not in #5; add it as a comment on #5 instead of a new issue.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal`, also `check_resource_exhaustion` for this tool.
- Campaigns and executions: corpus-sbx 2048 exec / 1083 ok; repo24-b 114688 / 56480 and 134656 / 58177; e2-0922 1024 / 516 (60 s and 4200 s budgets).
- Evidence (verbatim, trimmed):
  - `{'projectPath': '..\\..\\..\\..\\windows\\win.ini'}` -> `Memory Bank initialized successfully and MCP settings configured`
  - `{'projectPath': '"projectPath": "../../@./tmp/'}` -> same
  - `{'projectPath': '"projectPath": ["/etc/passwd", "/tmp"'}` -> same
- Hand-check hints: real. `projectPath` reaches `fs.mkdir`/`fs.writeFile`/`fs.readdir` with no containment, and the handler rewrites the Cline settings file. Caveat: none of the three evidence inputs left the cwd on Linux (backslashes are literal; the two `/` inputs normalize to paths inside cwd). The escape rests on code reading, not on the logged calls. I did not run the repro. `os.homedir()` honours `$HOME` on POSIX, which is why the repro overrides it. The Cline auto-launch consequence is inferred from what the settings file is for and was not tested. The tool's design takes an arbitrary project path, so the maintainer may call this by design; the settings rewrite is the strongest part of the report.
</details>
