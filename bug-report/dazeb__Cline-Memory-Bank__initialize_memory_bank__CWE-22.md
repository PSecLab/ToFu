# Unrestricted `projectPath` in `initialize_memory_bank`: writes into any directory and points the Cline `memory-bank` entry at `<projectPath>/build/index.js`

**Repository:** `dazeb/Cline-Memory-Bank` · **Tool:** `initialize_memory_bank` · **Tested commit:** `55c81b9`
**Weakness:** CWE-22 Path Traversal

## Summary
`initialize_memory_bank` creates a `memory-bank/` folder with four Markdown files under the caller's `projectPath`. The path is not checked at all: relative paths resolve against the server's working directory, `..` segments are accepted, and there is no allowed root. Existing memory bank files at the target are overwritten without warning. The tool then rewrites the user's Cline MCP settings so that the `memory-bank` server runs `node <projectPath>/build/index.js`, which means the same unchecked argument decides what script Cline launches next time.

## Details
`src/index.ts:546-559` at `55c81b9`:

```ts
  public async handleInitializeMemoryBank(args: any) {
    const projectPath = args.projectPath;
    ...
    const absoluteProjectPath = path.isAbsolute(projectPath)
      ? projectPath
      : path.resolve(process.cwd(), projectPath);
    try {
      const memoryBankPath = path.join(projectPath, this.memoryBankPath);
      await fs.mkdir(memoryBankPath, { recursive: true });
```

`src/index.ts:648-654` then writes `projectContext.md`, `activeContext.md`, `progress.md` and `decisionLog.md` into that folder with `fs.writeFile`, replacing whatever is there. Before that, `getProjectInfo` reads `<projectPath>/package.json` (`src/index.ts:335-338`) and `detectTechStack` runs `fs.readdir(projectPath, { recursive: true })` (`src/index.ts:407`).

`updateMcpSettings` (`src/index.ts:768-785`) writes the Cline settings file under `os.homedir()`:

```ts
      settings.mcpServers['memory-bank'] = {
        command: 'node',
        args: [path.join(projectPath, 'build', 'index.js')],
        env: { PROJECT_PATH: projectPath },
        disabled: false,
        autoApprove: []
      };
```

There is no check that `projectPath` is a project the user meant, that it stays inside a workspace, or that `build/index.js` there is this server.

## Steps to reproduce
1. Prerequisites: Node.js 16 or later. No accounts or keys. Create scratch directories and a marker file. `HOME` is pointed at a scratch folder so the settings write lands there and not in your real VS Code profile:
   ```
   mkdir -p /tmp/tofu-poc/root /tmp/tofu-poc/home
   echo '{"name": "tofu-poc-marker"}' > /tmp/tofu-poc/package.json
   ```
2. Install the server:
   ```
   git clone https://github.com/dazeb/Cline-Memory-Bank.git
   cd Cline-Memory-Bank && git checkout 55c81b9cf6c16700983c84dc4cdea3cafa19a75f
   npm install && npm run build
   ```
3. Start it with working directory `/tmp/tofu-poc/root` and call the tool with a relative path that leaves that directory:
   ```json
   {"projectPath": "../"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   SERVER = os.path.abspath("build/index.js")  # run from the Cline-Memory-Bank checkout

   async def main():
       server = StdioServerParameters(
           command="node", args=[SERVER], cwd="/tmp/tofu-poc/root",
           env={**os.environ, "HOME": "/tmp/tofu-poc/home"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("initialize_memory_bank", {"projectPath": "../"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe:
   - `/tmp/tofu-poc/memory-bank/` now exists, outside the server's working directory, with the four Markdown files.
   - `/tmp/tofu-poc/memory-bank/projectContext.md` starts its overview with `tofu-poc-marker`, read from the marker `package.json`.
   - `find /tmp/tofu-poc/home -name cline_mcp_settings.json -exec cat {} \;` shows the `memory-bank` entry with `"args": ["/tmp/tofu-poc/build/index.js"]` (on macOS the path starts with `/private/tmp`).

## Expected behavior
The tool should only initialize a memory bank inside a directory the user configured (for example `PROJECT_PATH` or an allow-listed workspace root), refuse paths that resolve outside it, and not overwrite an existing memory bank silently. It should not change which script the client launches based on a tool argument.

## Actual behavior
Every logged call succeeded with `Memory Bank initialized successfully and MCP settings configured`, including `projectPath` values such as `/tmp/doesnotexist/../etc/shadow` and `..\..\..\..\windows\win.ini`.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads (a README, an issue, a web page) can steer them. An attacker who can trigger this call can create a `memory-bank/` folder and overwrite its four files in any directory the user can write, and can recursively list a large directory tree. The more serious part is the settings rewrite: if `projectPath` names a directory that contains an attacker-supplied `build/index.js` (for example a cloned repository), Cline runs that script on its next start, outside the agent's normal approval flow. Even without an attacker, initializing any project other than this repository replaces a working `memory-bank` entry with one that points at a missing file.

## Suggested fix
- Resolve `projectPath` with `path.resolve` and reject it unless it is inside a configured root (`PROJECT_PATH`, or a list of allowed workspaces).
- Refuse to overwrite an existing `memory-bank/` unless the caller passes an explicit flag.
- Do not derive the server command from `projectPath`. Use the location of the running server (for example `fileURLToPath(import.meta.url)`), and only touch the Cline settings from the CLI `initialize_memory_bank` command, not from the MCP tool.

## Status on the default branch
Still present at `55c81b9` (2025-07-17). The tested commit is the head of the default branch.

## Prior reports
- #5 "Path Traversal Vulnerability in dazeb/cline-mcp-memory-bank" (issue, open 2026-04-27): same root cause at the same commit `55c81b9`. It names `handleInitializeMemoryBank`, `getProjectInfo` and `detectTechStack` and the unchecked `path.join(projectPath, ...)` with `mkdir`/`readdir`/`writeFile`. It does not mention the `updateMcpSettings` rewrite that points Cline at `<projectPath>/build/index.js`. Still open; the code is unchanged on the default branch.
- Documentation: README.md shows `projectPath: '/path/to/project'` as a free caller argument and describes the settings auto-configuration; it has no allowed-root setting and no warning about untrusted paths.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: duplicate of open issue #5 (2026-04-27) for the write location; the Cline settings rewrite to `<projectPath>/build/index.js` is not in #5. If filing, comment on #5 with that part instead of opening a new issue.
- ToFu class / sanitizers: path-traversal via `check_path_traversal` (only sanitizer listed for this tool).
- Campaigns and executions: corpus-sbx 1,536 exec / 858 ok (60 s); e2-0922 1,024 exec / 742 ok (60 s).
- Evidence (verbatim, trimmed): `{'projectPath': '/tmp/doesnotexist/../etc/shadow'}`, `{'projectPath': '..\\..\\..\\..\\windows\\win.ini'}` and `{'projectPath': '"projectPath": ../..ectPath": "'}` all returned `{'content': [{'type': 'text', 'text': 'Memory Bank initialized successfully and MCP settings configured'}]}`.
- Hand-check hints: real, but not classic traversal. The tool has no intended root, so "escaping" one is a design question; the concrete problems are the unchecked write location, the silent overwrite and the settings rewrite (`src/index.ts:768-785`), which is closer to CWE-15 / CWE-427 than CWE-22. The logged inputs did not reach sensitive files: `path.join` normalizes `/tmp/doesnotexist/../etc/shadow` to `/tmp/etc/shadow/memory-bank`, and on the Linux fuzzing hosts the backslash and quote inputs are single literal directory names under the server's cwd. The reproduction, the marker `package.json` read and the settings content are derived from the code, not from a logged run. Not verified: whether Cline reloads `cline_mcp_settings.json` live or only on restart. The settings path is hard-coded to `Code - Insiders`, so users of stable VS Code would not be affected by the settings rewrite. Side note: `detectTechStack` on a large directory (for example a home folder) runs a full recursive `readdir`, which can be slow.
</details>
