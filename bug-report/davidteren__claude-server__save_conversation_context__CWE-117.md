# Unvalidated `id` in `save_conversation_context` is used as a file name: `../` and control characters reach `fs.writeFile`

**Repository:** `davidteren/claude-server` · **Tool:** `save_conversation_context` · **Tested commit:** `0b85686`
**Weakness:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory (reported by the fuzzer as CWE-117; see internal notes)

## Summary
`save_conversation_context` stores a context as `~/.claude/contexts/<id>.json`. The `id` argument is used in the file path exactly as the caller sends it. Nothing rejects `/`, `..` or control characters, so a crafted `id` writes the JSON file outside the `contexts` directory or creates file names containing newlines and other control bytes.

## Details
`getContextPath` (`src/index.ts:75-82`) joins the caller's `id` straight into the storage path:

```ts
private async getContextPath(id: string, projectId?: string): Promise<string> {
  if (projectId) {
    const projectDir = path.join(this.projectsDir, projectId);
    await fs.mkdir(projectDir, { recursive: true });
    return path.join(projectDir, `${id}.json`);
  }
  return path.join(this.contextsDir, `${id}.json`);
}
```

`saveContext` (`src/index.ts:103-111`) then writes to that path with `fs.writeFile`. The `save_conversation_context` handler (`src/index.ts:336`) passes `request.params.arguments.id` through without checks; the tool schema only declares it as a string. `path.join` normalizes `..` segments, so an `id` such as `../outside` resolves to `~/.claude/outside.json`, one level above `contexts/`.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3.10+ with `pip install mcp`.
2. Build the server and point `HOME` at a scratch directory so nothing real is touched:

   ```bash
   git clone https://github.com/davidteren/claude-server.git && cd claude-server
   git checkout 0b85686
   npm install && npm run build
   mkdir -p /tmp/tofu-poc/home
   ```
3. Call the tool with an `id` containing `../`:

   ```json
   { "id": "../outside", "sessionId": "s1", "content": "tofu-poc" }
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"],
                                      env={"HOME": "/tmp/tofu-poc/home", "PATH": "/usr/bin:/bin"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("save_conversation_context",
                                                {"id": "../outside", "sessionId": "s1", "content": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the file is created at `/tmp/tofu-poc/home/.claude/outside.json`, outside `/tmp/tofu-poc/home/.claude/contexts/`.

## Expected behavior
The server accepts only simple identifiers for `id` (for example `^[A-Za-z0-9_-]{1,128}$`) and rejects anything else, so every context file stays inside `contexts/`.

## Actual behavior
Any string is accepted and becomes part of the file path. In the fuzzing run, ids containing newlines and other control characters were saved and echoed back, for example:

```
input:  {'id': ':"A  \n', 'sessionId': '', 'content': '', ...}
output: Conversation context saved with ID: :"A  \n
```

## Impact
Tool arguments in MCP are chosen by the model and can be steered by prompt injection in content it reads. A crafted `id` lets the caller place `.json` files anywhere the server's user can write that is reachable through `..` from `~/.claude/contexts`, including overwriting other `.json` files there (for example `~/.claude/context-index.json`). Control characters in file names also break tools that list the directory. The written content is the caller's own JSON, so impact is limited to file placement and overwrite of `.json` files.

## Suggested fix
Validate `id` (and `projectId`, `sessionId`) against a strict identifier pattern before building any path, and as a second check resolve the final path and refuse it unless it is inside `contextsDir` / `projectsDir`:

```ts
const safeId = /^[A-Za-z0-9_-]{1,128}$/;
if (!safeId.test(id)) throw new McpError(ErrorCode.InvalidParams, "invalid id");
const p = path.resolve(this.contextsDir, `${id}.json`);
if (!p.startsWith(path.resolve(this.contextsDir) + path.sep)) throw new McpError(ErrorCode.InvalidParams, "invalid id");
```

## Status on the default branch
Still present at `0b85686` (2026-03-19). That commit also archives the project ("superseded by Claude Code's native memory system"), so a fix may not be accepted; consider a short advisory note instead of an issue.

## Prior reports
- #4 "Add comprehensive analysis and planning documentation" (PR, open 2025-03-15): its summary says it adds "a security assessment document identifying potential vulnerabilities". The body has no details, so it is unclear whether it names this path. It is documentation only and still open, so it fixes nothing.
- Documentation: docs/analysis/feature-assessment.md: "Potential path traversal issues" and "Minimal input validation, potential path traversal issues" (the project's own assessment already lists path traversal as a known weakness, without naming a tool or a fix).
- Documentation: docs/ARCHITECTURE.md: "Input validation prevents directory traversal" (claims a protection that `getContextPath` does not have).
- Documentation: README.md: "This project is no longer maintained (March 2026)." (the repository is archived, so a fix is unlikely).
- Documentation: docs/USAGE.md suggests ids such as `id: "authentication/login-flow"` and `"2024-01-15/team-meeting"` (a `/` in `id` is documented usage, so only `..` segments and control characters are out of scope for the design).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_log_injection` (an input-side check: it fired because the arguments contained CR/LF and the call succeeded). No logger is involved: the server never logs `id` or `content`, and the stored JSON is written with `JSON.stringify`, which escapes CR/LF. The real weakness behind the alert is the unvalidated `id` in the file path, so the draft is framed as CWE-22.
- Campaigns and executions: corpus-sbx, 3,072 executions, 2,235 successful, 60 s budget.
- Evidence (verbatim, trimmed): `{'id': ':"A  \n', ...}` -> `Conversation context saved with ID: :"A  \n`; `{'id': 'context4', 'content': 'Log injection attempt\nINFO: User logged in', ...}` -> saved.
- The committed `build/index.js` is older than `src/index.ts` (it only exposes `save_context`); the fuzzed server was built from `src/`, which is why the reproduction runs `npm run build` first.
- Hand-check hints: real but low severity, by reading the code; the `../` write was not observed in the run (the fuzzer's ids had no `../`). Weakness relabelled from CWE-117 to CWE-22. Repository is archived.
</details>
