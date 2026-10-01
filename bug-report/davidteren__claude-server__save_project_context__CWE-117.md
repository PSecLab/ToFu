# Unvalidated `projectId` and `id` in `save_project_context` are used as path segments: `../` creates directories and files outside `~/.claude/projects`

**Repository:** `davidteren/claude-server` · **Tool:** `save_project_context` · **Tested commit:** `0b85686`
**Weakness:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory (reported by the fuzzer as CWE-117; see internal notes)

## Summary
`save_project_context` stores a context as `~/.claude/projects/<projectId>/<id>.json`. Both `projectId` and `id` are used in the path exactly as the caller sends them, and `projectId` is first passed to `fs.mkdir(..., { recursive: true })`. A crafted `projectId` or `id` therefore creates directories and writes the JSON file outside `~/.claude/projects`, and control characters end up in directory and file names.

## Details
`getContextPath` (`src/index.ts:75-82`):

```ts
if (projectId) {
  const projectDir = path.join(this.projectsDir, projectId);
  await fs.mkdir(projectDir, { recursive: true });
  return path.join(projectDir, `${id}.json`);
}
```

`saveContext` (`src/index.ts:103-111`) writes the context there with `fs.writeFile`. The `save_project_context` handler (`src/index.ts:295-333`) takes `id` and `projectId` from `request.params.arguments` without validation; the schema only requires them to be strings.

## Steps to reproduce
1. Prerequisites: Node.js 18+, Python 3.10+ with `pip install mcp`.
2. Build the server and point `HOME` at a scratch directory:

   ```bash
   git clone https://github.com/davidteren/claude-server.git && cd claude-server
   git checkout 0b85686
   npm install && npm run build
   mkdir -p /tmp/tofu-poc/home
   ```
3. Call the tool with a `projectId` that leaves the projects directory:

   ```json
   { "id": "note", "projectId": "../../outside-project", "content": "tofu-poc" }
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
               result = await session.call_tool("save_project_context",
                                                {"id": "note", "projectId": "../../outside-project", "content": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the new directory `/tmp/tofu-poc/home/outside-project/` containing `note.json`, two levels above `/tmp/tofu-poc/home/.claude/projects/`.

## Expected behavior
`projectId` and `id` are rejected unless they are simple identifiers, and the final path is checked to be inside `projectsDir` before any `mkdir` or write.

## Actual behavior
Both values are accepted as-is. In the fuzzing run, `id` values containing CR, DEL and other control bytes were saved and echoed back:

```
input:  {'id': '"id":\x7f\r\x7f\x7f... ', 'projectId': '', 'content': '', ...}
output: Project context saved with ID: "id":\x7f\r\x7f\x7f...
```

## Impact
MCP tool arguments are chosen by the model and can be steered by prompt injection. Through `projectId`, a caller can create arbitrary directory trees and drop `<id>.json` files anywhere the server's user can write that `..` segments can reach from `~/.claude/projects`, or overwrite existing `.json` files there. The file content is the caller's own JSON, so the impact is limited to unwanted directories and `.json` file creation or overwrite, but it happens under the user's home directory by default.

## Suggested fix
Validate `projectId` and `id` with a strict pattern (for example `^[A-Za-z0-9_-]{1,128}$`) before calling `fs.mkdir`, then resolve the final path and refuse it unless it starts with `path.resolve(this.projectsDir) + path.sep`.

## Status on the default branch
Still present at `0b85686` (2026-03-19). That commit archives the project, so a fix may not be accepted.

## Prior reports
- #4 "Add comprehensive analysis and planning documentation" (PR, open 2025-03-15): its summary says it adds "a security assessment document identifying potential vulnerabilities". The body has no details, so it is unclear whether it names this path. It is documentation only and still open, so it fixes nothing.
- Documentation: docs/analysis/feature-assessment.md: "Potential path traversal issues" and "Minimal input validation, potential path traversal issues" (the project's own assessment already lists path traversal as a known weakness, without naming a tool or a fix).
- Documentation: docs/ARCHITECTURE.md: "Input validation prevents directory traversal" (claims a protection that `getContextPath` does not have).
- Documentation: README.md: "This project is no longer maintained (March 2026)." (the repository is archived, so a fix is unlikely).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117), `check_log_injection` plus `check_invalid_json` (input-side checks: CR/LF in the arguments and a successful call). The server does not log these arguments, and the stored JSON escapes CR/LF, so CWE-117 does not fit. The weakness behind the alert is the unvalidated path segments; draft framed as CWE-22.
- Campaigns and executions: corpus-sbx, 2,560 executions, 1,213 successful, 60 s budget.
- Evidence (verbatim, trimmed): `{'id': 'context3', 'projectId': 'proj3', 'content': 'Line1\nLine2...', 'references': ['../../../../etc/passwd', 'context4'], ...}` -> `Project context saved with ID: context3` (the traversal string here was in `references`, which is only stored, not used as a path).
- The committed `build/index.js` predates `src/index.ts`; the fuzzed server was built from `src/`.
- Hand-check hints: real by reading the code (mkdir + writeFile on an unvalidated joined path); the `../` placement was not observed in the run. Relabelled CWE-117 -> CWE-22. Repository archived.
</details>
