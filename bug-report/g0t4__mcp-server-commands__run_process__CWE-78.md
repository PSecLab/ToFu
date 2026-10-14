# `run_process` executes any shell command line with no allowlist, denylist or working-directory restriction (by design; request for an opt-in policy)

**Repository:** `g0t4/mcp-server-commands` · **Tool:** `run_process` · **Tested commit:** `bc62283`
**Weakness:** CWE-78 OS Command Injection

## Summary
`run_process` passes `command_line` to the system shell (or `argv` to `spawn`) and returns stdout and stderr. This is the tool's documented purpose, and the README warns users to approve each call. There is, however, no server-side control at all: no allowlist or denylist, no confinement of `cwd`, no read-only mode. Whatever the LLM is steered into sending runs with the full privileges of the server user. This report is a request for an opt-in policy layer, not a claim of an unintended bug.

## Details
`src/run_process.ts:109-124` and `:163`:
```ts
    if (args.cwd) {
        options.cwd = args.cwd;
    }

    let spawnCommand = "";
    let spawnArgs: string[] = [];
    if (args.isShellMode) {
        (options as any).shell = true;
        spawnCommand = String(args.commandLine);
        spawnArgs = [];
    } else {
        (options as any).shell = false;
        const argv = args.argv as string[];
        spawnCommand = argv[0];
        spawnArgs = argv.slice(1);
    }
    ...
        const child = spawn(spawnCommand, spawnArgs, options);
```
`src/tools.ts:68-75` forwards `request.params.arguments` to `runProcess` with no checks. `cwd` can be any directory. `RunProcessArgsHelper` (`run_process.ts:41-90`) also coerces types silently, for example a non-string `stdin_text` is converted with `String(v)`, so `["not", "a", "string"]` becomes `not,a,string`.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No credentials.
2. Build the server as the README describes ("Use a local build"):
   ```bash
   git clone https://github.com/g0t4/mcp-server-commands && cd mcp-server-commands
   git checkout bc62283
   npm install && npm run build
   ```
3. From the repository root, call the tool with these arguments:
   ```json
   {"command_line": "id; cat /etc/hostname; echo tofu-poc > /tmp/tofu-poc.txt", "cwd": "/tmp", "timeout_ms": 30000}
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
               result = await session.call_tool("run_process", {
                   "command_line": "id; cat /etc/hostname; echo tofu-poc > /tmp/tofu-poc.txt",
                   "cwd": "/tmp",
                   "timeout_ms": 30000,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the `id` output and the host name in `STDOUT`, and the new file `/tmp/tofu-poc.txt`.

## Expected behavior
For a tool whose purpose is running commands, the server can still offer an opt-in way to limit what runs, for example an allowlist of executables or a fixed working directory set by the user at startup.

## Actual behavior
Every command runs. In the fuzzing run, `{"command_line": "cat ../../../../etc/passwd", "cwd": "/tmp", ...}` returned `EXIT_CODE` `0` and the contents of `/etc/passwd` in `STDOUT`. A call with `stdin_text: ["not", "a", "string"]` was also accepted rather than rejected.

## Impact
Tool arguments are chosen by the LLM, and prompt injection from untrusted content (a web page, an issue comment, a file the model reads) can steer them. If the user has set the client to auto-approve this tool, an injected instruction runs arbitrary commands as the user. The README's advice to use "Approve Once" is the only safeguard. This is inherent to the tool, so severity depends on deployment; I am filing it as a hardening request.

## Suggested fix
Add optional, user-controlled restrictions read from CLI flags or environment variables at startup, for example:
- `--allow=git,ls,rg` to accept only those `argv[0]` values (and, when set, reject `command_line` shell mode or parse its first word);
- `--root=/path/to/project` to require `cwd` to resolve under that directory;
- reject non-string `command_line`, `stdin_text` and `cwd` values instead of coercing them with `String()`.
Keep the current unrestricted behavior as the default if that is the intended use, and document the flags next to the existing warning.

## Status on the default branch
Still present at `bc62283` (2026-04-09). The tested commit is the current default branch head.

## Prior reports
- #10 "Critical Security Issue: Lack of Command Validation Enables Destructive Operations" (issue, closed 2025-09-18): the same request against the earlier `run_command` tool (v0.5.0): no command validation, asks for a denylist/whitelist and input sanitizing. It was closed, but the default branch at `bc62283` still has no allowlist, denylist or `cwd` restriction, so it was closed without such a change (the export does not say why).
- #12 "feat: add MCP tool annotations to run_command" (PR, open 2025-12-29): adds `destructiveHint: true` and `openWorldHint: true` to the tool definition. Related hardening for client-side approval; not merged and does not restrict what runs.
- #14 "Add SECURITY.md — enable private vulnerability reporting" (PR, open 2026-03-16): would add a private reporting channel; not merged, so the repository has no SECURITY.md.
- Documentation: `README.md` warning: "Be careful what you ask this server to run!", advising `Approve Once` and noting "Permissions are dictated by the user that runs the server" (unrestricted execution is documented as intended).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: same request already filed as #10 (closed 2025-09-18, for `run_command`) and not acted on in code; the README documents unrestricted execution. Filing again is likely to be closed; at most comment on #10 or propose the opt-in flags as a PR.
- ToFu class / sanitizers: os-command-injection, `check_blocked_command_bypass` ("Silent Bug Alert": the sanitizer judged the input malicious, the tool ran it).
- Campaigns and executions: `corpus-sbx` 2048 exec / 35 success (60 s); `e2-0922` 1024 exec / 9 success (60 s).
- Evidence (verbatim, trimmed): input `{'command_line': 'cat ../../../../etc/passwd', 'argv': None, 'cwd': '/tmp', 'stdin_text': '', 'timeout_ms': 30000}`; output `{'content': [{'name': 'EXIT_CODE', 'type': 'text', 'text': '0'}, {'name': 'STDOUT', 'type': 'text', 'text': 'root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:...'}]}`. Two more inputs used `cat /etc/passwd` with `stdin_text: ['not', 'a', 'string']`, same output.
- Hand-check hints: weak as a vulnerability. This is a command-runner by design, and the README has an explicit warning (README.md:26-30). There is no injection: the caller supplies the whole command line on purpose. ToFu's `check_blocked_command_bypass` fires on any sensitive command that runs, which is the expected behavior of this tool. Do not file as CWE-78 "injection". If filed at all, file as a feature request for an opt-in allowlist / cwd root. The fuzz runs did execute `cat /etc/passwd` under the sandbox; from the log alone I cannot tell whether that was the host's file bound into bwrap or a sandbox copy. Not run here.
</details>
