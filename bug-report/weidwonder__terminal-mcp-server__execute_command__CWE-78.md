# Shell injection via `env` in `execute_command` (SSH mode): variable values are expanded by the remote shell

**Repository:** `weidwonder/terminal-mcp-server` · **Tool:** `execute_command` · **Tested commit:** `c09db33`
**Weakness:** CWE-78 OS Command Injection

## Summary
`execute_command` runs a shell command locally or on a remote host over SSH. Running `command` is the purpose of the tool, so this report is not about that argument. It is about `env`, which the README documents as "Environment variables". In SSH mode the values (and the names) are pasted into a shell string with only `"` escaped, so `$(...)` or backticks inside a value run as commands on the remote host. A client or user who reviews `command` before approving a call would not expect `env` to execute code. The tool also has no allowlist, denylist or confirmation for commands of any kind.

## Details
SSH, interactive-shell path, `src/executor.ts:196-202` and `:254-256`:

```ts
const envSetup = Object.entries(env)
  .map(([key, value]) => `export ${key}="${String(value).replace(/"/g, '\\"')}"`)
  .join(' && ');
const fullCommand = envSetup ? `${envSetup} && ${command}` : command;
...
sessionData.shell.write(`echo "Starting command execution: ${fullCommand}"\n`);
sessionData.shell.write(`${fullCommand}\n`);
```

SSH, non-interactive path, `src/executor.ts:272-279`:

```ts
const fullCommand = envSetup ? `${envSetup} && ${command}` : command;
sessionData?.client?.exec(`/bin/bash --login -c "${fullCommand.replace(/"/g, '\\"')}"`, ...
```

Inside double quotes the shell still performs `$(...)`, backtick and `$VAR` expansion, and a `\` before the escaped quote undoes the escaping. `key` is not validated at all, so a name like `A=1; id; B` is also run. A second effect of line 254: the whole `fullCommand` is placed inside `echo "..."`, so any `$(...)` in `command` or `env` is executed twice (once by the echo line, once by the real line).

The local path (`src/executor.ts:341-354`) passes `env` through `exec(command, { env: envVars })`, so values are not interpreted there.

## Steps to reproduce
1. Prerequisites: Node.js; an SSH server you control (for example `localhost` with sshd enabled) that accepts key login with `~/.ssh/id_rsa` (the key path is hard-coded at `src/executor.ts:44`).
2. Install and start the server as the README describes:
   `git clone https://github.com/weidwonder/terminal-mcp-server.git && cd terminal-mcp-server && npm install && npm run build && node build/index.js`
3. Call the tool with a harmless `command` and the payload in `env`:

   ```json
   {"host": "127.0.0.1", "username": "<your-user>", "command": "echo ok", "env": {"TOFU": "$(id > /tmp/tofu-poc.txt)"}}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/terminal-mcp-server/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("execute_command", {
                   "host": "127.0.0.1",
                   "username": "<your-user>",
                   "command": "echo ok",
                   "env": {"TOFU": "$(id > /tmp/tofu-poc.txt)"},
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: on the SSH host, `/tmp/tofu-poc.txt` exists and contains the output of `id`, although `command` was only `echo ok`.

## Expected behavior
`env` values are treated as data: they are quoted for the shell (single quotes with `'` escaped) or passed through the SSH channel's environment, and names are checked against `^[A-Za-z_][A-Za-z0-9_]*$`.

## Actual behavior
The value is expanded by the remote shell and the embedded command runs. This was derived from the code; see the internal notes.

## Impact
The LLM fills in all arguments, and prompt injection from untrusted content can steer them. Because `command` already runs anything, the extra power for an attacker is small when a client auto-approves calls. It matters when a person or a client policy reviews `command` but treats `env` as configuration: the payload can hide in a value that looks like a setting. The README notes the project is no longer maintained, so this may be mainly a warning for users.

## Suggested fix
- Validate env names with `^[A-Za-z_][A-Za-z0-9_]*$` and reject others.
- Quote values with single quotes (`'` → `'\''`) instead of double quotes, or use ssh2's `env` option on `exec`/`shell` where the server allows it.
- Drop the `echo "Starting command execution: ${fullCommand}"` line or print a quoted copy, so commands are not evaluated twice.
- Consider an optional allowlist or confirmation hook for `command`, since the tool has none.

## Status on the default branch
Still present at `c09db33` (2025-09-17). The default branch has no newer commits than the tested one.

## Prior reports
- #5 "Critical Security Issue: Unrestricted Command Execution and Insecure Use of exec() in terminal-mcp-server" (issue, closed 2025-09-17): reports that `command` runs with no allowlist or denylist, and that the local path uses `exec()` (`src/executor.ts:347-354`). That covers this draft's "no allowlist" remark. It does not mention `env` or the SSH path, so the `env` quoting bug is not reported. It was closed about a minute after the head commit `c09db33` ("Update README.md"), with no code change on the default branch.
- Documentation: README.md: "Current Project not in maintance anymore." (the notice at `c09db33` points users to Desktop Commander). The README documents `env` only as "Environment variables, defaults to an empty object" and has no warning about command execution.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: os-command-injection; `check_blocked_command_bypass`.
- Campaigns and executions: e2-0922 only, 1 call, 0 succeeded, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`, no input or output survived. The reproduction above is derived from the code, not from a ToFu call.
- Hand-check hints: unclear. The ToFu alert itself is close to "by design": `execute_command` exists to run arbitrary commands, there is no block list in the code to bypass, and the single call did not succeed. The `env` expansion in SSH mode and the double evaluation via the `echo` line are real by code reading (`executor.ts:196-202, 254-256, 272-279`) but were not executed; they need an SSH host to confirm. If the reviewer does not want to file a design-level issue, the `env` quoting bug is the only concrete code defect worth reporting. README advertises an SSE mode (`--sse`, `--host 0.0.0.0`) that `src/index.ts` does not implement at this commit.
</details>
