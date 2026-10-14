# `vim_command` shell execution: `!` commands run via `system()` with weak quoting when enabled

**Repository:** `bigcodegen/mcp-neovim-server` · **Tool:** `vim_command` · **Tested commit:** `9076bbb`
**Weakness:** CWE-78 OS Command Injection

## Summary
`vim_command` runs an arbitrary Vim command. When the input starts with `!` it is treated as a shell command and executed through Neovim's `system()`. Shell execution is off by default (`ALLOW_SHELL_COMMANDS` must be `true`), and in the captured evidence the default-off guard blocked the input. The reportable concern is conditional: when an operator enables shell commands (which the README's recommended config does), the `!` payload reaches `system()` with only single-quote doubling applied, so shell metacharacters in the argument are not neutralized, and the tool argument is LLM-controlled.

## Details
The tool checks the flag, then calls `sendCommand` (`src/index.ts:106-118`). The execution path (`src/neovim.ts:163-185`):

```ts
if (normalizedCommand.startsWith('!')) {
  if (process.env.ALLOW_SHELL_COMMANDS !== 'true') {
    return 'Shell command execution is disabled. Set ALLOW_SHELL_COMMANDS=true ...';
  }
  const shellCommand = normalizedCommand.substring(1).trim();
  const output = await nvim.eval(`system('${shellCommand.replace(/'/g, "''")}')`);
```

`system()` runs its argument through a shell. The only transformation is `'` → `''`, which guards the VimL string literal, not the shell command inside it. Characters such as `;`, `|`, `` ` ``, and `$(...)` inside `shellCommand` are passed to the shell unchanged.

## Steps to reproduce
1. Prerequisites: Neovim running with a listening socket (`nvim --listen /tmp/nvim`), and the server started with shell commands enabled, as the README's recommended config sets:
   ```json
   { "command": "npx", "args": ["-y", "mcp-neovim-server"],
     "env": { "ALLOW_SHELL_COMMANDS": "true", "NVIM_SOCKET_PATH": "/tmp/nvim" } }
   ```
2. Call the tool with a harmless shell command. Arguments as JSON:
   ```json
   {"command": ":!id"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-neovim-server"],
                                      env={"ALLOW_SHELL_COMMANDS": "true", "NVIM_SOCKET_PATH": "/tmp/nvim"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("vim_command", {"command": ":!id"})
               print(result)

   asyncio.run(main())
   ```
3. Observe `id` output. A chained payload such as `:!echo a; id` runs both commands, showing metacharacters are not neutralized.

## Expected behavior
If shell execution is a supported feature, the tool should make clear it hands the LLM full shell access, and should not rely on quoting that does not neutralize shell metacharacters. Ideally shell commands are passed as an argv array, not interpolated into a `system()` string.

## Actual behavior
With the default configuration the guard blocked the input. From the fuzz evidence:

```
Shell command execution is disabled. Set ALLOW_SHELL_COMMANDS=true environment variable to enable shell commands.
```

With `ALLOW_SHELL_COMMANDS=true`, the `!` command runs via `system()` as shown above.

## Impact
In MCP, tool arguments are chosen by the LLM and can be steered by prompt injection from untrusted content. On a server configured per the README (shell enabled), an attacker who influences `command` gains arbitrary OS command execution as the server user. With the default configuration, execution is blocked.

## Suggested fix
Document that enabling `ALLOW_SHELL_COMMANDS` grants the model arbitrary shell access. If the feature is kept, build the command as an argv array passed to `jobstart`/`system()` without string interpolation, or restrict it to an explicit allowlist.

## Status on the default branch
Still present at `9076bbb` (2025-09-13). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
- Documentation: README.md: "Shell commands supported with `!` prefix when `ALLOW_SHELL_COMMANDS=true`" (the `!` shell path is a documented, opt-in feature)
- Documentation: README.md: "Defaults to false for security." (describes `ALLOW_SHELL_COMMANDS`; the README's manual-installation config then sets it to `"true"`. Nothing in the docs warns that the setting gives the model arbitrary shell access)
- No issue or pull request discusses shell execution, quoting or injection in `vim_command`. Searched all 9 issues and 15 pull requests (fetched 2026-10-01); 11 of the 15 pull requests have an empty description.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: os-command-injection (CWE-78); triggered `check_blocked_command_bypass`, `check_command_injection`. Campaigns: corpus-sbx (1/1), e2-0922 (1/1).
- Evidence (verbatim, trimmed): inputs `:!cat /etc/passwd` and `:!touch /tmp/vimtest && cat /tmp/vimtest` → both returned the "Shell command execution is disabled" message (guard held; `ALLOW_SHELL_COMMANDS` not set in the sandbox).
- Hand-check hints: WEAK as captured — this is a ToFu "silent bug" alert on the BLOCKED path (the default-off guard worked, so the fired alert is effectively a false positive for the tested config). The genuine, reportable issue is conditional and by-inspection: when the operator enables shell commands (README recommends exactly that), `system('...'.replace(/'/g,"''"))` does not neutralize shell metachars, and the arg is LLM-controlled. Frame honestly as conditional; do not overstate.
</details>
