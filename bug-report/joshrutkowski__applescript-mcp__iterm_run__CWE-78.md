# `iterm_run` types any caller command into the user's iTerm session, and the command is not escaped inside the AppleScript

**Repository:** `joshrutkowski/applescript-mcp` · **Tool:** `iterm_run` · **Tested commit:** `e6f4c2e`
**Weakness:** CWE-78 OS Command Injection

## Summary
`iterm_run` sends a command to the current (or a new) iTerm session with `write text`, which runs it in the user's shell. Running a command is the purpose of the tool, so this report is not about that by itself. Two things make it riskier than it needs to be: there is no allowlist, confirmation or documentation of the risk, and `command` is pasted into an AppleScript string literal without escaping. A double quote or backslash in the value changes the generated AppleScript instead of being typed as part of the command.

## Details
`src/categories/iterm.ts:43-60` at `e6f4c2e`:

```ts
      script: (args) => `
        tell application "iTerm"
          ${
            args.newWindow
              ? `set newWindow to (create window with default profile)
                 tell current session of newWindow`
              : `set w to current window
                 tell w's current session`
          }
            write text "${args.command}"
            activate
          end tell
        end tell
      `,
```

`src/framework.ts:275-280` builds the script from `request.params.arguments`, and `executeScript` runs it with `exec("osascript -e '<script>'")` (`src/framework.ts:183-185`). The single-quote escaping there protects the outer shell. Nothing escapes `"` or `\` for the AppleScript string, so the command text is not kept separate from the script source.

## Steps to reproduce
1. Prerequisites: macOS with iTerm2 running and Automation permission for the client that runs the server.
2. Install and start the server:
   ```
   git clone https://github.com/joshrutkowski/applescript-mcp.git
   cd applescript-mcp && git checkout e6f4c2ee7d2b391cbcab32fc14dd2e8b8f2564d9
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool twice: once with a plain command, once with a command that contains double quotes:
   ```json
   {"command": "echo tofu-poc", "newWindow": true}
   ```
   ```json
   {"command": "echo \"tofu-poc\"", "newWindow": true}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("iterm_run", {"command": "echo tofu-poc", "newWindow": True}))
               print(await session.call_tool("iterm_run", {"command": "echo \"tofu-poc\"", "newWindow": True}))

   asyncio.run(main())
   ```
4. What to observe: the first call opens an iTerm window and runs `echo tofu-poc` with no prompt to the user. The second call, a valid shell command, fails with an `AppleScript execution failed` syntax error because its quotes end the AppleScript string early.

## Expected behavior
The command text should reach iTerm exactly as given, as data, whatever characters it contains. Given what the tool does, users should also be told clearly that it runs arbitrary commands, and ideally be able to restrict or confirm them.

## Actual behavior
The value is spliced into the AppleScript source. The fuzzing harness recorded output `None` for all logged calls (see internal notes).

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. With this tool enabled and auto-approved, injected text can get commands run in the user's terminal with the user's privileges; that is inherent to the feature and worth stating in the README. The missing escaping adds a second problem: the value can alter the AppleScript itself, not just the command line, and ordinary commands with quotes break.

## Suggested fix
- Pass the command to `osascript` as an argument instead of interpolating it: use `on run argv` with `write text (item 1 of argv)`, and call `execFile("osascript", ["-e", script, command])` without a shell.
- Document in the README that `iterm_run` executes arbitrary commands, and recommend that clients require confirmation for it. An optional allowlist (for example an environment variable with permitted command prefixes) would help users who want to restrict it.

## Status on the default branch
Still present at `e6f4c2e` (2025-04-19). The tested commit is the head of the default branch.

## Prior reports
- #16 "Add permissions to enable some features without others" (issue, open 2025-05-03): a user asks for a permissions list so the server can be used "without giving the goods away to my entire computer". Related to the missing allowlist / confirmation for `iterm_run`; still open, no fix.
- #8 "Add Pages.app Document Operations Category" (PR, closed 2025-04-16): context only. It "Handles string escaping for quotes in document content" for Pages (`src/categories/pages.ts:30` escapes `"`); `iterm.ts` does not use that pattern, and the PR does not touch it.
- No issue or PR about `iterm_run`, command escaping or command injection, among all 6 issues and 19 pull requests (fetched 2026-10-01).
- Documentation: README.md: "`run` | Execute command | `command`, `newWindow` (optional)" with the example `Run "ls -la" in iTerm` (running commands is the documented purpose; no warning, allowlist or confirmation is documented)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: os-command-injection via `check_blocked_command_bypass`. `check_process_and_fd_leaks` also fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); e2-0922 1,024 exec / 1,024 ok (60 s).
- Evidence (verbatim): `{'command': '/etc/passwd\x00', 'newWindow': False}`, `{'command': '../../../../etc/passwd', 'newWindow': False}` and `{'command': 'cat /etc/passwd; ls -la /', 'newWindow': True}`, each with output `None`.
- Hand-check hints: weak as filed by ToFu. The tool runs commands by design and has no blocklist to bypass, so `check_blocked_command_bypass` firing is not evidence of a bypass. Output `None` on every call suggests nothing ran (macOS-only server; the sandboxed campaigns most likely ran on Linux without `osascript`; check the campaign host). The real code issue is the unescaped interpolation into AppleScript source (closer to CWE-94), which the quote reproduction shows benignly; it is derived from the code and was not run (no macOS host here). `${args.*}` interpolation also appears in `finder`, `mail`, `messages`, `calendar`, `shortcuts` and `system` (grep count at the tested commit; not reviewed one by one); a single report covering the shared `executeScript` design may land better than per-tool issues.
</details>
