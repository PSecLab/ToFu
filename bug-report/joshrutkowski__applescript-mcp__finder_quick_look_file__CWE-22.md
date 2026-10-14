# Unchecked `path` in `finder_quick_look_file`: any file is previewed, and the value is not escaped inside the AppleScript

**Repository:** `joshrutkowski/applescript-mcp` · **Tool:** `finder_quick_look_file` · **Tested commit:** `e6f4c2e`
**Weakness:** CWE-22 Path Traversal

## Summary
`finder_quick_look_file` selects a file in Finder and opens a Quick Look preview of it. The caller's `path` is pasted into an AppleScript string literal with no validation: it is not normalized, not limited to any folder, and not escaped. Any file the user can read can be opened on screen, and characters such as `"` in the value change the generated script instead of being treated as part of the path.

## Details
`src/categories/finder.ts:89-101` at `e6f4c2e`:

```ts
      script: (args) => `
        try
          set filePath to POSIX file "${args.path}"
          tell application "Finder"
            activate
            select filePath
            tell application "System Events"
              delay 0.5
              key code 49 -- Space key
            end tell
          end tell
          return "Quick Look preview opened for ${args.path}"
```

`src/framework.ts:275-280` builds this string from `request.params.arguments` and passes it to `executeScript`, which runs `osascript -e '<script>'` (`src/framework.ts:183-185`). The shell layer escapes single quotes correctly. The AppleScript layer does not escape `"` or `\` in `args.path`, and there is no allowed-folder check.

## Steps to reproduce
1. Prerequisites: macOS with Finder, and Automation / Accessibility permission for the terminal or client that runs the server (System Events sends the Space key). Create a marker file:
   ```
   mkdir -p /tmp/tofu-poc/sub && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install and start the server:
   ```
   git clone https://github.com/joshrutkowski/applescript-mcp.git
   cd applescript-mcp && git checkout e6f4c2ee7d2b391cbcab32fc14dd2e8b8f2564d9
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool with a path that climbs out of `/tmp/tofu-poc/sub`:
   ```json
   {"path": "/tmp/tofu-poc/sub/../outside.txt"}
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
               result = await session.call_tool("finder_quick_look_file", {"path": "/tmp/tofu-poc/sub/../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: Finder comes to the front with `outside.txt` selected and Quick Look shows `marker`. The result text is `Quick Look preview opened for /tmp/tofu-poc/sub/../outside.txt`. Calling it again with a path that contains a double quote, for example `{"path": "/tmp/tofu-poc/out\"side.txt"}`, returns an `AppleScript execution failed` syntax error instead of a clean "file not found", which shows the value is not escaped.

## Expected behavior
The path should be resolved and checked against an allowed folder if the server is meant to be limited, and it should always be passed to AppleScript as data (escaped, or as an `on run argv` argument), never spliced into script source.

## Actual behavior
Any path is accepted and spliced into the script as written. The fuzzing harness only recorded `None` as output for this tool (see internal notes).

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. Through this tool alone an attacker can make any readable file pop up on the user's screen; the file content is not returned to the caller, so the direct disclosure is limited to whoever is looking at the screen. The missing escaping is the more important part: the same pattern is used across the server's script templates, and untrusted text should not be able to change the AppleScript that runs.

## Suggested fix
Pass arguments to `osascript` as `argv` instead of interpolating them: write the script with `on run argv` and `set filePath to POSIX file (item 1 of argv)`, then call `execFile("osascript", ["-e", script, args.path])` without a shell. If the server should be limited to some folders, `path.resolve` the value and reject it unless it starts with an allowed root. Apply the same change to the other script templates that interpolate `args.*`.

## Status on the default branch
Still present at `e6f4c2e` (2025-04-19). The tested commit is the head of the default branch.

## Prior reports
- #8 "Add Pages.app Document Operations Category" (PR, closed 2025-04-16): context only. It "Handles string escaping for quotes in document content" for Pages (`src/categories/pages.ts:30` escapes `"`); `finder.ts` does not use that pattern, and the PR does not touch it.
- No issue or PR about `quick_look` / `finder_quick_look_file`, path checks or AppleScript escaping in Finder, among all 6 issues and 19 pull requests (fetched 2026-10-01).
- Documentation: README.md: "Show me a preview of ~/Documents/report.pdf" (example prompt; previewing a caller-chosen path is the documented use, and no allowed folder is documented)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`. `check_process_and_fd_leaks` also fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); e2-0922 1,024 exec / 1,024 ok (60 s).
- Evidence (verbatim): `{'path': '/etc/passwd\x00'}`, `{'path': '../../../../etc/passwd'}` and `{'path': '..\\..\\..\\..\\windows\\win.ini'}`, each with output `None`.
- Hand-check hints: unclear. This is a macOS-only server. The sandboxed campaigns most likely ran on Linux (bwrap), where `osascript` does not exist; output `None` on every call is consistent with no script running. Check the campaign host before relying on this. The recorded output does not show the tool doing anything. The alert is a pattern match on the input string. The tool has no intended root, so "traversal" is a design question; the content is shown on screen, not returned. The reproduction is derived from the code and was not run (no macOS host here). The double-quote syntax error is expected from reading the template, not observed. The real code-level weakness is the unescaped interpolation into AppleScript source (closer to CWE-94 than CWE-22); consider reframing the issue around that and covering all categories in one report.
</details>
