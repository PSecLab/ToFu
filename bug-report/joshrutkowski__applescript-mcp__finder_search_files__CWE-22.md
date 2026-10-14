# `finder_search_files` ignores `location` and searches a hard-coded developer folder; `query` is not escaped inside the AppleScript

**Repository:** `joshrutkowski/applescript-mcp` · **Tool:** `finder_search_files` · **Tested commit:** `e6f4c2e`
**Weakness:** CWE-22 Path Traversal

## Summary
`finder_search_files` is documented as searching for files by name under `location` (default: home folder). The script never uses `location`. It always searches the hard-coded folder `/Users/joshrutkowski/Downloads`, so the tool does not work on other machines and the `location` argument has no effect. Separately, `query` is pasted into the AppleScript source without escaping.

## Details
`src/categories/finder.ts:56-67` at `e6f4c2e`:

```ts
      script: (args) => `
        set searchPath to "/Users/joshrutkowski/Downloads"
        tell application "Finder"
          try
            set theFolder to POSIX file searchPath as alias
            set theFiles to every file of folder theFolder whose name contains "${args.query}"
            ...
            if resultList is "" then
              return "No files found matching '${args.query}'"
```

The schema (`src/categories/finder.ts:41-55`) advertises `location` with default `~`, but the template does not reference `args.location`. `args.query` is inserted inside a double-quoted AppleScript string with no escaping of `"` or `\`. The script runs through `osascript -e` (`src/framework.ts:183-185`).

## Steps to reproduce
1. Prerequisites: macOS with Finder and Automation permission for the client that runs the server. Create a marker file: `mkdir -p /tmp/tofu-poc && echo marker > /tmp/tofu-poc/outside.txt`.
2. Install and start the server:
   ```
   git clone https://github.com/joshrutkowski/applescript-mcp.git
   cd applescript-mcp && git checkout e6f4c2ee7d2b391cbcab32fc14dd2e8b8f2564d9
   npm install && npm run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"query": "outside", "location": "/tmp/tofu-poc"}
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
               result = await session.call_tool("finder_search_files", {"query": "outside", "location": "/tmp/tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: `/tmp/tofu-poc/outside.txt` is not found. On a machine without `/Users/joshrutkowski/Downloads` the result is `Failed to search files: ...`; with that folder present, only its contents are searched. A `query` containing a double quote, for example `{"query": "out\"side"}`, gives an `AppleScript execution failed` syntax error instead of "No files found", which shows the value is not escaped.

## Expected behavior
The search should run under `location` (after resolving it and, if the server is meant to be limited, checking it against an allowed root), and `query` should be passed to AppleScript as data.

## Actual behavior
`location` is ignored and the search folder is fixed to the author's Downloads folder. The fuzzing harness recorded `None` as output for the logged call (see internal notes).

## Impact
Mostly a functional bug: the tool cannot search anywhere useful for other users. The security-relevant part is the unescaped `query`: in MCP the LLM chooses tool arguments and prompt injection can steer them, and text that is spliced into script source can change what the AppleScript does instead of only what it searches for. Path traversal through `location` is not possible at this commit because the value is never used.

## Suggested fix
Use `location` (default to the home folder via `path of home folder` or `os.homedir()`), resolve it, and check it against an allowed root if one is wanted. Pass `query` and the folder as `osascript` `argv` arguments (`on run argv`) through `execFile` instead of interpolating them into the script text.

## Status on the default branch
Still present at `e6f4c2e` (2025-04-19). The tested commit is the head of the default branch.

## Prior reports
- #8 "Add Pages.app Document Operations Category" (PR, closed 2025-04-16): context only. It "Handles string escaping for quotes in document content" for Pages (`src/categories/pages.ts:30` escapes `"`); `finder.ts` does not use that pattern, and the PR does not touch it.
- No issue or PR about `search_files`, the ignored `location` or the hard-coded search folder, among all 6 issues and 19 pull requests (fetched 2026-10-01).
- Documentation: README.md: "`search_files` | Search for files | `query`, `location` (optional)" with the example "Find all PDF files in my Documents folder" (documents a `location` argument that the script ignores)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`. `check_process_and_fd_leaks` also fired for this tool.
- Campaigns and executions: corpus-sbx 2,048 exec / 2,048 ok (60 s); e2-0922 1,024 exec / 1,024 ok (60 s).
- Evidence (verbatim): `{'query': 'test', 'location': '../../../../etc/passwd'}` with output `None`. Only one logged sample.
- Hand-check hints: weak, and misclassified as path traversal. `location` never reaches any file operation (`src/categories/finder.ts:57` hard-codes the folder), so the flagged input cannot traverse anything. The alert is a pattern match on the input string, and the output `None` suggests the script never ran (macOS-only server; the sandboxed campaigns most likely ran on Linux without `osascript`; check the campaign host). What is real: the hard-coded developer path (functional bug) and the unescaped `query` interpolation (closer to CWE-94). The reproduction is derived from the code and was not run (no macOS host here).
</details>
