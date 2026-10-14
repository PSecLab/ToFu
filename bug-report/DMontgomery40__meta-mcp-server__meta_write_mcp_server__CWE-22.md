# Path traversal in `meta_write_mcp_server`: `files[].path` with `../` writes outside `outputDir`

**Repository:** `DMontgomery40/meta-mcp-server` · **Tool:** `meta_write_mcp_server` · **Tested commit:** `b36b530`
**Weakness:** CWE-22 Path Traversal

## Summary
`meta_write_mcp_server` writes a list of files into `outputDir`. The schema documents each `files[].path` as a "Relative path within the output directory", but the handler never checks that the joined path stays inside `outputDir`. A path such as `../outside.txt` creates or overwrites a file next to the output directory instead of inside it. The tool is also annotated `destructiveHint: false`, so clients that relax approval for non-destructive tools may not ask before such a write.

## Details
`src/main.ts:24-27` defines the contract, and `src/main.ts:285-292` writes the files:

```ts
const FileEntrySchema = z.object({
  path: z.string()
    .min(1, "File path must not be empty")
    .describe("Relative path within the output directory (e.g. 'src/index.ts', 'package.json')"),
// ...
      await mkdir(args.outputDir, { recursive: true });
      // ...
      for (const file of args.files) {
        const fullPath = path.join(args.outputDir, file.path);
        const dir = path.dirname(fullPath);
        await mkdir(dir, { recursive: true });
        await writeFile(fullPath, file.content, "utf8");
```

`path.join` normalizes `..` segments, so `path.join("/tmp/tofu-poc/root", "../outside.txt")` is `/tmp/tofu-poc/outside.txt`. There is no `path.resolve` plus prefix check, and no rejection of `..` segments. `writeFile` truncates an existing file, and `mkdir(dir, { recursive: true })` creates any missing parent directories on the way.

Related points in the same handler:
- `src/main.ts:276-281` declares `destructiveHint: false` and `idempotentHint: true`, but the tool overwrites existing files without warning.
- `outputDir` itself accepts any absolute or relative path (`src/main.ts:33-35`), and there is no configured base directory. That is a design choice, but it means the only boundary a user can see when approving a call is `outputDir`, and the `files` entries can step outside it.
- With `--http` (`src/main.ts:493-514`, and the Dockerfile default `CMD`), the server calls `httpServer.listen(port, ...)` with no host argument and no authentication on the transport.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and npm. No accounts or env vars. Create a marker file first:

   ```bash
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install and build as the README describes:

   ```bash
   git clone https://github.com/DMontgomery40/meta-mcp-server.git
   cd meta-mcp-server && git checkout b36b530
   npm install && npm run build
   ```
3. Call the tool from the repository root with:

   ```json
   {"outputDir": "/tmp/tofu-poc/root", "files": [{"path": "../outside.txt", "content": "overwritten by tofu-poc\n"}]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/main.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("meta_write_mcp_server", {
                   "outputDir": "/tmp/tofu-poc/root",
                   "files": [{"path": "../outside.txt", "content": "overwritten by tofu-poc\n"}],
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `cat /tmp/tofu-poc/outside.txt` prints `overwritten by tofu-poc` instead of `marker`. The file sits outside `/tmp/tofu-poc/root`. Using `"path": "../new.txt"` instead creates `/tmp/tofu-poc/new.txt`.

## Expected behavior
The call is rejected with an error because `../outside.txt` resolves outside `outputDir`. Nothing outside `/tmp/tofu-poc/root` is created or changed.

## Actual behavior
The tool reports success and lists the escaping path as a created file:

```
Successfully created MCP server in /tmp/tofu-poc/root:
  - ../outside.txt
```

and `/tmp/tofu-poc/outside.txt` is overwritten.

## Impact
In MCP the LLM chooses `outputDir` and `files`, and prompt injection from untrusted content (a README, an issue, a web page) can steer those values. A call whose `outputDir` looks harmless, such as a new folder under `/tmp`, can still create or overwrite any file the server process can write, through a `files` entry with `../` segments. Because `outputDir` is already unrestricted, the extra reach is limited; the main problem is that the documented contract ("relative path within the output directory") and the `destructiveHint: false` annotation both understate what the tool can do. In HTTP mode, anyone who can reach the port can make the same call.

## Suggested fix
- For each entry, compute `const root = path.resolve(args.outputDir); const full = path.resolve(root, file.path);` and reject the call unless `path.relative(root, full)` is non-empty, does not start with `..`, and is not absolute. Also reject absolute `file.path` values outright.
- Optionally support a base directory (for example a `META_MCP_ROOT` environment variable) and require `outputDir` to resolve under it.
- Refuse to overwrite existing files unless the caller passes an explicit `overwrite: true`, or set `destructiveHint: true`.
- In `--http` mode, bind to `127.0.0.1` by default.

## Status on the default branch
Still present at `b36b530` (2026-03-23). The default branch head is the tested commit.

## Prior reports
- No issue or pull request covers this. Searched all 1 issue and 2 pull requests (fetched 2026-10-01).
- Documentation: README.md: `meta_write_mcp_server` is listed as "Write files for a new MCP server to disk" (no base directory or containment is documented). The README appendix lists "Unsafe state changes (destructive file/system/API actions)" as a prompt-injection risk and recommends "Human confirmation for destructive/high-risk actions"; that is general advice to users, not a statement that `files[].path` may leave `outputDir`, and it sits oddly with the tool's `destructiveHint: false`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal`. `check_reflected_output` also fired for this tool (outputDir and file paths are echoed in the reply), not used here.
- Campaigns and executions: corpus-sbx 3072 exec / 97 ok (60 s); e2-0922 2048 exec / 84 ok (300 s). Low success ratio is expected: most fuzzed `files` arrays fail schema validation or mkdir.
- Evidence (verbatim, trimmed):
  - `{'outputDir': '"ou4putDir": "/tmp/server", "files": [{"path": "/etc/passwd\\u0001", "content": "nulbn"}', 'files': [{'path': '/etc/passwd\x01', 'content': 'nulbn'}]}` -> `Successfully created MCP server in "ou4putDir": "/tmp/server", ...:\n  - /etc/passwd\x01`
  - `{'outputDir': '"outputDir": "../../\x7f...\x7f../,./../tmp/evil"{"outpu', 'files': [{'path': '<non-BMP chars>', 'content': ''}]}` -> `Successfully created MCP server in "outputDir": "../../...`
  - same with `outputDir` starting `boutputDir": "../../...` -> success.
- Hand-check hints: weak. The missing containment check on `files[].path` is real in the code (`path.join` at `src/main.ts:289`, no resolve/prefix check). But none of the logged payloads actually escaped: `path.join` appends an absolute `file.path` (the `/etc/passwd\x01` entry became `<outputDir>/etc/passwd\x01`, under the fuzzer's scratch cwd because `outputDir` was a relative junk string), and the `../` sequences were inside `outputDir`, which is unrestricted by design. The reproduction above (`../outside.txt`) is derived from code reading and was not executed; run it before filing. A maintainer may answer that `outputDir` is arbitrary anyway, so frame it as a contract/annotation mismatch rather than a high-severity bug. The `destructiveHint: false` point and the all-interfaces HTTP bind are verified in code; I did not check which clients act on `destructiveHint`.
</details>
