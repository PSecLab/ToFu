# Path traversal in `create_plugin`: `outputPath` can create and overwrite project files anywhere on disk

**Repository:** `Sheshiyer/framer-plugin-mcp` · **Tool:** `create_plugin` · **Tested commit:** `5e17486`
**Weakness:** CWE-22 Path Traversal

## Summary
`create_plugin` scaffolds a Framer plugin project in the directory given by `outputPath`. The path is resolved with `path.resolve()` and used as-is: absolute paths and `../` sequences are accepted, and there is no base directory the result must stay under. The tool then creates that directory and writes five files into it, replacing any existing files with the same names. A caller can therefore create directories and overwrite `package.json`, `tsconfig.json`, `vite.config.ts` and other files in any location the server process can write to.

## Details
`src/index.ts:125-128` resolves the caller's path and creates it:

```ts
  private async handleCreatePlugin(args: CreatePluginArgs) {
    try {
      const pluginDir = path.resolve(args.outputPath);
      await fs.ensureDir(pluginDir);
```

The handler then writes, without checking whether the files already exist:

- `package.json` (`src/index.ts:163`, `fs.writeJSON`)
- `tsconfig.json` (`:187`) and `tsconfig.node.json` (`:201`)
- `vite.config.ts` (`:230`, `fs.writeFile`)
- `src/index.tsx` (`:327`)

`path.resolve()` only normalizes the path. Nothing compares the result against an allowed root, rejects absolute paths, or refuses to write into a directory that already holds a project. `build_plugin` (`src/index.ts:345-356`) has the same unrestricted `path.resolve(args.pluginPath)`.

## Steps to reproduce
1. Prerequisites: Node.js 16+ and npm. No accounts or API keys.
2. Install and build as the README describes, then start the server over stdio:

   ```bash
   git clone https://github.com/sheshiyer/framer-plugin-mcp.git
   cd framer-plugin-mcp
   npm install
   npm run build
   node build/index.js
   ```
3. Call the tool with these arguments. The relative `../` form shows the escape from the server's working directory; `/tmp/tofu-poc` as an absolute path has the same effect.

   ```json
   {"name": "tofu-poc", "description": "ToFu PoC", "outputPath": "../../../../../../../../tmp/tofu-poc", "web3Features": []}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/framer-plugin-mcp/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "create_plugin",
                   {"name": "tofu-poc", "description": "ToFu PoC",
                    "outputPath": "../../../../../../../../tmp/tofu-poc", "web3Features": []},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe: the tool answers `Successfully created Framer plugin project at /tmp/tofu-poc`, and `ls -R /tmp/tofu-poc` shows `package.json`, `tsconfig.json`, `tsconfig.node.json`, `vite.config.ts` and `src/index.tsx`, all outside the server's working directory. Clean up with `rm -rf /tmp/tofu-poc`.

## Expected behavior
The tool should only create projects under a configured base directory (for example the server's working directory or a `--root` option), and should refuse absolute paths or `..` segments that resolve outside it. It should also refuse, or ask before, overwriting an existing `package.json` or `vite.config.ts`.

## Actual behavior
Any resolvable path is accepted and the files are written there. From the fuzzing run, input `outputPath: "..\\..\\..\\..\\windows\\win.ini"` was accepted and returned:

```
Successfully created Framer plugin project at <server cwd>/..\..\..\..\windows\win.ini
```

On the Linux test host the backslashes are literal characters, so that call created a directory with that name inside the working directory. It shows the input is not validated at all, but it did not escape the directory. The escape in step 3 follows directly from `path.resolve()` with no root check.

## Impact
In MCP, tool arguments are chosen by the LLM, and prompt injection in web pages, documents or repositories the model reads can steer `outputPath`. An attacker who can do that can create directories and overwrite project files in any location the server user can write to, for example replacing another project's `package.json` or `vite.config.ts`. The `name` argument is also inserted unescaped into the generated `vite.config.ts` (`src/index.ts:213`) and `src/index.tsx` (`:242`, `:257`), so an overwritten `vite.config.ts` can contain caller-chosen JavaScript that runs the next time someone runs Vite in that directory. The write is limited to these fixed file names, which keeps this from being a fully arbitrary file write.

## Suggested fix
Resolve against a fixed base directory and reject anything that leaves it:

```ts
const baseDir = path.resolve(process.env.FRAMER_PLUGIN_ROOT ?? process.cwd());
const pluginDir = path.resolve(baseDir, args.outputPath);
const rel = path.relative(baseDir, pluginDir);
if (rel === '' || rel.startsWith('..') || path.isAbsolute(rel)) {
  throw new McpError(ErrorCode.InvalidParams, 'outputPath must stay inside the plugin root');
}
if (await fs.pathExists(path.join(pluginDir, 'package.json'))) {
  throw new McpError(ErrorCode.InvalidParams, 'refusing to overwrite an existing project');
}
```

Apply the same check to `pluginPath` in `build_plugin`. Separately, validate `name` (for example `/^[A-Za-z_][A-Za-z0-9_-]*$/`) before inserting it into generated source files.

## Status on the default branch
Still present at `5e17486` (2024-12-20). The tested commit is the current head of the default branch.

## Prior reports
- #4 "🔒 Correction des vulnérabilités de sécurité critiques - Path Traversal et Injection de commandes" (issue, open 2025-05-25): reports this bug (unsafe `path.resolve()` on user input at lines 128 and 163, no restriction on file paths) and proposes a `SecurityValidator.validatePath(args.outputPath, process.cwd())` base-directory check. It also reports the `execSync` build step. No fix: the default branch head `5e17486` (2024-12-20) predates it and no PR implements it.
- #3 "Add MseeP.ai badge to README" (PR, open 2025-04-25): an automated scan quoted in the body lists "Potential path traversal in fs module" at `src/index.ts` lines 128 and 163, the same code.
- Documentation: README.md: "outputPath: Output directory path" (the example uses `./plugins/my-web3-plugin`; no base directory or limit is documented)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported as #4 (open, unfixed; also flagged by the scan quoted in PR #3). Add the repro and the overwrite / `name` injection points to #4 instead of opening a new issue.
- ToFu class / sanitizers: `path-traversal` (CWE-22), fired by `check_path_traversal` ("Silent Bug Alert": the sanitizer flagged the input, the tool succeeded). Triggered list: `check_path_traversal`.
- Campaigns and executions: corpus-sbx: 2048 exec / 1904 ok (budget 60s); e2-0922: 2048 exec / 1947 ok (budget 60s).
- Evidence (verbatim, trimmed):
  - [corpus-sbx] input `{'name': 'SensitiveFileAccess', 'description': 'Trying to access win.ini', 'outputPath': '..\\..\\..\\..\\windows\\win.ini', 'web3Features': ['nft-display']}` -> `Successfully created Framer plugin project at /home/mza6485/toolfuzzer/eval/targets/Sheshiyer__framer-plugin-mcp/..\..\..\..\windows\win.ini`
  - [corpus-sbx] input `{'name': 'TestPlugin', 'description': 'Normal description', 'outputPath': '..?./.../../.', 'web3Features': []}` -> `Successfully created Framer plugin project at /home/mza6485/toolfuzzer/eval/targets/Sheshiyer__framer-plugin-mcp/..?.`
  - [corpus-sbx] input `{'name': 'TestPlugin', 'description': 'Normal description', 'outputPath': '..?./...../.', 'web3Features': []}` -> `Successfully created Framer plugin project at /home/mza6485/toolfuzzer/eval/targets/Sheshiyer__framer-plugin-mcp/..?./.....`
- Hand-check hints: real by code reading (`path.resolve(args.outputPath)` then `ensureDir` and five unconditional writes, no root check), but none of the three evidence calls actually left the target directory: the backslash path is a literal name on Linux, and `..?./.../../.` and `..?./...../.` normalize to subdirectories of cwd. I did not run the step 3 reproduction. A maintainer may argue that choosing any output path is intended; the overwrite of existing project files and the unescaped `name` in `vite.config.ts` are the strongest arguments that it needs a boundary.
- Side observations: `build_plugin` calls `require('child_process')` inside an ES module (`"type": "module"` in `package.json`), so it likely throws `require is not defined` and never runs `npm run build` (not verified). Code injection through `name` into generated files is a separate weakness (CWE-94) and could be its own issue.
- The public "Actual behavior" excerpt replaces the fuzzing host's home path with `<server cwd>`.
- Fuzzed commit `5e17486196e1fe334c79c45f52ff63a68c3da681`; `head_sha` is the same commit.

</details>
