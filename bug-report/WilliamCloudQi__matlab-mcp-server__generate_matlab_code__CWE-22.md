# Path traversal in `generate_matlab_code`: `scriptPath` writes the generated file anywhere on disk

**Repository:** `WilliamCloudQi/matlab-mcp-server` · **Tool:** `generate_matlab_code` · **Tested commit:** `ab88f6b`
**Weakness:** CWE-22 Path Traversal

## Summary
`generate_matlab_code` turns a description into a MATLAB template and, with `saveScript: true`, writes it to `scriptPath`. `scriptPath` goes straight to `fs.writeFileSync` with no check, so `../` sequences or an absolute path create or overwrite any file the server process can write. The caller's `description` is copied into the file, including any newlines, so the caller also controls whole lines of the content. MATLAB does not need to be installed for this tool to write the file.

## Details
`src/index.ts:403-425` at `ab88f6b`:

```ts
        case 'generate_matlab_code': {
          const description = String(request.params.arguments?.description || '');
          const saveScript = Boolean(request.params.arguments?.saveScript || false);
          const scriptPath = request.params.arguments?.scriptPath as string | undefined;
          ...
            const generatedCode = this.matlabHandler.generateCode(description);
            ...
            if (saveScript) {
              const targetPath = scriptPath || path.join(process.cwd(), `matlab_generated_${Date.now()}.m`);
              fs.writeFileSync(targetPath, generatedCode);
              responseText += `\n\nGenerated MATLAB script saved to: ${targetPath}`;
            }
```

There is no base directory, no `path.resolve` plus containment check, no extension check and no "do not overwrite" flag. Relative paths resolve against the server's working directory. `generateCode()` (lines 118-140) interpolates `description` into the template three times. The MATLAB availability check at lines 341-355 only blocks `execute_matlab_code`, so this tool writes the file even when MATLAB is missing.

`execute_matlab_code` has the same pattern: `fs.copyFileSync(tempFile, targetPath)` with the caller's `scriptPath` at lines 83-86.

## Steps to reproduce
1. Prerequisites: Node.js. MATLAB is not required for this tool.
2. Install and build as the README describes: `git clone https://github.com/WilliamCloudQi/matlab-mcp-server && cd matlab-mcp-server && git checkout ab88f6b && npm install && npm run build`, then run `node build/index.js`.
3. Call the tool with `{"description": "tofu poc", "saveScript": true, "scriptPath": "../../../../../../../../tmp/tofu-poc.txt"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/matlab-mcp-server/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "generate_matlab_code",
                   {
                       "description": "tofu poc",
                       "saveScript": True,
                       "scriptPath": "../../../../../../../../tmp/tofu-poc.txt",
                   },
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc.txt` now exists and starts with `% MATLAB code generated from description: tofu poc`, and that the result ends with `Generated MATLAB script saved to: ../../../../../../../../tmp/tofu-poc.txt`. An absolute `scriptPath` such as `/tmp/tofu-poc.txt` works the same way.

## Expected behavior
Generated scripts are written only inside a configured output directory (for example the server's working directory or a `MATLAB_SCRIPTS_DIR`). A `scriptPath` that resolves outside it, or that is not a `.m` file, is rejected.

## Actual behavior
The file is written wherever `scriptPath` points. In the fuzz run the tool accepted `..\..\..\..\windows\win.ini` and reported:

```
Generated MATLAB script saved to: ..\..\..\..\windows\win.ini
```

## Impact
`scriptPath` and `description` are chosen by the LLM, which can be steered by prompt injection from untrusted content (a file, a web page, a dataset description). With this tool an attacker can create or overwrite any file the user running the server can write, with lines they choose. Examples are shell startup files or other tools' config files, which can lead to code execution the next time they are loaded. The leading `%` comment lines limit what file formats stay valid, but many formats (shell scripts among them) tolerate a broken first line.

## Suggested fix
Resolve the path against a fixed base directory and reject anything that escapes it:

```ts
const baseDir = path.resolve(process.env.MATLAB_SCRIPTS_DIR || process.cwd());
const target = path.resolve(baseDir, scriptPath || `matlab_generated_${Date.now()}.m`);
const rel = path.relative(baseDir, target);
if (rel.startsWith('..') || path.isAbsolute(rel) || path.extname(target) !== '.m') {
  throw new McpError(ErrorCode.InvalidParams, 'scriptPath must be a .m file inside the scripts directory');
}
fs.writeFileSync(target, generatedCode, { flag: 'wx' });
```

Apply the same check to `execute_matlab_code` (lines 83-86). Using `fs.realpathSync` on the parent directory also covers symlinks that point outside the base. `flag: 'wx'` refuses to overwrite an existing file.

## Status on the default branch
Still present at `ab88f6b` (2025-05-18). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR found. Searched the 1 issue and 4 pull requests (fetched 2026-10-01). The only security-flavoured item, #3 "Add MseeP.ai badge to README" (PR, closed 2025-05-18), is a badge PR whose scan summary lists `child_process.exec()` findings in the vendored `node-matlab`, not `scriptPath`.
- Documentation: README.md describes `generate_matlab_code` with "Option to save generated scripts" (and `execute_matlab_code` with "Option to save scripts for future reference"). Neither README.md nor llms-install.md says where scripts may be saved or warns about `scriptPath`. No SECURITY.md or `docs/`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Fired: `check_path_traversal` (also `check_reflected_output` for the tool).
- Campaigns and executions: `corpus-sbx`: 2048 execs, 1497 success, 60 s budget; `e2-0922`: 1024 execs, 729 success, 60 s budget.
- Evidence (verbatim, trimmed): (1) input `{'description': 'Generate code to open and read the file ../../../../etc/shadow', 'saveScript': False, 'scriptPath': '../../../../../tmp/evil.m'}`, output text starts `Generated MATLAB code for: "Generate code to open and read the file ../../../../etc/shadow"` (no save, `saveScript` false). (2) input `{'description': 'Write a script that lists all files in the parent directory', 'saveScript': True, 'scriptPath': '..\\..\\..\\..\\windows\\win.ini'}`, output ends `Generated MATLAB script saved to: ..\..\..\..\windows\win.ini`. Analysis for both: "Silent Bug Alert: Sanitizers ['check_path_traversal'] flagged this input as malicious, but the target tool executed successfully without raising any exception."
- Hand-check hints: **real.** `scriptPath` reaches `fs.writeFileSync` unchecked (`src/index.ts:421-424`). Caveat on the evidence: assuming row (2) ran on a Linux fuzz host (I did not confirm the OS from the log), backslashes are ordinary filename characters there, so it created a file literally named `..\..\..\..\windows\win.ini` in the cwd, not an escape. Row (1) did not save. The POSIX `../` escape in the repro is derived from the code, not observed in the log. Maintainer may argue a "custom path" is a feature; the draft's case is that in MCP the path is LLM-chosen and needs containment. The `build/` dir is gitignored; the repo ships `build_files/index.js` with the same code (`build_files/index.js:348-349`).
</details>
