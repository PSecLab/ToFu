# newtype-01/obsidian-mcp — `manage_folder`: path traversal escapes the vault (CWE-22, live-demonstrated destructive)

- **Project**: newtype-01/obsidian-mcp (node)
- **Tools**: `manage_folder` (create/rename/delete), and the whole file family — `update_file`, `create_note`, `delete_note`, `move_note` — all build `path.join(VAULT_PATH, callerPath)` with **no containment check**
- **Class**: unrestricted filesystem write/rename/delete outside the intended vault root
- **Status**: POTENTIAL, **DEMONSTRATED LIVE** (twice)
- **Severity**: Critical — an MCP client (or adversarial content steering one) can create/rename/delete any path the server's user can write

## Summary
Every path-bearing tool resolves the caller's string with `path.join(VAULT_PATH, x)`
and calls `fs.mkdirSync` / `fs.renameSync` / `fs.unlinkSync` on the result. A
`../../...` argument walks out of `VAULT_PATH` to anywhere the process can reach.
There is no `path.resolve` + prefix check, no realpath confinement, no rejection
of `..`.

## How we know it's real (not a static guess)
On 2026-09-24 this tool **twice removed files from the ToFu evaluation host**
during the `repo24` deep campaign. Running without a filesystem sandbox (cwd
isolation only), a fuzzed `manage_folder` folder path resolved out of the target's
scratch dir into the harness tree and deleted `eval/configs/` (6,231 generated
configs), `eval/runs/`, and 36 tracked repo files; every subsequent slice failed
with FileNotFoundError and the campaign died. The run index shows the tool active
in the exact window the `eval/` directory mtime changed (15:44:59). That is a
runtime proof of unconfined deletion, on a real host, from fuzz input alone.

## Affected code (eval/targets/newtype-01__obsidian-mcp/src/index.ts)
```ts
// every path tool, same shape:
const fullPath = path.join(VAULT_PATH, folderPath);   // no containment
fs.mkdirSync(fullPath, { recursive: true });          // or renameSync / unlinkSync
```

## Why this matters for MCP
A notes/vault MCP server that joins caller paths without confinement is an
arbitrary-filesystem-write/delete primitive for any agent steered by untrusted
content — the same shape as UltimateCoderMCP (arbitrary delete) and
DesktopCommander (full-access default). The same tool that erased our harness
erases a user's home directory.

## Suggested fix (maintainer)
Resolve with `path.resolve(VAULT_PATH, x)`, then reject unless the result is
`=== VAULT_PATH` or starts with `VAULT_PATH + path.sep`; realpath-check existing
ancestors; reject `..` segments and null bytes.

## Note for ToFu (bubblewrap sandbox, 2026-09-24)
run_eval now supports TOFU_SANDBOX=bwrap: each fuzzer runs with / read-only and
only its own scratch/corpus/metrics/seeds/llm_cache/target dirs writable, so a
traversal like this one lands in scratch, never the harness. Verified: this exact
tool ran 1,536 execs sandboxed (123 successes, 10 alerts) with eval/configs and a
canary file outside the sandbox untouched. cwd isolation (item 91) was necessary
but not sufficient; the sandbox is the containment.
