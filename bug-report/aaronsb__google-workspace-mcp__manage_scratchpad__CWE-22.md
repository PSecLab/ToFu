# `manage_scratchpad`: a `drive` attachment's `fileId` becomes an unchecked local path when sent to `workspace`

**Repository:** `aaronsb/google-workspace-mcp` · **Tool:** `manage_scratchpad` · **Tested commit:** `ccdf507`
**Weakness:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Summary
`manage_scratchpad` lets a caller attach files to a buffer and later write the buffer and its attachments to the workspace directory. The `workspace` attachment source is contained correctly (see below). The `drive` source is not: the caller's `fileId` is stored unchanged as the attachment's file-system `location`, and the `send` → `workspace` adapter later copies that `location` with `fs.copyFile`. A `fileId` holding an absolute path or `..` segments is used as-is, so a file outside the workspace can be copied into it. This is a code-path gap found by reading the source; the fuzzing evidence does not demonstrate it (see Internal notes). Report it so a maintainer can confirm and close the gap.

## Details
`attach` for the `drive` source stores `fileId` directly, `src/server/scratchpad/handler.ts:549-554`:

```ts
} else {
  // Drive attachments — use fileId as identifier, metadata resolved later on send
  resolvedFilename = fileId ?? 'unknown';
  mimeType = 'application/octet-stream';
  size = 0;
  location = fileId ?? '';
}
```

The `workspace` source, by contrast, goes through `resolveWorkspacePath` + `verifyPathSafety` (lines 537-540), and `resolveWorkspacePath` (`src/executor/workspace.ts:161-175`) calls `sanitizePath`, which rejects `..` and `.` segments and strips separators. So the `workspace` source is contained.

On send to `workspace`, `src/server/scratchpad/adapters/send-workspace.ts:56-63` copies each attachment by its stored `location` with no containment check on the source:

```ts
for (const att of attachments.values()) {
  if (!att.location) continue;
  try {
    const destPath = path.join(targetDir, att.filename);
    if (path.resolve(att.location) !== path.resolve(destPath)) {
      await fs.copyFile(att.location, destPath);
    }
```

For a `drive` attachment, `att.location` is the caller's `fileId`. `att.filename` is also the `fileId`, which `path.join` would sanitize into the workspace, so the copy destination stays inside the workspace; the unchecked side is the copy source.

## Steps to reproduce
1. Prerequisites: Node.js 22.12+. No Google account is needed for the two calls below; the workspace write path runs without credentials. Point `XDG_CONFIG_HOME`/`XDG_DATA_HOME` at a temp directory.
2. Build the tested commit: `git clone https://github.com/aaronsb/google-workspace-mcp.git && cd google-workspace-mcp && git checkout ccdf507 && npm ci && npm run build`. Published form: `npx -y @aaronsb/google-workspace-mcp`.
3. Create a buffer, attach with a `drive` `fileId` set to a readable file outside the workspace, then send to `workspace`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["build/index.js"],
           env={"XDG_CONFIG_HOME": "/tmp/tofu-gws/config", "XDG_DATA_HOME": "/tmp/tofu-gws/data"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               c = await session.call_tool("manage_scratchpad", {"operation": "create", "content": "poc"})
               sid = ...  # read the scratchpad id from c
               await session.call_tool("manage_scratchpad", {
                   "operation": "attach", "scratchpadId": sid,
                   "source": "drive", "fileId": "/etc/hostname"})
               print(await session.call_tool("manage_scratchpad", {
                   "operation": "send", "scratchpadId": sid,
                   "target": "workspace", "targetParams": {"filename": "out.txt"}}))

   asyncio.run(main())
   ```
   `/etc/hostname` is used as a harmless stand-in for a file outside the workspace.
4. What to observe: whether a copy of the outside file appears in the workspace directory next to `out.txt`. If it does, the source path was not contained. If the copy is skipped or errors, the gap is not reachable this way; record that.

## Expected behavior
The copy source for every attachment stays inside the workspace, or a `drive` attachment is resolved through the Drive API by file ID rather than treated as a local path.

## Actual behavior
The `drive` branch stores the caller string as a local path and the send adapter copies from it with no containment check on the source. Not shown by the fuzzing evidence; see Internal notes.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. If the copy source is reachable, a file outside the workspace could be copied into the workspace, where other tools can read it back. The effect is bounded by the server process's own file permissions. The `workspace` attachment source does not have this gap.

## Suggested fix
Resolve `drive` attachments through the Drive API using the file ID, not as a path. If a `drive` attachment's `location` is ever read from disk, pass it through `resolveWorkspacePath` + `verifyPathSafety` first, the same as the `workspace` source, and skip any source that resolves outside the workspace.

## Status on the default branch
Still present at `14c25e6` (2026-10-01). `src/server/scratchpad/handler.ts` and `src/server/scratchpad/adapters/send-workspace.ts` are unchanged between `ccdf507` and `14c25e6`.

## Prior reports
- #146 "fix: workspace-relative uploads, and confirmations that say what they acted on" (PR, closed 2026-07-12): made relative `manage_drive upload` paths workspace-relative but kept absolute ones on purpose ("Absolute paths are untouched, so uploads from outside the workspace keep working"). This is still so at `14c25e6` (`src/services/drive/patch.ts:125`). Reading a local file outside the workspace is therefore already intended for `upload`, which weakens this report. It does not touch the scratchpad.
- #183 "Spotlighting only wraps Gmail HTML ..." (issue, open 2026-08-17): mentions a fork commit "Add prompt injection boundaries and restrict upload paths", so outside-workspace upload paths have been questioned before. Not about the scratchpad; no fix.
- #171 "manage_scratchpad writes to Google without going through the safety-policy layer" (issue, closed 2026-08-17) and #173 "fix(scratchpad): route its Google writes through the safety layer (#171)" (PR, closed 2026-08-17): a security fix to the same `handleSend` path. #173 leaves the `workspace` target out on purpose because "it writes a local file and touches no Google API". It does not look at attachment sources, so it does not fix this.
- Documentation: docs/architecture/api/ADR-301-scratchpad-buffer-for-service-agnostic-content-authoring.md: "location: string; // workspace file path or Drive fileId" (by design a `drive` attachment's `location` is a Drive file ID, not a local path; copying it with `fs.copyFile` is not documented behaviour).
- Documentation: SECURITY.md: "**DO NOT** open a public issue on GitHub" (security reports go by email to aaronsb@gmail.com; affects how this is filed).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_invalid_json`, `check_path_traversal`, `check_reflected_output`, `check_strict_markitdown_security_contract`.
- Campaigns and executions: `corpus-sbx` 1,536/1,536 and `e2-0922` 1,536/1,536, 60 s each.
- Evidence (verbatim, trimmed): all three rows are `operation: attach`, `source: workspace`, `filename: '../../../../etc/passwd'`, `scratchpadId: sp-1234/sp-1235` -> output `Scratchpad sp-1234 not found or expired. Use create to start a new one.` ToFu's "MarkItDown Security Bypass" / "Silent Bug" text refers to the URI `workspace`.
- Hand-check hints: unclear, leaning weak. The evidence does NOT show traversal: every row failed at `requireScratchpadId` because `sp-1234`/`sp-1235` were never created, so no file op ran. The `workspace` source is contained by `sanitizePath` (rejects `..`), so the `../../../../etc/passwd` payload would have been neutralized even with a valid scratchpad. The one genuine code gap I found is the `drive`-source `fileId` → `location` → `fs.copyFile` source path (handler.ts:549-554 + send-workspace.ts:56-63), which has no containment check; it is not exercised by any evidence row and needs a valid scratchpad plus a readable source file to confirm. Hand-verify before filing; if the drive-copy gap does not reproduce, this item is a false positive.
</details>
