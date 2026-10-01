# Path traversal in `store_project_data`: reported by fuzzing, but `project_path` is never used as a file path (unconfirmed)

**Repository:** `revit-mcp/revit-mcp` · **Tool:** `store_project_data` · **Tested commit:** `c9ef49e`
**Weakness:** CWE-22 Path Traversal

## Summary
`store_project_data` saves Revit project metadata, including an optional `project_path` string, into the local SQLite database `revit-data.db`. A fuzzing run flagged it because values such as `../../../../<file>` in `project_path` were accepted without error. On reading the code at the tested commit, `project_path` is only stored as text through a parameterized SQL statement and echoed back; no file operation uses it. This draft records what was checked; as it stands it does not describe a vulnerability.

## Details
`src/tools/store_project_data.ts:11` and `:19-22` at `c9ef49e`:

```ts
      project_path: z.string().optional().describe("File path to the project"),
      ...
    async (args: any) => {
      try {
        const projectId = storeProject(args);
        const project = getProjectByName(args.project_name);
```

`storeProject` (`src/database/service.ts:30-85`) binds every field as a parameter:

```ts
    const result = db.prepare(`
      INSERT INTO projects (
        project_name, project_path, project_number, project_address,
        client_name, project_status, author, timestamp, last_updated, metadata
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      data.project_name,
      data.project_path || null,
```

The only `fs` use in `src/` is `fs.readdirSync(__dirname)` in `src/tools/register.ts:12`, which lists the tool modules. `project_path` is not sent to the Revit add-in either. It is read back only through the `getProject*` helpers in `service.ts`, which `query_stored_data` uses to return projects and `store_room_data` uses to look up a project by name.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and a C/C++ toolchain for `better-sqlite3`. Revit is not needed for this tool. Create a marker file outside the repository:
   ```
   mkdir -p /tmp/tofu-poc && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install and build the server as the README describes:
   ```
   git clone https://github.com/revit-mcp/revit-mcp.git
   cd revit-mcp && git checkout c9ef49e4c397298d291304f822b89ba3a102e6bf
   npm install && npm run build
   ```
   The client script below starts it with `node build/index.js` from the repository directory.
3. Call the tool with these arguments:
   ```json
   {"project_name": "tofu-poc", "project_path": "../../../../../../tmp/tofu-poc/outside.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("store_project_data", {"project_name": "tofu-poc", "project_path": "../../../../../../tmp/tofu-poc/outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: based on the code, the result is `"success": true` with `"project_path": "../../../../../../tmp/tofu-poc/outside.txt"` stored as a string, and `/tmp/tofu-poc/outside.txt` still contains `marker` with an unchanged modification time. This was not run.

## Expected behavior
A path-like argument that the server does not open needs no containment. If a later version opens `project_path`, it should be resolved and checked against an allowed root first.

## Actual behavior
By code reading, the value is stored and echoed only. The fuzzer's alert came from an input-side pattern check (`../` in the argument plus a successful call), not from an observed file access.

## Impact
None found at this commit. The stored string is returned to whatever client calls `query_stored_data`; a consumer that later trusts it as a file path would need its own validation.

## Suggested fix
No change is needed for path traversal as the code stands. Optionally, if `project_path` is meant to be a real Revit file path, validate its shape (for example require an absolute path ending in `.rvt`) before storing it, so bad data does not accumulate in `revit-data.db`.

## Status on the default branch
Unchanged at `c9ef49e` (2026-02-25). The tested commit is the head of the default branch. The README at that commit says the repository is being archived in favour of `mcp-servers-for-revit/mcp-servers-for-revit`.

## Prior reports
- No issue or PR reports this. Searched all 11 issues and 22 pull requests (fetched 2026-10-01); none mentions `project_path`, `store_project_data`, path traversal or SQL handling.
- #31 "Claude/check sqlite implementation 011 cuyx ghmvb ex vw5 mnsy4 nr" (PR, closed 2025-11-10): empty body; by its title it concerns the SQLite storage that `store_project_data` writes to. It describes no path handling.
- #22 "Add MseeP.ai badge" (PR, closed 2025-05-15; its badge is on the README): third-party badge PR reporting an automated scan score of 100/100 with no findings listed; not related.
- Documentation: README.md: "| store_project_data | Store project metadata in local database |" (documents a metadata store, consistent with `project_path` being stored as text only). README.md also carries a deprecation notice: "this repo is being archived in favour of the mono repo".

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`; `check_log_injection` and `check_reflected_output` also fired per `triggered`. In `src/sanitizers/base.py:4-7`, `check_path_traversal` returns true whenever the input contains `../`, `..\` or a well-known system file name; it does not observe a file operation. The alert text is "Silent Bug Alert: Sanitizers ['check_path_traversal'] flagged this input as malicious, but the target tool executed successfully".
- Campaigns and executions: corpus-sbx 2,048 exec / 2,046 ok (60 s); repo24 103,936 / 103,928 (4,200 s); e2-0922 1,024 / 1,022 (60 s).
- Evidence (verbatim, trimmed): input `{'project_name': "'; DROP TABLE users; --", 'project_path': <../../../../ + a system file>, 'project_number': "1' OR '1'='1", ...}` -> `{"success": true, "message": "Project data stored successfully", "project_id": 6, "project": {... "project_path": <same string>, ...}}`. Second row: a `..\..\..\..\` Windows-style path, also stored and echoed. The SQL-looking values were stored literally, which confirms the statements are parameterized.
- Hand-check hints: weak, almost certainly a false positive. `project_path` never reaches `fs` or the Revit socket at this commit. The repo is deprecated in favour of `mcp-servers-for-revit`, which was not checked. I would not file this. The reproduction is derived from the code, not from a logged run that inspected the marker file.
</details>
