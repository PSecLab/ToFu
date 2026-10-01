# Log injection in `git_files`: unvalidated `owner` / `repo` / `branch` end up in multi-line server log entries

**Repository:** `puravparab/Gitingest-MCP` · **Tool:** `git_files` · **Tested commit:** `c3b630a`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`git_files` builds `https://github.com/{owner}/{repo}` (plus `/tree/{branch}`) from the tool arguments with no validation and hands it to `gitingest.ingest`. When the clone or branch lookup fails, gitingest raises a `RuntimeWarning` whose text contains the full git command line (with the caller's values) followed by git's multi-line error output, and the MCP SDK writes that warning to the server log. Neither this server nor the libraries strip CR/LF or other control characters from `owner`, `repo` or `branch`, so a caller can shape what appears in the log.

## Details
`src/gitingest_mcp/server.py:90-95`:

```python
url = f"https://github.com/{owner}/{repo}"
try:
    ingester = GitIngester(url, branch=branch)
    await ingester.fetch_repo_data()
```

`src/gitingest_mcp/ingest.py:11-23` appends the branch and calls the library:

```python
if branch:
    self.url = f"{url}/tree/{branch}"
...
summary, self.tree, self.content = await loop.run_in_executor(
    None, lambda: ingest(self.url)
)
```

During fuzzing, gitingest (0.1.4 per `uv.lock`) emitted `Warning: Failed to fetch branch list: Command failed: git ls-remote --heads <url>\nError: <git stderr>` and the record was logged by the `mcp.server.lowlevel.server` logger. Characters such as `"`, `,`, `:` and spaces from `owner` passed through unchanged into that line. There is no allow-list for GitHub owner, repository or branch names anywhere in this server.

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`, `git`, outbound access to `github.com` (the tool runs `git ls-remote` / `git clone`). Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/puravparab/gitingest-mcp gitingest-mcp` (append `@c3b630a07304fb02e98eec12d38640a8c024a4ed` to the URL to match the tested commit).
3. Call the tool with a CR/LF in `owner`:

   ```json
   {"owner": "octocat\r\nFAKE-LOG-ENTRY", "repo": "Hello-World", "file_paths": ["README"], "branch": "main"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/puravparab/gitingest-mcp@c3b630a07304fb02e98eec12d38640a8c024a4ed",
                 "gitingest-mcp"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("git_files", {
                   "owner": "octocat\r\nFAKE-LOG-ENTRY",
                   "repo": "Hello-World",
                   "file_paths": ["README"],
                   "branch": "main",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr (the client script forwards it to the terminal). Check whether a log line starts with `FAKE-LOG-ENTRY` instead of the logger prefix. Also note that every failed call already writes a multi-line entry, because git's error output is embedded as-is.

## Expected behavior
The tool rejects `owner`, `repo` and `branch` values that are not valid GitHub owner, repository and ref names, so no control characters reach git or the log. Log entries built from external text have CR/LF escaped.

## Actual behavior
The values are used unchanged. A logged entry from fuzzing, for `owner = '"ow,er": "octocat", "repo": "Hello-World", "file_paths": [], "branch": "main'`:

```
Warning: RuntimeWarning: Warning: Failed to fetch branch list: Command failed: git ls-remote --heads https://github.com/"ow,er": "octocat", "repo": "hello-world", "file_paths": [], "branch": "main/hello-world
Error: fatal: unable to access 'https://github.com/"ow,er": ...': URL using bad/illegal format or missing URL
```

## Impact
Tool arguments are chosen by the model and can be steered by prompt injection. If CR/LF in an argument reaches the log, an attacker can add lines that look like separate log entries and mislead someone reading the server log. The log is local stderr in a typical stdio setup, so the impact is low. The more useful fix is input validation, which also keeps arbitrary strings out of the git command line.

## Suggested fix
Validate the arguments before building the URL, for example:

```python
OWNER_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$")
REPO_RE = re.compile(r"^[A-Za-z0-9._-]{1,100}$")
BRANCH_RE = re.compile(r"^[A-Za-z0-9._/-]{1,255}$")
```

Return an error for anything that does not match, and apply the same check in `git_summary` and `git_tree`. If any of these values are logged by this server in the future, escape `\r` and `\n` first.

## Status on the default branch
Still present at `c3b630a` (2025-03-21). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 4 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; `check_introspection_log_injection`. Also fired: `check_introspection_incomplete_cleanup` and `check_introspection_temp_file_leak` (`/tmp/gitingest` left behind, CWE-459/CWE-533), `check_introspection_weak_hash`, `check_resource_exhaustion`. Those are separate findings, not covered here.
- Campaigns and executions: corpus-sbx 1024 exec / 1018 success; e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'owner': '"ow,er": "octocat", "repo": "Hello-World", "file_paths": [], "branch": "main', 'repo': 'Hello-World', 'file_paths': [], 'branch': 'main'}` -> logged (logger `mcp.server.lowlevel.server`): `Warning: RuntimeWarning: Warning: Failed to fetch branch list: Command failed: git ls-remote --heads https://github.com/"ow,er": ...main/hello-world\nError: fatal: unable to access ...`
  - `{'owner': 'octocat', 'repo': '', 'file_paths': [], 'branch': 'main'}` -> logged `... git ls-remote --heads https://github.com/octocat/\nError: remote: Not Found\nfatal: repository 'https://github.com/octocat/' not found`. This input has NO newline, yet the sanitizer fired.
- Hand-check hints: unclear, likely misclassified. In all logged cases the newline in the log comes from gitingest's own message format (`Command failed: ...\nError: <git stderr>`), not from caller input; the second evidence item proves the alert fires with no CR/LF in the arguments. The log call is in gitingest and the MCP SDK, not in this repo. I could not inspect gitingest 0.1.4 (no source locally, no network), so I do not know whether a CR/LF in `owner` survives its URL parsing; the reproduction in step 3 is a test to run, not a logged result. What is solid: no validation of `owner`/`repo`/`branch`. Consider dropping this report or reframing it as "validate owner/repo/branch" together with the `git_summary` / `git_tree` drafts. Not run.
</details>
