# Path traversal in `git_read_important_files`: `file_paths` entries are joined to the repo root with no containment

**Repository:** `adhikasp/mcp-git-ingest` · **Tool:** `git_read_important_files` · **Tested commit:** `cd392d5`
**Weakness:** CWE-22 Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')

## Summary
`git_read_important_files` clones a repository and reads the files named in `file_paths`, returning their contents. Each entry is joined to the clone directory with `os.path.join` and opened, with no check that the result stays inside the clone. An entry containing `..` or an absolute path resolves outside the clone, so the tool returns the contents of a file elsewhere on the server. Report so a maintainer can add containment. (The same tool also inherits the unrestricted-clone SSRF gap of `clone_repo`, reported under `git_directory_structure`.)

## Details
`src/mcp_git_ingest/main.py:90-125`:

```python
def git_read_important_files(repo_url: str, file_paths: List[str]) -> dict[str, str]:
    try:
        repo_path = clone_repo(repo_url)
        results = {}
        for file_path in file_paths:
            full_path = os.path.join(repo_path, file_path)
            if not os.path.isfile(full_path):
                results[file_path] = f"Error: File not found"
                continue
            try:
                with open(full_path, 'r', encoding='utf-8') as f:
                    results[file_path] = f.read()
```

`os.path.join(repo_path, file_path)` with `file_path = "../../../../etc/hostname"` resolves above `repo_path`; with an absolute `file_path` it discards `repo_path` entirely. The opened path is never checked against `repo_path`.

## Steps to reproduce
1. Prerequisites: Python 3.8+, `git` on PATH. Needs a cloneable `repo_url` (any small public repo works).
2. Install and start as the README describes: `uvx --from git+https://github.com/adhikasp/mcp-git-ingest mcp-git-ingest`.
3. Call the tool with a benign `repo_url` and a traversal entry in `file_paths`:

   ```json
   {"repo_url": "https://github.com/adhikasp/mcp-git-ingest", "file_paths": ["README.md", "../../../../etc/hostname"]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/adhikasp/mcp-git-ingest", "mcp-git-ingest"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("git_read_important_files", {
                   "repo_url": "https://github.com/adhikasp/mcp-git-ingest",
                   "file_paths": ["README.md", "../../../../etc/hostname"],
               })
               print(result)

   asyncio.run(main())
   ```
   `/etc/hostname` is a harmless stand-in for a file outside the clone.
4. What to observe: the returned dict maps `"../../../../etc/hostname"` to the contents of that file (the host's name), confirming the read escaped the clone directory.

## Expected behavior
Each `file_path` is resolved and rejected unless it stays inside the clone directory, for example by comparing `os.path.realpath(full_path)` against `os.path.realpath(repo_path)`.

## Actual behavior
The joined path is opened without a containment check. The fuzzing evidence does not show the escape: its one row used a benign `file_paths: ["README.md"]` and a `file:///etc/passwd` `repo_url` that failed to clone, so no file was read. The gap is visible in the code and in step 4.

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. A crafted `file_paths` entry makes the tool return the contents of a file outside the cloned repository, bounded by the server process's file permissions. The caller controls which path is read.

## Suggested fix
After `full_path = os.path.join(repo_path, file_path)`, compute `real = os.path.realpath(full_path)` and skip the entry unless `real == repo_root or real.startswith(repo_root + os.sep)` where `repo_root = os.path.realpath(repo_path)`. Reject absolute `file_path` values up front.

## Status on the default branch
Still present at `cd392d5` (2025-01-26). This is the tested commit and the current default-branch head; the function is unchanged.

## Prior reports
None found. Searched all 7 issues and 8 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README only describes the server as reading "GitHub repository structure and important files"; it has no security notes and no setting that limits clone targets or file paths.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: `corpus-sbx` 1,536/1,532 and `e2-0922` 1,024/972, 60 s each.
- Evidence (verbatim, trimmed): `{'repo_url': 'file:///etc/passwd', 'file_paths': ['README.md']}` -> `{"error": "Failed to process repository: Failed to clone repository: ... fatal: invalid gitfile format: /etc/passwd ..."}`. ToFu flags a "silent bug" (check_path_traversal fired, tool returned an error string).
- Hand-check hints: real code gap, evidence weak. The `os.path.join(repo_path, file_path)` with no realpath containment is a clear traversal in the file-read loop, but the single evidence row never reached the loop because the clone failed. To confirm, a cloneable repo_url is required (step 3 uses the repo's own URL). Also note the clone step shares the unrestricted-URL SSRF gap with `git_directory_structure`.
</details>
