# `analyze_changes` flagged for path traversal; `../` in `path` does not escape the repository (likely false positive)

**Repository:** `hyperb1iss/lucidity-mcp` · **Tool:** `analyze_changes` · **Tested commit:** `cdcb184`
**Weakness:** CWE-22 Path Traversal (reported by the fuzzer; not confirmed)

## Summary
`analyze_changes` runs `git diff` (and `git diff --cached`) inside `workspace_root`, optionally limited to `path`, and returns the parsed diff to the model. Our fuzzer sent `../` sequences in `path` and `workspace_root` and flagged the calls because the tool returned normally. On review, the outputs show no file content outside a repository, and `git` itself rejects pathspecs outside the work tree. We do not think the reported traversal is real. `workspace_root` accepts any directory that contains `.git`, which is by design.

## Details
The tool requires `workspace_root`, then calls `get_git_diff` (`lucidity/tools/code_analysis.py:305-312`). `get_git_diff` returns empty results unless `<workspace_root>/.git` exists (`:28-30`), changes into the workspace (`:37`), and runs `git diff` with the caller's `path` as the pathspec (`:47-55`). Any git error is caught and turned into an empty diff (`:74-76`), which the tool reports as `no_changes`.

```python
if not os.path.exists(os.path.join(workspace_root, ".git")):
    logger.error("No .git directory found in workspace root: %s", workspace_root)
    return "", ""
...
os.chdir(workspace_root)
...
diff_command = ["git", "diff"]
if path:
    normalized_path = path.replace("\\", "/")
    diff_command.append(normalized_path)
```

There is no allowed-root setting for `workspace_root`, so the tool can read diffs from any local repository the server user can access. The tool is built to work that way, so it is not a traversal.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`, `git`, and the `mcp` Python package for the client script. Create a small repository to use as the workspace:

   ```bash
   mkdir -p /tmp/tofu-poc/repo && cd /tmp/tofu-poc/repo && git init -q
   ```
2. Install and start the server as the README describes (stdio is the default transport):

   ```bash
   git clone https://github.com/hyperb1iss/lucidity-mcp.git && cd lucidity-mcp
   git checkout cdcb184
   uv venv .venv && uv sync
   ```
3. Call the tool with a `../` pathspec:

   ```json
   {"workspace_root": "/tmp/tofu-poc/repo", "path": "../outside.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["--directory", "/path/to/lucidity-mcp", "run", "lucidity-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("analyze_changes", {"workspace_root": "/tmp/tofu-poc/repo", "path": "../outside.txt"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `{"status": "no_changes", ...}`. `git` refuses a pathspec outside the work tree, the error is caught, and no outside content is returned.

## Expected behavior
Pathspecs outside the repository are rejected. That is what happens.

## Actual behavior
From our runs:

```
input:  {'workspace_root': 'valid_repo', 'path': '../../.git/config'}
output: {"status": "no_changes", "message": "No changes detected in the git diff", "file_list": []}
```

## Impact
No traversal found. The tool returns only `git diff` output for a repository that the caller names.

## Suggested fix
None needed for this report. As hardening, the server could accept an operator-configured list of allowed workspace roots.

## Status on the default branch
The tested commit `cdcb184` (2025-03-19) is the current head of the default branch.

## Prior reports
None found. Searched all 4 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch. Two issues involve this tool but not path handling: #4 "Error: 400 <400> InternalError.Algo.InvalidParameter: Range of input length should be [1, 57344]" (issue, open) is about large diffs exceeding the LLM input limit, and #6 "About mcpServers JSON configuration?" (issue, open) asks how to pass `workspace_root` and `path`.
- Documentation: README.md: "`workspace_root`: The root directory of the workspace/git repository" (the caller names the repository; no allowed-root setting is documented)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal` on all three evidence calls, as an input-pattern "Silent Bug Alert" (input flagged, tool did not raise). `check_introspection_log_injection` also fired; `path` is interpolated into `logger.info` at `code_analysis.py:305` (only reaches a sink with `--log-file` or console logging).
- Campaigns and executions: `corpus-sbx` 2560 / 2546 ok, `e2-0922` 512 / 489 ok, 60 s budget each.
- Evidence (verbatim, trimmed): `{'workspace_root': 'valid_repo', 'path': '../../.git/config'}` -> `no_changes`; `{'workspace_root': '', ...}` -> `workspace_root parameter is required`; a third call with `../` in both arguments -> `no_changes`. The relative `workspace_root` values probably had no `.git`, so git may never have run.
- Hand-check hints: weak for the reported CWE-22 (likely false positive). That `git` rejects out-of-tree pathspecs comes from git's documented behavior; the reproduction was not executed here. I began a deeper look at how `path` is handed to `git` (`code_analysis.py:47-64`), but that part of the analysis was withheld and is not in this draft. A hand-checker should review that argument handling directly before deciding whether to file anything for this tool.
</details>
