# [Likely false positive, do not file as is] Path traversal check in `list_directory`: `..` and absolute paths are already rejected

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `list_directory` · **Tested commit:** `84ac42d`
**Weakness:** CWE-22 Path Traversal (reported by the fuzzer; not confirmed)

## Summary
`list_directory` lists `.py` files under a directory. The fuzzer flagged it because traversal strings such as `../../../` were accepted as input without an exception. Reading the code and the actual replies shows the tool refuses them: every traversal attempt returned "Access denied". We found no way out of the working directory through this tool while `MCP_ALLOW_SYSTEM_ACCESS` is off.

## Details
`mcp_python_interpreter/server.py:134-143` and `:811-819` (tested commit):

```python
def is_path_allowed(path: Path) -> bool:
    if ALLOW_SYSTEM_ACCESS:
        return True
    try:
        path.resolve().relative_to(WORKING_DIR.resolve())
        return True
    except ValueError:
        return False
...
            path = Path(directory_path)
            if not path.is_absolute():
                path = WORKING_DIR / directory_path
            if not is_path_allowed(path):
                return f"Access denied: Can only list files in working directory: {WORKING_DIR}"
```

`resolve()` normalizes `..` and follows symlinks before the `relative_to` check, so `../`, absolute paths and symlinks that point outside the working directory are all refused. The walk itself (`find_python_files`, `rglob("*.py")`) starts from the checked path.

## Steps to reproduce
1. Prerequisites: Python 3.10+. Leave `MCP_ALLOW_SYSTEM_ACCESS` unset.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
3. Call the tool with a traversal path:

   ```json
   {"directory_path": "../../../tmp"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-python-interpreter", args=["--dir", "/tmp/tofu-wd"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("list_directory", {"directory_path": "../../../tmp"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `Access denied: Can only list files in working directory: /tmp/tofu-wd`.

## Expected behavior
Paths outside the working directory are refused.

## Actual behavior
They are refused. From the fuzzing run (working directory shortened):

```
{'directory_path': '../../../'}        -> Access denied: Can only list files in working directory: <wd>
{'directory_path': '../../../tmp'}     -> Access denied: Can only list files in working directory: <wd>
{'directory_path': '/etc/passwd\x00'}  -> Access denied: Can only list files in working directory: <wd>
```

## Impact
None found for this tool. The working-directory restriction is not a security boundary for the server as a whole, because `run_python_code` runs arbitrary code in the server process with no path restriction. That is a separate, documentation-level point.

## Suggested fix
No code change needed for `list_directory`. Optionally, state in the README's "Security Considerations" that the working-directory restriction applies to the file tools only and that `run_python_code` / `run_python_file` run with the full rights of the user.

## Status on the default branch
Unchanged at `84ac42d` (2026-07-02); the check is in place. The tested commit is the current default branch head.

## Prior reports
- #10 "Security: Path Traversal bypass in file read operations" (issue, closed 2026-07-02): reports a `../` bypass of the same `is_path_allowed()` guard, but for `read_file` only; `list_directory` is not mentioned. No linked fix PR. At `84ac42d` the guard resolves the path first.
- Documentation: README.md: "Strict file path security (only within the working directory)" (documents the restriction this check enforces).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (input-pattern "silent bug" alert), plus `check_reflected_output` on this tool.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed): the three calls in "Actual behavior"; all returned `Access denied: Can only list files in working directory: /home/mza6485/.tofu_scratch/yzfly__mcp-python-interpreter__list_directory`.
- Hand-check hints: false positive (counted as weak). `check_path_traversal` matched the input string; the tool returned a refusal, not an exception, so ToFu called it a silent bug. The guard (`resolve()` + `relative_to`) is correct. Recommend not filing. The only related real issue in this server is `run_python_code(save_as=...)` skipping the guard; see the `write_file` draft.
</details>
