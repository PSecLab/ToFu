# [Likely false positive, do not file as is] Path traversal check in `run_python_file`: scripts outside the working directory are already refused

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `run_python_file` · **Tested commit:** `84ac42d`
**Weakness:** CWE-22 Path Traversal (reported by the fuzzer; not confirmed)

## Summary
`run_python_file` runs a Python file in a subprocess. The fuzzer flagged it for path traversal, but no call log survived, and the code applies the same containment check as the other file tools before it runs anything. A path outside the working directory, whether absolute, built from `..`, or reached through a symlink, is refused. We found no way to run a script outside the working directory through this tool while `MCP_ALLOW_SYSTEM_ACCESS` is off.

## Details
`mcp_python_interpreter/server.py:643-650` and `:134-143` (tested commit):

```python
    path = Path(file_path)
    if not path.is_absolute():
        path = WORKING_DIR / path
    if not is_path_allowed(path):
        return f"Access denied: Can only run files in working directory: {WORKING_DIR}"

    if not path.exists():
        return f"File '{path}' not found."
...
def is_path_allowed(path: Path) -> bool:
    if ALLOW_SYSTEM_ACCESS:
        return True
    try:
        path.resolve().relative_to(WORKING_DIR.resolve())
        return True
    except ValueError:
        return False
```

The check runs before `path.exists()` and before the subprocess is built (`server.py:661-665`). `resolve()` collapses `..` and follows symlinks, so the containment test is sound.

## Steps to reproduce
1. Prerequisites: Python 3.10+. Leave `MCP_ALLOW_SYSTEM_ACCESS` unset. Create a harmless script outside the working directory: `echo 'print("tofu-poc")' > /tmp/tofu-poc.py`.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
3. Ask the server, started with `--dir /tmp/tofu-wd`, to run `../tofu-poc.py`:

   ```json
   {"file_path": "../tofu-poc.py", "environment": "system", "timeout": 10}
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
               result = await session.call_tool("run_python_file", {"file_path": "../tofu-poc.py", "environment": "system", "timeout": 10})
               print(result)

   asyncio.run(main())
   ```
4. Observe `Access denied: Can only run files in working directory: /tmp/tofu-wd`; `tofu-poc` is not printed.

## Expected behavior
Scripts outside the working directory are refused.

## Actual behavior
Based on the code, they are refused. No fuzzing log is available for this tool to show a different outcome.

## Impact
None found for this tool. The restriction does not limit `run_python_code`, which runs arbitrary code in the server process, so it should not be read as a sandbox.

## Suggested fix
No code change needed for `run_python_file`. Optionally, document that the working-directory restriction applies only to which file is started; the script itself runs with the user's full rights.

## Status on the default branch
Unchanged at `84ac42d` (2026-07-02); the check is in place. The tested commit is the current default branch head.

## Prior reports
- #10 "Security: Path Traversal bypass in file read operations" (issue, closed 2026-07-02): reports a `../` bypass of the same `is_path_allowed()` guard, but for `read_file` only; `run_python_file` is not mentioned. No linked fix PR. At `84ac42d` the guard resolves the path first.
- Documentation: README.md: "Isolated working directory" under "Security Considerations" (documents the restriction this check enforces).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `triggered` lists `check_path_traversal`, `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`.
- Campaigns and executions: e2-0922 1 exec / 0 ok (60 s budget). No other campaign ran this tool.
- Evidence: none. `log_available: false`, so no run log survived. The reproduction and the conclusion above come from reading the code only.
- Hand-check hints: false positive (counted as weak). With one execution and zero successes there is nothing behind the alert. The guard is the same correct `resolve()` + `relative_to` check used by `read_file`/`write_file`. Recommend not filing.
</details>
