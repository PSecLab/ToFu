# [Likely false positive, do not file as is] Path traversal check in `read_file`: `..` and absolute paths are already rejected

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `read_file` · **Tested commit:** `84ac42d`
**Weakness:** CWE-22 Path Traversal (reported by the fuzzer; not confirmed)

## Summary
`read_file` returns the content of a file. The fuzzer flagged it because traversal strings like `../../../../etc/passwd` were accepted as input without an exception. The tool actually refused every one of them with "Access denied", or looked the name up inside the working directory and found nothing. We found no read outside the working directory through this tool while `MCP_ALLOW_SYSTEM_ACCESS` is off.

## Details
`mcp_python_interpreter/server.py:134-143` and `:730-734` (tested commit):

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
    path = Path(file_path)
    if not path.is_absolute():
        path = WORKING_DIR / path
    if not is_path_allowed(path):
        return f"Access denied: Can only read files in working directory: {WORKING_DIR}"
```

`resolve()` collapses `..` and follows symlinks before the containment check, so absolute paths, `../` sequences and symlinks inside the working directory that point elsewhere are all refused. The Windows-style payload `..\..\..\..\windows\win.ini` is a single file name on Linux, so it was looked up inside the working directory and reported as not found.

## Steps to reproduce
1. Prerequisites: Python 3.10+. Leave `MCP_ALLOW_SYSTEM_ACCESS` unset.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
3. Call the tool with a traversal path:

   ```json
   {"file_path": "../../../../etc/hostname", "max_size_kb": 16}
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
               result = await session.call_tool("read_file", {"file_path": "../../../../etc/hostname", "max_size_kb": 16})
               print(result)

   asyncio.run(main())
   ```
4. Observe `Access denied: Can only read files in working directory: /tmp/tofu-wd`.

## Expected behavior
Files outside the working directory are refused.

## Actual behavior
They are refused. From the fuzzing run (working directory shortened):

```
{'file_path': '/etc/passwd\x00', 'max_size_kb': 0}                   -> Access denied: Can only read files in working directory: <wd>
{'file_path': '../../../../etc/passwd', 'max_size_kb': 1024}         -> Access denied: Can only read files in working directory: <wd>
{'file_path': '..\\..\\..\\..\\windows\\win.ini', 'max_size_kb': 2048} -> Error: File '..\..\..\..\windows\win.ini' not found
```

## Impact
None found for this tool. Note that the README presents the working directory as an isolation feature, while `run_python_code` executes arbitrary code in the server process with no path restriction, so the restriction protects only against misuse of the file tools.

## Suggested fix
No code change needed for `read_file`. Optionally, document in "Security Considerations" that `run_python_code` and `run_python_file` are not restricted to the working directory.

## Status on the default branch
Unchanged at `84ac42d` (2026-07-02); the check is in place. The tested commit is the current default branch head.

## Prior reports
- #10 "Security: Path Traversal bypass in file read operations" (issue, closed 2026-07-02): reports the same thing for `read_file` (`../../../etc/passwd` read outside `--dir`) and suggests resolving the path before the check. It was closed with no linked fix PR in the list, and the checkout has only the head commit `84ac42d`, so I cannot tell whether the guard changed after the report. At `84ac42d` `is_path_allowed()` already resolves the path, and our run saw only refusals.
- Documentation: README.md: "Strict file path security (only within the working directory)" (documents the restriction this check enforces).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already reported as #10 (closed 2026-07-02, no fix PR listed). The current guard refuses the payload, which matches the false-positive verdict here. Do not file.
- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (input-pattern "silent bug" alert). Also listed for this tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_reflected_output`; none of them appears in the evidence calls.
- Campaigns and executions: corpus-sbx 2560 exec / 2555 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed): the three calls in "Actual behavior"; the two refusals carried the real scratch path `/home/mza6485/.tofu_scratch/yzfly__mcp-python-interpreter__read_file`.
- Hand-check hints: false positive (counted as weak). The guard is correct; no evidence call read anything. Recommend not filing. In theory a symlink swapped in by another local process between the check and `open()` could escape (TOCTOU); that needs a second local actor and is negligible next to `run_python_code`, so I left it out of the body.
</details>
