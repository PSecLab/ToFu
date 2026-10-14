# Write restriction enforced by `write_file` is skipped by `run_python_code`'s `save_as`: files can be written and overwritten outside `--dir`

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `write_file` (flagged); affected code in `run_python_code` · **Tested commit:** `84ac42d`
**Weakness:** CWE-22 Path Traversal

## Summary
The README promises "Prevented writes outside the working directory" and "Explicit overwrite protection". `write_file` keeps that promise: it checks every path with `is_path_allowed()` and refuses to overwrite unless asked. The fuzzer's traversal attempts against `write_file` were all refused or stayed inside the working directory. `run_python_code` also writes files, through its `save_as` argument, and that path is joined to the working directory with no check at all. An absolute or `../` value writes a `.py` file anywhere the user can write, and silently replaces an existing one.

## Details
`write_file` is contained, `mcp_python_interpreter/server.py:779-787` (tested commit):

```python
    path = Path(file_path)
    if not path.is_absolute():
        path = WORKING_DIR / path
    if not is_path_allowed(path):
        return f"Access denied: Can only write files in working directory: {WORKING_DIR}"
    try:
        if path.exists() and not overwrite:
            return f"File '{path}' exists. Use overwrite=True to replace."
```

`run_python_code` is not, `server.py:543-554`:

```python
    if save_as:
        save_path = WORKING_DIR / save_as
        if not save_path.suffix == '.py':
            save_path = save_path.with_suffix('.py')
        try:
            save_path.parent.mkdir(parents=True, exist_ok=True)
            with open(save_path, 'w', encoding='utf-8') as f:
                f.write(code)
```

With pathlib, `WORKING_DIR / "/abs/path"` returns `/abs/path`, and `WORKING_DIR / "../x"` keeps the `..`. There is no `is_path_allowed()` call and no existence check, and missing parent directories are created. The only constraint is that the suffix is forced to `.py`.

## Steps to reproduce
1. Prerequisites: Python 3.10+. Leave `MCP_ALLOW_SYSTEM_ACCESS` unset.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
3. With the server started as `--dir /tmp/tofu-wd`, first confirm `write_file` refuses an outside path, then use `save_as`:

   ```json
   {"file_path": "/tmp/tofu-poc.txt", "content": "tofu-poc"}
   ```
   ```json
   {"code": "print('tofu-poc')", "execution_mode": "inline", "save_as": "/tmp/tofu-poc.txt"}
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
               r1 = await session.call_tool("write_file", {"file_path": "/tmp/tofu-poc.txt", "content": "tofu-poc"})
               print("write_file:", r1)
               r2 = await session.call_tool("run_python_code", {"code": "print('tofu-poc')",
                                                                "execution_mode": "inline",
                                                                "save_as": "/tmp/tofu-poc.txt"})
               print("run_python_code:", r2)

   asyncio.run(main())
   ```
4. Observe: `write_file` returns `Access denied: Can only write files in working directory: /tmp/tofu-wd`. The `run_python_code` call succeeds, and `/tmp/tofu-poc.py` (suffix forced to `.py`) now exists outside the working directory with the content `print('tofu-poc')`. Run it again with different code and the file is replaced without warning. `save_as: "../tofu-poc"` has the same effect.

## Expected behavior
`save_as` goes through the same `is_path_allowed()` check and the same overwrite rule as `write_file`, so it can only create files inside the working directory.

## Actual behavior
`write_file` is contained. In the fuzzing run (working directory shortened), the Windows-style payload became a single file name inside the working directory on Linux, and the Unix payloads were refused:

```
{'file_path': '..\\..\\..\\..\\windows\\win.ini', 'content': 'test', 'overwrite': True}
  -> Successfully wrote to <wd>/..\..\..\..\windows\win.ini. Size: 0.00 KB
{'file_path': '../../../../etc/passwd', 'content': 'malicious attempt', 'overwrite': False}
  -> Access denied: Can only write files in working directory: <wd>
```

`save_as` has no such check (from source; the fuzzer did not target it).

## Impact
The LLM chooses `save_as`, and prompt injection can steer it. It can create or overwrite any `.py` file the user can write, for example a module on `sys.path` or a script in another project, which would then run the next time it is imported or started. In practice the gain is small, because the same `run_python_code` call can already run arbitrary code with the user's rights. The concrete problem is that the documented isolation does not hold, and users who rely on `--dir` may not expect writes elsewhere.

## Suggested fix
Apply the existing guard to `save_as`:

```python
    if save_as:
        save_path = WORKING_DIR / save_as
        if save_path.suffix != '.py':
            save_path = save_path.with_suffix('.py')
        if not is_path_allowed(save_path):
            return f"Access denied: Can only save files in working directory: {WORKING_DIR}"
```

Also consider honoring an `overwrite` flag here, and stating in the README that inline and subprocess execution are not restricted to the working directory.

## Status on the default branch
Still present at `84ac42d` (2026-07-02). The tested commit is the current default branch head.

## Prior reports
- #10 "Security: Path Traversal bypass in file read operations" (issue, closed 2026-07-02): about a `../` bypass of `is_path_allowed()` in `read_file`. It does not mention `write_file` or `run_python_code(save_as=...)`, which never calls the guard, so the `save_as` gap is not reported and not fixed.
- Documentation: README.md: "Prevented writes outside the working directory" and "Explicit overwrite protection" under "Security Considerations" (the promises that `save_as` does not keep).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (input-pattern "silent bug" alert). Also `check_introspection_insecure_file_permissions` (file created with mode `0o664`, which is just the default umask), `check_introspection_insecure_temp_permissions`, `check_reflected_output`.
- Campaigns and executions: corpus-sbx 2560 exec / 2558 ok; e2-0922 1 exec / 1 ok (60 s budgets).
- Evidence (verbatim, trimmed):
  - `{'file_path': '..\\..\\..\\..\\windows\\win.ini', 'content': 'test', 'overwrite': True}` -> `Successfully wrote to /home/mza6485/.tofu_scratch/yzfly__mcp-python-interpreter__write_file/..\..\..\..\windows\win.ini. Size: 0.00 KB`
  - `{'file_path': '/etc/passwd\x00', 'content': 'null byte injection', 'overwrite': False}` -> `Access denied: ...`
  - `{'file_path': '../../../../etc/passwd', 'content': 'malicious attempt', 'overwrite': False}` -> `Access denied: ...`
- Hand-check hints: weak. The `write_file` alert itself is a false positive: the guard works and the one "successful" write stayed inside the working directory. I reframed the draft around `run_python_code(save_as=...)`, which skips the guard (confirmed in source, `server.py:543-554`); this was not exercised by the fuzzer and I did not run it. Worth filing only as a consistency/documentation fix, because `run_python_code` already gives arbitrary code execution.
</details>
