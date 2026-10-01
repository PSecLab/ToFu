# No directory restriction in `insert_text_file_contents`: any absolute path the server user can write is modified

**Repository:** `tumf/mcp-text-editor` · **Tool:** `insert_text_file_contents` · **Tested commit:** `2d66b6f`
**Weakness:** CWE-22 Path Traversal

## Summary
`insert_text_file_contents` inserts text before or after a line in a file. The only path checks are "must be absolute" and a deny-list for `..`, `~` and encoded slashes; there is no allowed root directory. Any absolute path the server process can write is accepted, so the tool is not confined to a project or workspace. The README's "validates all file paths to prevent directory traversal attacks" can give users the impression of a confinement that does not exist.

## Details
The handler only requires an absolute path (`src/mcp_text_editor/handlers/insert_text_file_contents.py:70-72`):

```python
file_path = arguments["file_path"]
if not os.path.isabs(file_path):
    raise RuntimeError(f"File path must be absolute: {file_path}")
```

`TextEditor.insert_text_file_contents` reads the file through `_validate_file_path`, then writes it back (`src/mcp_text_editor/text_editor.py:555-558`, `:597-599`). The validator is called without a `base_dir` (`text_editor.py:83`), so it falls into the branch that allows any path (`src/mcp_text_editor/utils.py:72-79`):

```python
# No base_dir: allow absolute or relative paths, but still check for obvious traversal attempts
if _contains_traversal_patterns(file_path):
    raise ValueError("Path traversal not allowed")
try:
    resolved = pathlib.Path(file_path).resolve()
...
return str(resolved)
```

`normalize_and_validate_path` already supports `base_dir` containment (`utils.py:52-71`), but nothing in the server sets it, and there is no option or env var to configure a root.

## Steps to reproduce
1. Prerequisites: Python 3.11+, `uv`, and the `mcp` Python package for the client script. Create a marker file:

   ```bash
   mkdir -p /tmp/tofu-poc && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install the server from a checkout, as the README's manual installation describes, and start it from an unrelated working directory:

   ```bash
   git clone https://github.com/tumf/mcp-text-editor && cd mcp-text-editor
   git checkout 2d66b6f
   uv venv && uv pip install -e .
   ```
3. Call the tool on the marker file. The hash is the SHA-256 of the current contents (`marker\n`), the same value `get_text_file_contents` returns.

   Arguments:
   ```json
   {"file_path": "/tmp/tofu-poc/outside.txt", "file_hash": "<sha256 of 'marker\\n'>", "contents": "tofu-poc", "after": 1}
   ```

   ```python
   import asyncio, hashlib
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       h = hashlib.sha256(open("/tmp/tofu-poc/outside.txt").read().encode()).hexdigest()
       server = StdioServerParameters(command="uv", args=["run", "--directory", "/path/to/mcp-text-editor", "mcp-text-editor"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("insert_text_file_contents", {"file_path": "/tmp/tofu-poc/outside.txt", "file_hash": h, "contents": "tofu-poc", "after": 1})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `cat /tmp/tofu-poc/outside.txt` now prints `marker` followed by `tofu-poc`. A path with `..` (for example `/tmp/tofu-poc/sub/../outside.txt`) is rejected with `Path traversal not allowed`; the issue is the missing root, not the `..` filter.

## Expected behavior
When the server is meant to edit files in a given project or workspace, paths that resolve outside that directory are rejected.

## Actual behavior
Any absolute path without `..` or `~` is accepted and written, wherever it is on disk. No run log survived from our test, so this is derived from the code at the tested commit.

## Impact
The LLM picks `file_path`, and prompt injection in a file or page the model reads can steer it. If a user expects the editor to stay inside the project they are working on, injected instructions can make it insert text into any file the server's user can write. The server runs with the user's own permissions, so this does not cross a privilege boundary; it is a missing confinement option. Severity depends on how the server is deployed.

## Suggested fix
Add an allowed-root setting (CLI argument or env var, for example a list of directories) and pass it as `base_dir` to `normalize_and_validate_path`, or resolve the path and reject it unless it is under one of the configured roots. Apply the check in one shared place used by every tool, including `TextEditorService.delete_text_file_contents`, which currently opens `request.file_path` without calling the validator (`src/mcp_text_editor/service.py:137`). If unrestricted access is intended, say so in the README's "Security Considerations" section instead of describing the `..` filter as traversal protection.

## Status on the default branch
Still present at `9176a50` (2026-09-12). `utils.py`, the insert handler and `TextEditor.insert_text_file_contents` are unchanged; the only change is an empty-patch-list check in `edit_file_contents`.

## Prior reports
- #22 "[Security] "Arbitrary file read/write: path validation is a single "".."" substring check with no directory confinement"" (issue, closed 2026-06-07): same weakness, no directory confinement. The body only asks where to share details privately; nothing public says what happened next, and the default branch at `9176a50` still sets no `base_dir`, so it is not fixed.
- #15 "P0 fixes: path validation, secure hash compare, and file locking" (PR, closed 2025-09-07): introduced `normalize_and_validate_path` with an optional `base_dir` (the function is on the default branch). Nothing passes `base_dir`, so it does not fix this.
- #21 "Security scan results for mcp-text-editor -- 89.1/100 (Safe)" (issue, closed 2026-09-08): third-party scan; reports only a missing `destructiveHint` annotation, nothing about paths.
- Documentation: README.md "Security Considerations": "The server validates all file paths to prevent directory traversal attacks" and "Proper file system permissions should be set to restrict access to authorized directories" (the first describes the `..` filter; the second leaves confinement to OS permissions, which supports a by-design reply)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: same weakness already reported as #22 (closed 2026-06-07 after the reporter asked for a private channel); not fixed at 9176a50. Ask the maintainer whether a private advisory exists before filing, and reference #22.
- ToFu class / sanitizers: path-traversal; triggered `check_path_traversal` and `check_introspection_log_injection`.
- Campaigns and executions: `e2-0922`, 1 execution, 0 successful, 60 s budget.
- Evidence (verbatim, trimmed): none. `log_available: false`; the reproduction is derived from the code at `2d66b6f`, not from a captured run. We do not know what path ToFu sent.
- Hand-check hints: weak, likely by design. `..` and `~` are rejected, so a `../` traversal from a root is not possible; there is simply no root. The README documents absolute paths and says access control should come from filesystem permissions. The only fuzzer call failed (0 successes), so `check_path_traversal` probably fired on the argument shape, not on a confirmed out-of-root write. Worth filing only as a hardening request (configurable root) plus the `service.py` validator gap, or drop it. The reproduction was not executed here.
</details>
