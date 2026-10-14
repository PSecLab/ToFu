# Path traversal in `merge-pdfs`: `output_path` can create or overwrite files outside the working directory

**Repository:** `hanweg/mcp-pdf-tools` · **Tool:** `merge-pdfs` · **Tested commit:** `388ba1f`
**Weakness:** CWE-22 Path Traversal

## Summary
`merge-pdfs` opens every path in `input_paths`, merges them, and writes the result to `output_path`. None of these paths are checked, so `../` segments or absolute paths let a caller read PDFs from any directory and create or overwrite any file the server process can write. The server has no configured base directory, so there is no boundary between the folders the user meant to share and the rest of the disk.

## Details
`src/pdf_tools/server.py:152-169` at `388ba1f`:

```python
    if name == "merge-pdfs":
        input_paths = arguments.get("input_paths", [])
        output_path = arguments.get("output_path")
        ...
        merger = PyPDF2.PdfMerger()
        try:
            for path in input_paths:
                with open(path, 'rb') as pdf_file:
                    merger.append(pdf_file)

            with open(output_path, 'wb') as output_file:
                merger.write(output_file)
```

There is no `os.path.realpath` plus prefix check, no rejection of `..` or absolute paths, and no allow-list of directories in the server. Relative paths resolve against the server's working directory. `open(output_path, 'wb')` truncates an existing file. The success message (`Successfully merged ... into {output_path}`) does not warn that an existing file was replaced.

The other tools in this server (`extract-pages`, `merge-pdfs-ordered`, `search-pdfs`, `find-related-pdfs`) take paths the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No accounts or env vars. Create a marker file and an empty working folder first:

   ```bash
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install as the README describes (Linux/macOS form), then create a one-page input PDF inside the working folder:

   ```bash
   git clone https://github.com/hanweg/mcp-pdf-tools.git
   cd mcp-pdf-tools && git checkout 388ba1f
   uv venv && uv pip install -e .
   .venv/bin/python -c "from PyPDF2 import PdfWriter; w = PdfWriter(); w.add_blank_page(width=72, height=72); w.write('/tmp/tofu-poc/root/in.pdf')"
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with:

   ```json
   {"input_paths": ["in.pdf"], "output_path": "../outside.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="/path/to/mcp-pdf-tools/.venv/bin/pdf-tools",
           args=[],
           cwd="/tmp/tofu-poc/root",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("merge-pdfs", {
                   "input_paths": ["in.pdf"],
                   "output_path": "../outside.txt",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply is `Successfully merged 1 PDFs into ../outside.txt`, and `head -c 5 /tmp/tofu-poc/outside.txt` prints `%PDF-` instead of `marker`. With `"output_path": "../new.txt"` the tool creates `/tmp/tofu-poc/new.txt`. Input paths behave the same way: `"input_paths": ["../new.txt"]` with `"output_path": "copy.pdf"` reads the PDF from outside the folder.

## Expected behavior
Paths are limited to directories the user configured. `../outside.txt` is rejected with an error and nothing outside `/tmp/tofu-poc/root` is opened, created or changed.

## Actual behavior
The tool overwrites `/tmp/tofu-poc/outside.txt` and reports success. During fuzzing the server accepted traversal-shaped and absolute paths in both arguments without any validation error; the calls failed later, on file contents or missing files:

```
input:  {"input_paths": ["/etc/passwd\x00", "predefined_seed:sample3.pdf"], "output_path": "../output/merged.pdf"}
output: Error merging PDFs: embedded null byte
```

## Impact
In MCP the LLM chooses `input_paths` and `output_path`, and prompt injection from untrusted content (for example text inside a PDF the user asks it to merge) can steer them. An attacker who controls the arguments can overwrite any file the server user can write with PDF bytes, for example a shell profile or a config file, which breaks it. Through `input_paths` the attacker can also copy PDFs from outside the intended folder into a place of their choosing. File contents are not returned in the reply.

## Suggested fix
- Add an allow-list of directories (command-line arguments or an env var such as `PDF_TOOLS_ALLOWED_DIRS`).
- In a shared helper, resolve each path with `os.path.realpath()` and reject it unless it equals an allowed root or starts with `root + os.sep`. Apply it to every entry of `input_paths` and to `output_path`, and to the path arguments of the other tools.
- Refuse to overwrite an existing `output_path` unless the caller passes an explicit `overwrite: true`.

## Status on the default branch
Still present at `388ba1f` (2024-12-22). The default branch head is the tested commit.

## Prior reports
- #2 "Add MseeP.ai badge to README" (PR, open 2025-04-28): a third-party badge PR whose body pastes an automated semgrep result, "Potentially unsafe file access. Make sure the filename is properly validated.", for `server.py` lines 164 and 168, which are this tool's `open(path, 'rb')` and `open(output_path, 'wb')`. It is not a bug report, it is still open, and those lines are unchanged on the default branch.
- Documentation: README.md: "WORK IN PROGRESS - USE WITH CAUTION - Windows:" (a general caution only; the README does not say which paths the tools may touch, and there is no allowed-directory setting).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: not filed and not fixed. Only an automated semgrep note in open badge PR #2 flags these exact lines (164, 168).
- ToFu class / sanitizers: path-traversal (CWE-22). Fired for this tool: `check_path_traversal`, `check_introspection_path_traversal`, `check_introspection_sensitive_file_access`, `check_file_access`.
- Campaigns and executions: corpus-sbx 2048 exec / 211 ok (60 s); e2-0922 1024 exec / 100 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'input_paths': ['predefined_seed:sample5.pdf', '/dev/random'], 'output_path': '/etc/passwd'}` -> `"Error merging PDFs: [Errno 2] No such file or directory: 'predefined_seed:sample5.pdf'"`
  - `{'input_paths': ['/etc/passwd\x00', 'predefined_seed:sample3.pdf'], 'output_path': '../output/merged.pdf'}` -> `'Error merging PDFs: embedded null byte'`
  - `{'input_paths': ['predefined_seed:sample4.pdf', '/dev/random'], 'output_path': '/etc/passwd'}` -> same `No such file or directory` error.
- Hand-check hints: real in code, weak in the logs. `open(output_path, 'wb')` at `server.py:168` with no check is verified by reading the code. None of the logged calls escaped: `predefined_seed:sampleN.pdf` is an unsubstituted ToFu seed placeholder, and the tracer flagged it as "outside dedicated directory" only because the fuzzer's cwd was the scratch dir, not the repo dir (a ToFu artifact, not target behaviour). The `\x00` call fails in Python before any syscall, and the `/etc/passwd` output path was never reached because the first input failed. The reproduction above was not executed; run it before filing. No root concept exists, so a maintainer may call arbitrary paths intended; frame it as adding an allowed-directories boundary and an overwrite guard. Consider one combined issue for all five tools.
</details>
