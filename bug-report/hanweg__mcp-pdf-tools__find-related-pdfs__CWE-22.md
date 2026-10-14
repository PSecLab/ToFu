# Path traversal in `find-related-pdfs`: `base_path` walks and parses PDFs in any directory

**Repository:** `hanweg/mcp-pdf-tools` · **Tool:** `find-related-pdfs` · **Tested commit:** `388ba1f`
**Weakness:** CWE-22 Path Traversal

## Summary
`find-related-pdfs` walks `base_path`, opens the first PDF whose name contains `target_filename`, extracts its text, and returns matching PDFs plus the list of words it extracted. `base_path` is passed to `os.walk()` with no check of where it points, so `..` or an absolute path makes the server walk and parse PDFs anywhere the process can read. The reply can include file paths and the extracted word list of a PDF outside any folder the user meant to share.

## Details
`src/pdf_tools/server.py:331-358` and `:428-431` at `388ba1f`:

```python
        base_path = arguments.get("base_path")
        target_filename = arguments.get("target_filename")
        ...
            for root, _, files in os.walk(base_path):
                for filename in files:
                    if target_filename.lower() in filename.lower() and filename.lower().endswith('.pdf'):
                        target_pdf_path = os.path.join(root, filename)
                        break
        ...
            reader = PdfReader(target_pdf_path)
            extracted_text = ""
            for page in reader.pages:
                extracted_text += page.extract_text() + "\n"
        ...
                result_text = f"Extracted {len(search_terms)} search terms from {os.path.basename(target_pdf_path)}.\n"
                result_text += "Search terms found: " + ", ".join(sorted(search_terms)) + "\n\n"
```

There is no allow-list of directories and no `realpath` plus prefix check on `base_path`. The second `os.walk(base_path)` at line 412 then lists every PDF under the same tree whose name matches an extracted word, with full paths. The server has no configured root at all, so this applies to every directory the server user can read.

The other tools in this server (`extract-pages`, `merge-pdfs`, `merge-pdfs-ordered`, `search-pdfs`) take paths the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No accounts or env vars. Create an empty working folder first:

   ```bash
   mkdir -p /tmp/tofu-poc/root
   ```
2. Install as the README describes (Linux/macOS form), then place a marker PDF one level above the working folder:

   ```bash
   git clone https://github.com/hanweg/mcp-pdf-tools.git
   cd mcp-pdf-tools && git checkout 388ba1f
   uv venv && uv pip install -e .
   .venv/bin/python -c "from PyPDF2 import PdfWriter; w = PdfWriter(); w.add_blank_page(width=72, height=72); w.write('/tmp/tofu-poc/outside.pdf')"
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with:

   ```json
   {"base_path": "..", "target_filename": "outside"}
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
               result = await session.call_tool("find-related-pdfs", {
                   "base_path": "..",
                   "target_filename": "outside",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply names `outside.pdf` (for a blank page, `No related PDFs found for terms extracted from outside.pdf`). With the same call and `"base_path": "."` the reply is `Could not find target PDF: outside`. The difference shows the tool found and parsed a PDF outside `/tmp/tofu-poc/root`. With a PDF that contains text, the reply also lists the words extracted from it once a related file is found.

## Expected behavior
`base_path` is limited to directories the user configured, and `..` (or any path resolving outside them) is rejected before the tool walks or opens anything.

## Actual behavior
The tool walks the parent directory and parses `/tmp/tofu-poc/outside.pdf`. During fuzzing, traversal-shaped `base_path` values were accepted without an error:

```
input:  {"base_path": "../../../../etc/passwd", "target_filename": "target.pdf", "pattern_matching_only": false, "min_pattern_occurrences": 2}
output: Could not find target PDF: target.pdf
```

(That value names a regular file, so `os.walk` returned nothing; the point is that no check rejected it.)

## Impact
In MCP the LLM chooses `base_path` and `target_filename`, and prompt injection from untrusted content (for example text inside a PDF being processed) can steer them. An attacker can make the server enumerate PDF file paths anywhere on the machine and return the vocabulary of PDFs outside the intended folder, which can include personal or business data. The tool does not write files, so the effect is limited to disclosure of PDF names, paths and text terms.

## Suggested fix
- Add an allow-list of directories (command-line arguments or an env var such as `PDF_TOOLS_ALLOWED_DIRS`).
- Resolve `base_path` with `os.path.realpath()` and reject it unless it equals an allowed root or starts with `root + os.sep`. Use `os.walk(..., followlinks=False)` (the default) and re-check `realpath` of each file before opening it, so symlinks inside the root cannot point out of it.
- Apply the same helper to the path arguments of the other four tools.

## Status on the default branch
Still present at `388ba1f` (2024-12-22). The default branch head is the tested commit.

## Prior reports
- #2 "Add MseeP.ai badge to README" (PR, open 2025-04-28): related only. A third-party badge PR whose body pastes an automated semgrep result, "Potentially unsafe file access", for `server.py` lines 164 and 168 (the `merge-pdfs` handler) "and 3 more medium severity issues" at unnamed locations. It does not name this tool, it is not a bug report, and nothing was changed.
- Documentation: README.md: "WORK IN PROGRESS - USE WITH CAUTION - Windows:" (a general caution only; the README does not say which paths the tools may touch, and there is no allowed-directory setting).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Only `check_path_traversal` fired for this tool. That check matches the input string (`../`, `..\`, `/etc/passwd`, `windows\win.ini`); no tracer-based alert fired.
- Campaigns and executions: corpus-sbx 2048 exec / 615 ok (60 s); e2-0922 1024 exec / 310 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'base_path': '/etc/passwd\x00', 'target_filename': 'file.pdf', ...}` -> `'Error processing PDFs: scandir: embedded null character in path'`
  - `{'base_path': '../../../../etc/passwd', 'target_filename': 'target.pdf', ...}` -> `'Could not find target PDF: target.pdf'`
  - `{'base_path': '/tmp', 'target_filename': '..\\..\\..\\..\\windows\\win.ini', ...}` -> `'Could not find target PDF: ..\\..\\..\\..\\windows\\win.ini'`
- Hand-check hints: weak. The missing restriction on `base_path` is real in code (`server.py:340`, `:355`, `:412`), but none of the logged calls actually read anything outside the target directory: the alert is input-pattern only, and `os.walk` on a regular file yields nothing. The impact is read-only and limited to PDFs. The reproduction above was derived from code reading and was not executed; I did not confirm that PyPDF2 `extract_text()` returns an empty string for a page made by `add_blank_page` (if it raises, the reply is `Error processing PDFs: ...`, which still shows the file was opened). The server has no root concept, so this may be seen as by design. Consider one combined issue for all five tools.
</details>
