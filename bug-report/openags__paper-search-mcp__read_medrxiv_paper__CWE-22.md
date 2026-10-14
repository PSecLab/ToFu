# Path traversal in `read_medrxiv_paper`: `save_path` reads and writes PDFs outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_medrxiv_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_medrxiv_paper` checks for `<save_path>/<paper_id with / replaced>.pdf`, returns its text if the file exists, and otherwise downloads the medRxiv PDF to that path. `save_path` is never checked, so the tool will return the text of any existing local `.pdf` the caller names, and will create directories and write the downloaded PDF anywhere the server user can write.

## Details
`paper_search_mcp/server.py:571-585` calls `MedRxivSearcher.read_paper`, `paper_search_mcp/academic_platforms/medrxiv.py:133-142`:

```python
pdf_path = f"{save_path}/{paper_id.replace('/', '_')}.pdf"
if not os.path.exists(pdf_path):
    pdf_path = self.download_pdf(paper_id, save_path)

try:
    reader = PdfReader(pdf_path)
    text = ""
    for page in reader.pages:
        text += page.extract_text() + "\n"
    return text.strip()
```

`download_pdf` (`medrxiv.py:111-115`) runs `os.makedirs(save_path, exist_ok=True)` and writes the response to the same path. `save_path` is not resolved or compared with a download root. The code is identical to the bioRxiv connector.

## Steps to reproduce
1. Prerequisites: Python 3.10+. The read case needs no network. The write case needs outbound HTTPS to `www.medrxiv.org`.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   cp <any PDF that contains text> /tmp/tofu-poc.pdf   # stands in for a private document
   ```
3. Read a PDF outside `./downloads`:

   ```json
   {"paper_id": "tofu-poc", "save_path": "/tmp"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "paper_search_mcp.server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("read_medrxiv_paper",
                   {"paper_id": "tofu-poc", "save_path": "/tmp"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the result is the text of `/tmp/tofu-poc.pdf`. For the write side, use a real medRxiv DOI (from `search_medrxiv`) with `"save_path": "/tmp/tofu-poc-dir"` and observe the new file there.

## Expected behavior
`save_path` must resolve inside a configured download directory before any `exists`, read, `makedirs` or write.

## Actual behavior
Any directory is accepted. The logged calls used IDs that do not exist on medRxiv, so the download failed and the handler returned an empty string:

```
{'paper_id': '10.1101/2020.01.01.20000001', 'save_path': '../../../../etc/'}
-> ''
```

## Impact
Tool arguments come from the LLM and can be steered by prompt injection in untrusted content. An attacker can have the server return the text of local `.pdf` files outside the download folder, and can create directories and write medRxiv PDFs into any writable location. Only `.pdf` names are affected. Severity: medium-low.

## Suggested fix
Resolve `save_path` under one download root (`os.path.realpath` plus `os.path.commonpath`) before building `pdf_path`, and reject anything outside it. Apply the same helper in `download_pdf` and in `biorxiv.py`, which has the same code.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `medrxiv.py:115-117` (write) and `medrxiv.py:137-139` (exists/read) are unchanged apart from logging. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_insecure_file_permissions`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 43008 / 43008 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `''`
  - `{'paper_id': '10.1101/2020.01.01.20000001', 'save_path': '../../../../etc/'}` -> `''`
  - `{'paper_id': '/etc/passwdᘕ', 'save_path': '../'}` -> `''`
- Hand-check hints: real. The retained calls show only the input-pattern alert with empty output (exceptions are swallowed by the handler). The read-any-local-PDF repro is derived from source, not run. `check_introspection_insecure_file_permissions` in the triggered set suggests some repo24 call did write a file. Consider filing together with `read_biorxiv_paper` (identical code) or in one consolidated `save_path` issue.
</details>
