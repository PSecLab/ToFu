# Path traversal in `read_biorxiv_paper`: `save_path` reads and writes PDFs outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_biorxiv_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_biorxiv_paper` checks for `<save_path>/<paper_id with / replaced>.pdf` on disk, returns its text if it exists, and otherwise downloads the bioRxiv PDF to that path. `save_path` is never checked, so the tool will read the text of any existing local `.pdf` the caller names, and will create directories and write the downloaded file anywhere the server user can write.

## Details
`paper_search_mcp/server.py:554-568` calls `BioRxivSearcher.read_paper`, `paper_search_mcp/academic_platforms/biorxiv.py:132-140`:

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

`download_pdf` (`biorxiv.py:110-114`) runs `os.makedirs(save_path, exist_ok=True)` and writes `f"{save_path}/{paper_id.replace('/', '_')}.pdf"`. Replacing `/` in `paper_id` keeps the file name flat, but `save_path` can be absolute or contain `../`.

## Steps to reproduce
1. Prerequisites: Python 3.10+. The read case needs no network. The write case needs outbound HTTPS to `www.biorxiv.org`.
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
               result = await session.call_tool("read_biorxiv_paper",
                   {"paper_id": "tofu-poc", "save_path": "/tmp"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the result is the text of `/tmp/tofu-poc.pdf`. For the write side, call it with a real bioRxiv DOI (from `search_biorxiv`) and `"save_path": "/tmp/tofu-poc-dir"`, and observe `/tmp/tofu-poc-dir/10.1101_<...>.pdf` being created.

## Expected behavior
`save_path` must resolve inside a configured download directory before any `exists`, read, `makedirs` or write.

## Actual behavior
Any directory is accepted. The logged fuzzing calls used a made-up DOI, so the download failed and the server returned an empty string:

```
{'paper_id': '10.1101/2023.01.01.123456', 'save_path': '../../../../../tmp'}
-> ''
{'paper_id': '10.1101/2023.01.01.123456', 'save_path': '/etc/passwd'}
-> ''
```

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection in untrusted content. An attacker can have the server return the text of local `.pdf` files outside the download folder, and can create directories and write bioRxiv PDFs into any writable location. Only `.pdf` names are affected. Severity: medium-low.

## Suggested fix
Resolve the path once under a download root and reject it if it leaves that root:

```python
root = os.path.realpath(DOWNLOAD_ROOT)
target_dir = os.path.realpath(os.path.join(root, save_path))
if os.path.commonpath([root, target_dir]) != root:
    raise ValueError("save_path must stay inside the download directory")
```

Use the same helper in `download_pdf` and in the identical medRxiv connector (`medrxiv.py`).

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `biorxiv.py:190-192` (write) and `biorxiv.py:214-216` (exists/read) keep the same logic. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_insecure_file_permissions`, `check_introspection_path_traversal`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 22528 / 22522 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '10.1101/2023.01.01.123456', 'save_path': '/etc/passwd'}` -> `''`
  - `{'paper_id': '10.1101/2023.01.01.123456', 'save_path': '../../../../../tmp'}` -> `''`
  - `{'paper_id': '10.1101/2023.01.01.123456', 'save_path': './downloads/../secrets'}` -> `''`
- Hand-check hints: real. The retained calls only show the input-pattern alert plus empty output (the exception is swallowed by the handler). The read-any-local-PDF repro is derived from source (`os.path.exists` then `PdfReader`), not run. The write repro assumes bioRxiv serves the PDF to a scripted client; not verified. `check_introspection_path_traversal` is in the triggered set, so some repo24 call touched a path outside the target dir, but that call is not in the evidence. Note the handler's `print()` on error writes to stdout, which is the JSON-RPC channel in stdio mode (separate bug).
</details>
