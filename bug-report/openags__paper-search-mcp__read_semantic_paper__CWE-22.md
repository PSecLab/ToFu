# Path traversal in `read_semantic_paper`: `save_path` creates directories and writes PDFs anywhere

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_semantic_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_semantic_paper` starts with `os.makedirs(save_path, exist_ok=True)`, before any lookup or download. It then reads `<save_path>/semantic_<id>.pdf` if present, or downloads the paper's PDF to that path. `save_path` is never checked, so every call creates the directory the caller names, and successful downloads land there.

## Details
`paper_search_mcp/server.py:644-666` calls `SemanticSearcher.read_paper`, `paper_search_mcp/academic_platforms/semantic.py:419-432`:

```python
os.makedirs(save_path, exist_ok=True)
filename = f"semantic_{paper_id.replace('/', '_')}.pdf"
pdf_path = os.path.join(save_path, filename)

if not os.path.exists(pdf_path):
    paper = self.get_paper_details(paper_id)
    if not paper or not paper.pdf_url:
        return f"Error: Could not find PDF URL for paper {paper_id}"

    pdf_response = requests.get(paper.pdf_url, timeout=30)
    pdf_response.raise_for_status()

    with open(pdf_path, "wb") as f:
        f.write(pdf_response.content)
```

There is no download root and no `realpath`/`commonpath` check. If a `semantic_<id>.pdf` already exists in the named directory, its text is returned.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `api.semanticscholar.org` (only needed for the download part). `PAPER_SEARCH_MCP_SEMANTIC_SCHOLAR_API_KEY` is optional.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a directory outside `./downloads`. The paper ID is the one from the fuzzing run:

   ```json
   {"paper_id": "DOI:10.18653/v1/N18-3011", "save_path": "/tmp/tofu-poc-dir"}
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
               result = await session.call_tool("read_semantic_paper",
                   {"paper_id": "DOI:10.18653/v1/N18-3011", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/` exists after the call even if the PDF download fails. If the PDF host serves the file, `/tmp/tofu-poc-dir/semantic_DOI:10.18653_v1_N18-3011.pdf` is also created.

## Expected behavior
`save_path` must resolve inside a configured download directory, and no directory is created before that check passes.

## Actual behavior
The directory is created first, then the download is attempted. From the fuzzing run, this call passed `os.makedirs("../../malicious")` and then failed at the PDF host:

```
{'paper_id': 'DOI:10.18653/v1/N18-3011', 'save_path': '../../malicious'}
-> Error downloading PDF: 418 Client Error: Unknown for url: https://www.aclweb.org/anthology/N18-3011.pdf
```

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection in untrusted content. An attacker can create directories anywhere the server user can write on every call, and write downloaded PDFs named `semantic_<id>.pdf` there. Name and content are not attacker-chosen. Severity: low.

## Suggested fix
Move `os.makedirs` after a containment check: resolve `save_path` under one download root (`os.path.realpath` plus `os.path.commonpath`), reject anything outside it, and only create the directory right before a successful write. Share the helper with `download_semantic` (`semantic.py:387-392`).

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `semantic.py:453-466` has the same order (`os.makedirs` first, no check). The tool is now annotated `destructiveHint: True`.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #65 "Harden Semantic Scholar PDF downloads" (PR, closed 2026-09-28): validates PDF bytes before saving and removes bad cached files. It does not touch `save_path`, and `semantic.py` on the default branch still writes the response unchecked, so its changes are not on the default branch.
- #134 "fix(semantic): validate PDF downloads before replacing cache" (PR, open 2026-10-01): validates the PDF and stages the write in a temporary file before replacing the target. It does not mention `save_path` containment, so it would not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_blocking_event_loop_call`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 2048 / 2042 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': 'DOI:10.18653/v1/N18-3011', 'save_path': '../../malicious'}` -> `Error downloading PDF: 418 Client Error: Unknown for url: https://www.aclweb.org/anthology/N18-3011.pdf`
  - `{'paper_id': 'URL:http://169.254.169.254/latest/meta-data/', 'save_path': '../'}` -> `Error: Could not find PDF URL for paper URL:http://169.254.169.254/latest/meta-data/`
  - `{'paper_id': 'DOI:10.1865-/v1/N18-3011', 'save_path': '../../malicious'}` (repo24) -> `Error: Could not find PDF URL for paper DOI:10.1865-/v1/N18-3011`
- Hand-check hints: real, low severity. The "418" output can only be produced after line 419 `os.makedirs(save_path)` succeeded (a failure there would return `Error reading paper: ...`), so the run did create `../../malicious` relative to the server's cwd. That inference is from source; no tracer record of the mkdir is in the evidence. The `URL:` paper ID is resolved by the Semantic Scholar API, not fetched locally, so it is not SSRF.
</details>
