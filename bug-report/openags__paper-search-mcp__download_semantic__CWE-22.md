# Path traversal in `download_semantic`: `save_path` writes the PDF outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_semantic` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_semantic` looks up a paper on Semantic Scholar, downloads its open-access PDF and saves it as `<save_path>/semantic_<id>.pdf`. `save_path` is used as given, so an absolute path or `../` sequences put the file anywhere the server user can write, and missing directories are created.

## Details
`paper_search_mcp/server.py:623-641` passes `save_path` to `SemanticSearcher.download_pdf`, `paper_search_mcp/academic_platforms/semantic.py:379-394`:

```python
paper = self.get_paper_details(paper_id)
if not paper or not paper.pdf_url:
    return f"Error: Could not find PDF URL for paper {paper_id}"
pdf_url = paper.pdf_url
pdf_response = requests.get(pdf_url, timeout=30)
pdf_response.raise_for_status()

# Create download directory if it doesn't exist
os.makedirs(save_path, exist_ok=True)

filename = f"semantic_{paper_id.replace('/', '_')}.pdf"
pdf_path = os.path.join(save_path, filename)

with open(pdf_path, "wb") as f:
    f.write(pdf_response.content)
```

`/` in `paper_id` is replaced, but `save_path` is not resolved or checked against a root. The response is not checked to be a PDF.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `api.semanticscholar.org` and to the PDF host Semantic Scholar returns. `PAPER_SEARCH_MCP_SEMANTIC_SCHOLAR_API_KEY` is optional (without it, requests are rate-limited).
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a paper that has an open-access PDF (for example the docstring example `ARXIV:2106.15928`; any ID for which `search_semantic` shows a `pdf_url` works) and a directory outside `./downloads`:

   ```json
   {"paper_id": "ARXIV:2106.15928", "save_path": "/tmp/tofu-poc-dir"}
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
               result = await session.call_tool("download_semantic",
                   {"paper_id": "ARXIV:2106.15928", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/semantic_ARXIV:2106.15928.pdf` is created and its path is returned.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected.

## Actual behavior
Any directory is accepted. In the logged fuzzing calls the PDF fetch failed before the write (the PDF host answered 418, or DNS failed in our sandbox), for example:

```
{'paper_id': 'DOI:10.18653/v1/N18-3011', 'save_path': '../../../../etc/passwd'}
-> Error downloading PDF: 418 Client Error: Unknown for url: https://www.aclweb.org/anthology/N18-3011.pdf
```

The same call with a reachable PDF continues to `os.makedirs("../../../../etc/passwd")` and `open(...)`.

## Impact
Tool arguments come from the LLM and can be steered by prompt injection in untrusted content. An attacker can create directories and write a downloaded PDF named `semantic_<id>.pdf` into any writable directory. The name pattern and the third-party content limit the damage to clutter, disk use, and planting or overwriting files of that name. Severity: low.

## Suggested fix
Resolve `save_path` under one download root before `os.makedirs` (`os.path.realpath` plus `os.path.commonpath`) and reject anything outside it. Use the same helper in `read_semantic_paper` (`semantic.py:419-432`) and in the other connectors.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `semantic.py:421-427` is unchanged. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #65 "Harden Semantic Scholar PDF downloads" (PR, closed 2026-09-28): validates PDF bytes before saving and removes bad cached files. It does not touch `save_path`, and `semantic.py` on the default branch still writes the response unchecked, so its changes are not on the default branch.
- #134 "fix(semantic): validate PDF downloads before replacing cache" (PR, open 2026-10-01): validates the PDF and stages the write in a temporary file before replacing the target. It does not mention `save_path` containment, so it would not fix this.
- #70 "Improve DOI fallback downloads and Sci-Hub mirror handling" (PR, open 2026-05-07): adds PDF response validation for Semantic Scholar downloads after 0-byte PDFs were reported. No path checks.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_blocking_event_loop_call`, `check_introspection_incomplete_cleanup`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_resource_exhaustion`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 512 / 504 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `Error: Could not find PDF URL for paper /etc/passwd\x00`
  - `{'paper_id': 'MAG:112218234', 'save_path': '..\\..\\..\\..\\windows\\win.ini'}` -> `Error downloading PDF: HTTPConnectionPool(host='sites.clas.ufl.edu', port=80): ... NameResolutionError ...`
  - `{'paper_id': 'DOI:10.18653/v1/N18-3011', 'save_path': '../../../../etc/passwd'}` -> `Error downloading PDF: 418 Client Error: Unknown for url: https://www.aclweb.org/anthology/N18-3011.pdf`
- Hand-check hints: real at code level, low severity. None of the retained calls reached `os.makedirs`/`open`; the alert is the input-pattern check. The temp-file introspection alerts in the triggered set suggest a repo24 call wrote a file, but it is not in the evidence. I did not verify that `ARXIV:2106.15928` resolves to a downloadable PDF. On Windows, `paper_id` with `\` would also traverse because only `/` is replaced.
</details>
