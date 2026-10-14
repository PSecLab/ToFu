# Path traversal in `read_citeseerx_paper`: `save_path` is not contained when the PDF fallback runs

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_citeseerx_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_citeseerx_paper` returns the CiteSeerX abstract when there is one. When a paper has no abstract, it falls back to `download_pdf`, which creates `save_path` and writes the PDF there with no containment. A caller can then make the server create directories and write a file in any writable location. The fallback only runs for papers without an abstract, so this is hard to reach in practice.

## Details
`paper_search_mcp/server.py:1111-1121` calls `CiteSeerXSearcher.read_paper`, which only downloads when `paper.abstract` is empty (`paper_search_mcp/academic_platforms/citeseerx.py:363-375`). `download_pdf`, `citeseerx.py:320-332`:

```python
# Create save directory if it doesn't exist
os.makedirs(save_path, exist_ok=True)

# Generate filename
filename = f"{paper_id.replace('/', '_')}.pdf"
if paper.doi:
    filename = f"{paper.doi.replace('/', '_')}.pdf"
filepath = os.path.join(save_path, filename)

# Save PDF
with open(filepath, 'wb') as f:
    for chunk in response.iter_content(chunk_size=8192):
        f.write(chunk)
```

`save_path` is not resolved or checked against a root. The response is not checked to be a PDF.

## Steps to reproduce
1. Prerequisites: Python 3.10+, outbound HTTPS to `citeseerx.ist.psu.edu`, and a CiteSeerX paper ID whose record has a PDF link but no abstract. `PAPER_SEARCH_MCP_CITESEERX_API_KEY` is optional.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with such an ID and a directory outside `./downloads`:

   ```json
   {"paper_id": "<CiteSeerX id with a PDF and no abstract>", "save_path": "/tmp/tofu-poc-dir"}
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
               result = await session.call_tool("read_citeseerx_paper",
                   {"paper_id": "<CiteSeerX id with a PDF and no abstract>", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `PDF downloaded to /tmp/tofu-poc-dir/<id>.pdf. Text extraction not implemented.` and the new file.

## Expected behavior
`save_path` must resolve inside a configured download directory before `os.makedirs` and the write.

## Actual behavior
The path is not checked. In the fuzzing run every lookup failed before the fallback, so no write was observed:

```
{'paper_id': 'valid-paper-id', 'save_path': '../../../../../tmp'}
-> Error reading paper: Paper valid-paper-id not found
```

## Impact
Tool arguments come from the LLM and can be steered by prompt injection in untrusted content. If the fallback is reached, an attacker can create directories and drop a downloaded file with a `.pdf` name into any writable directory. Reaching it requires a CiteSeerX record without an abstract, which limits practical impact. Severity: low.

## Suggested fix
Resolve `save_path` under one download root (`os.path.realpath` plus `os.path.commonpath`) before `os.makedirs` and reject anything outside it, using the same shared helper as the other connectors.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `citeseerx.py` is unchanged.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_log_injection`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 24576 / 24572 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': 'valid-paper-id', 'save_path': '/tmp/../etc/'}` -> `Error reading paper: Paper valid-paper-id not found`
  - `{'paper_id': 'valid-paper-id', 'save_path': '../../../../../tmp'}` -> same
  - `{'paper_id': '"paper_', 'save_path': 'd": "/etc/passwd\\u0000", "save_path": "./dowpath'}` -> `Error reading paper: Paper "paper_ not found`
- Hand-check hints: unclear. The code has no containment, but no logged call reached `download_pdf`, and the fallback needs a record without an abstract plus a working CiteSeerX API (`_get` treats a redirect to web.archive.org as unavailable, suggesting the API is often down). I could not find a concrete ID offline. The filename can come from the server-supplied `paper.doi`, with only `/` replaced.
</details>
