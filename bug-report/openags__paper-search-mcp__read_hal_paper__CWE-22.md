# Path traversal in `read_hal_paper`: `save_path` lets the caller write the downloaded PDF anywhere

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_hal_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_hal_paper` downloads a HAL PDF with `HALSearcher.download_pdf` and then extracts its text. The download step creates `save_path` and writes `hal_<id>.pdf` into it without any containment, so `../` or an absolute path puts the file anywhere the server user can write.

## Details
`paper_search_mcp/server.py:1215-1225` calls `HALSearcher.read_paper`, which calls `download_pdf(paper_id, save_path)` first (`paper_search_mcp/academic_platforms/hal.py:165`). The write is at `hal.py:141-150`:

```python
os.makedirs(save_path, exist_ok=True)
safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", hal_id) or hal_id
output_path = os.path.join(save_path, f"hal_{safe_name}.pdf")

try:
    dl_response = self.session.get(pdf_url, stream=True, timeout=60)
    dl_response.raise_for_status()
    with open(output_path, "wb") as fh:
        for chunk in dl_response.iter_content(chunk_size=8192):
            fh.write(chunk)
```

The file name is sanitized; the directory is not checked against any root.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `api.archives-ouvertes.fr` and `hal.archives-ouvertes.fr`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Take a `paper_id` with a non-empty `pdf_url` from `search_hal`, then read it into a directory outside `./downloads`:

   ```json
   {"paper_id": "<hal:id with a pdf_url, from search_hal>", "save_path": "/tmp/tofu-poc-dir"}
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
               print(await session.call_tool("search_hal", {"query": "machine learning", "max_results": 10}))
               result = await session.call_tool("read_hal_paper",
                   {"paper_id": "<hal:id from above>", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/hal_<id>.pdf` is created and the tool returns its text.

## Expected behavior
`save_path` must resolve inside a configured download directory; otherwise the call is rejected before anything is created.

## Actual behavior
Any directory is accepted. The logged calls used IDs with no HAL PDF, so they stopped before the write:

```
{'paper_id': 'valid-paper-id', 'save_path': '../../../../etc'}
-> No open-access PDF found on HAL for valid-paper-id. The document may be metadata-only or under embargo.
```

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection in untrusted content. An attacker can create directories and write a HAL PDF named `hal_<id>.pdf` into any writable directory. Name and content are not attacker-chosen, which limits the effect to clutter, disk use and file planting. Severity: low.

## Suggested fix
Resolve `save_path` under one download root in `download_pdf` (`os.path.realpath` plus `os.path.commonpath`) and reject anything outside it. Fixing it there also fixes `download_hal`.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `hal.py:142-149` is unchanged. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_path_traversal`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_reflected_output`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 10240 / 6319 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': 'valid-paper-id', 'save_path': '../../../../etc'}` -> `No open-access PDF found on HAL for valid-paper-id. ...`
  - `{'paper_id': 'valid-paper-id', 'save_path': './downloads/../secret'}` -> same
- Hand-check hints: real at code level, low severity. Retained evidence never reached the write. `check_introspection_path_traversal` in the triggered set means some repo24 call touched a path outside the target dir, but that call is not in the evidence. Same root cause as `download_hal`; file together. Step 3 needs a real HAL ID with a PDF, not chosen offline.
</details>
