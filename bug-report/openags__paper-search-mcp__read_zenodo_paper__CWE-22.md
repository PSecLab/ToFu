# Path traversal in `read_zenodo_paper`: `save_path` writes the downloaded PDF outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_zenodo_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`read_zenodo_paper` downloads a Zenodo record's PDF to `<save_path>/zenodo_<record_id>.pdf` and returns its text. `save_path` is used as given, so `../` or an absolute path makes the server create directories and write the file anywhere the server user can write. In our run, `save_path: "../../../../etc/"` made the server try to write `/etc/zenodo_24692.pdf`.

## Details
`paper_search_mcp/server.py:1189-1199` calls `ZenodoSearcher.read_paper`, which calls `download_pdf(paper_id, save_path)` (`paper_search_mcp/academic_platforms/zenodo.py:170`). The write, `zenodo.py:146-156`:

```python
os.makedirs(save_path, exist_ok=True)
safe_name = re.sub(r"[^a-zA-Z0-9._-]+", "_", record_id) or record_id
output_path = os.path.join(save_path, f"zenodo_{safe_name}.pdf")

try:
    dl_response = self.session.get(pdf_url, stream=True, timeout=60)
    dl_response.raise_for_status()
    with open(output_path, "wb") as fh:
        for chunk in dl_response.iter_content(chunk_size=8192):
            fh.write(chunk)
    return output_path
```

The record ID is numeric, so the file name is safe, but `save_path` is never resolved or checked against a download root.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `zenodo.org`. `PAPER_SEARCH_MCP_ZENODO_ACCESS_TOKEN` is optional.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   mkdir -p /tmp/tofu-run && cd /tmp/tofu-run   # server working directory
   ```
3. Call the tool with a record that has a PDF (record `24692` did in our run) and a relative path that leaves the working directory:

   ```json
   {"paper_id": "24692", "save_path": "../tofu-poc-dir"}
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
               result = await session.call_tool("read_zenodo_paper",
                   {"paper_id": "24692", "save_path": "../tofu-poc-dir"})
               print(result.content[0].text[:400])

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/zenodo_24692.pdf` is created, outside `/tmp/tofu-run`, and the paper text is returned.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected before anything is created.

## Actual behavior
Any directory is accepted. The calls logged under this finding stopped before the write (bad ID, or a 404 record), for example:

```
{'paper_id': '123456', 'save_path': '../../../../etc/'}
-> Failed to fetch Zenodo record 123456: 404 Client Error: NOT FOUND for url: https://zenodo.org/api/records/123456
```

Another run of the same tool with an existing record reached the write and was stopped only by our read-only sandbox:

```
{'paper_id': '24692', 'save_path': '../../../../etc/'}
-> Failed to download PDF from https://zenodo.org/api/records/24692/files/2675.pdf/content: [Errno 30] Read-only file system: '../../../../etc/zenodo_24692.pdf'
```

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection in untrusted content. An attacker can create directories and write a Zenodo-hosted PDF named `zenodo_<id>.pdf` into any directory the server user can write. Zenodo is an open repository where anyone with an account can publish, so the attacker can likely choose the content. The fixed name pattern limits overwrites. Severity: low to medium.

## Suggested fix
Resolve `save_path` under one download root in `ZenodoSearcher.download_pdf` and reject anything outside it, before `os.makedirs`:

```python
root = os.path.realpath(DOWNLOAD_ROOT)
target = os.path.realpath(os.path.join(root, save_path))
if os.path.commonpath([root, target]) != root:
    return "save_path must stay inside the download directory"
```

This covers `download_zenodo` too. A shared helper would fix the other connectors with the same pattern.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `zenodo.py:147-156` is unchanged. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_insecure_file_permissions`, `check_introspection_path_traversal`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`.
- Campaigns and executions: repo24 13312 exec / 12702 ok (4200 s); e2-0922 512 / 512 (60 s).
- Evidence (verbatim, trimmed):
  - `{'paper_id': 'null', 'save_path': '/tmp/../tmp'}` -> `Could not determine Zenodo record ID from: null`
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `Could not determine Zenodo record ID from: /etc/passwd\x00`
  - `{'paper_id': '123456', 'save_path': '../../../../etc/'}` -> `Failed to fetch Zenodo record 123456: 404 Client Error: NOT FOUND ...`
- Hand-check hints: real. This finding's own evidence (repo24) never reached the write, but the corpus-sbx evidence for the same tool (filed by ToFu as CWE-201) shows `open()` on `../../../../etc/zenodo_24692.pdf`, canonical `/etc/zenodo_24692.pdf`; that call is quoted above as "another run". Merge the CWE-201 draft into this one. Record 24692 having a PDF comes from that log; not re-checked.
</details>
