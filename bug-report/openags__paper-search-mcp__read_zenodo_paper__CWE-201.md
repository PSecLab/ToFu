# `read_zenodo_paper` writes the downloaded PDF to any caller-chosen `save_path`

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_zenodo_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-201 Insertion of Sensitive Information Into Sent Data (reported); the evidence supports CWE-22 Path Traversal instead

## Summary
`read_zenodo_paper` downloads a Zenodo record's PDF to `<save_path>/zenodo_<record_id>.pdf`, then extracts and returns its text. `save_path` is used as given, so `../` or an absolute path makes the server create directories and write the file anywhere the server user can write. Our fuzzer reported this as data exfiltration because a traversed path was opened during a call that also contacted Zenodo; the opened file is the tool's own download target, and no local data is sent anywhere.

## Details
`paper_search_mcp/server.py:1189-1199` calls `ZenodoSearcher.read_paper`, which calls `download_pdf(paper_id, save_path)` first (`paper_search_mcp/academic_platforms/zenodo.py:170`). The write is at `zenodo.py:146-156`:

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

`save_path` is not resolved or compared with a download root.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `zenodo.org`. `PAPER_SEARCH_MCP_ZENODO_ACCESS_TOKEN` is optional.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with the record from the fuzzing run and a directory outside `./downloads`:

   ```json
   {"paper_id": "24692", "save_path": "/tmp/tofu-poc-dir"}
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
                   {"paper_id": "24692", "save_path": "/tmp/tofu-poc-dir"})
               print(result.content[0].text[:400])

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/zenodo_24692.pdf` is created and its text is returned.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected.

## Actual behavior
The write goes to the traversed path. It failed only at the filesystem level (our sandbox mounts that path read-only), not because the code rejected it:

```
{'paper_id': '24692', 'save_path': '../../../../etc/'}
-> Failed to download PDF from https://zenodo.org/api/records/24692/files/2675.pdf/content: [Errno 30] Read-only file system: '../../../../etc/zenodo_24692.pdf'
```

The tracer resolved that path to `/etc/zenodo_24692.pdf`.

## Impact
Tool arguments come from the LLM and can be steered by prompt injection. An attacker can create directories and write Zenodo-hosted PDFs named `zenodo_<id>.pdf` into any writable directory. No local file content is disclosed: the returned text is the downloaded record's. Severity: low.

## Suggested fix
Resolve `save_path` under one download root in `download_pdf` (`os.path.realpath` plus `os.path.commonpath`) and reject anything outside it. That also fixes `download_zenodo`.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `zenodo.py:147-156` is unchanged. The tool is now annotated `destructiveHint: True`.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: data-exfiltration (CWE-201). Triggered: `check_introspection_exfil`, `check_introspection_insecure_file_permissions`, `check_introspection_path_traversal`, `check_path_traversal`.
- Campaigns and executions: corpus-sbx 1024 exec / 1010 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'paper_id': '24692', 'save_path': '../../../../etc/'}` -> `Failed to download PDF from https://zenodo.org/api/records/24692/files/2675.pdf/content: [Errno 30] Read-only file system: '../../../../etc/zenodo_24692.pdf'`; tracer: READ `../../../../etc/zenodo_24692.pdf` and outbound to `188.185.43.153`; canonical `/etc/zenodo_24692.pdf`.
  - `{'paper_id': '24672', 'save_path': '..'}` -> `... [Errno 30] Read-only file system: '../zenodo_24672.pdf'`; canonical inside `.tofu_scratch/`, outside the target dir.
  - `{'paper_id': '24682', 'save_path': '..'}` -> same shape for record 24682.
- Hand-check hints: weak as CWE-201. The "read" is the `open(output_path, "wb")` on the download target, and the connection is to Zenodo, so there is no read-local-then-send path. The path traversal itself is real and clearly shown here; it duplicates the `read_zenodo_paper` CWE-22 draft, so merge into that one rather than filing twice.
</details>
