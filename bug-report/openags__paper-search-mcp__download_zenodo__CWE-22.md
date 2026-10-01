# Path traversal in `download_zenodo`: `save_path` writes the PDF outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_zenodo` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_zenodo` fetches a Zenodo record, downloads its first PDF file and saves it as `<save_path>/zenodo_<record_id>.pdf`. `save_path` is used as given, so `../` sequences or an absolute path place the file anywhere the server user can write, and missing directories are created. The same function backs `read_zenodo_paper`, where our run observed writes to `../../../../etc/zenodo_24692.pdf` (canonical `/etc/zenodo_24692.pdf`).

## Details
`paper_search_mcp/server.py:1202-1212` passes `save_path` to `ZenodoSearcher.download_pdf`, `paper_search_mcp/academic_platforms/zenodo.py:146-156`:

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

The record ID is numeric, so the file name is safe. The directory is not: there is no download root and no `realpath`/`commonpath` check.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `zenodo.org`. `PAPER_SEARCH_MCP_ZENODO_ACCESS_TOKEN` is optional.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a record that has a PDF (record `24692` had one in our run) and a directory outside `./downloads`:

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
               result = await session.call_tool("download_zenodo",
                   {"paper_id": "24692", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/zenodo_24692.pdf` is created and its path is returned.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected.

## Actual behavior
Any directory is accepted. The logged `download_zenodo` calls used IDs that are not Zenodo records, so they stopped early:

```
{'paper_id': 'test_paper', 'save_path': '../../../../tmp'}
-> Could not determine Zenodo record ID from: test_paper
```

Through `read_zenodo_paper`, which calls this same function, our sandboxed run shows the write being attempted outside the working directory (the sandbox mounted it read-only):

```
{'paper_id': '24692', 'save_path': '../../../../etc/'}
-> Failed to download PDF from https://zenodo.org/api/records/24692/files/2675.pdf/content: [Errno 30] Read-only file system: '../../../../etc/zenodo_24692.pdf'
```

## Impact
Tool arguments come from the LLM and can be steered by prompt injection in untrusted content. An attacker can create directories and write a Zenodo-hosted PDF named `zenodo_<id>.pdf` into any directory the server user can write. Zenodo is an open repository where anyone with an account can publish a record, so an attacker can likely choose the content by publishing their own PDF. The name pattern still limits what can be overwritten. Severity: low to medium.

## Suggested fix
Resolve `save_path` under one download root before `os.makedirs` (`os.path.realpath` plus `os.path.commonpath`) and reject anything outside it. A shared helper used by all `download_*`/`read_*` tools would fix this and the sibling connectors at once.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `zenodo.py:147-156` is unchanged (only imports and metadata parsing changed). `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_file_access`, `check_introspection_insecure_file_permissions`, `check_introspection_sensitive_file_access`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 2048 exec / 1984 ok; repo24 58368 / 56726 (4200 s); e2-0922 512 / 501.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `Could not determine Zenodo record ID from: /etc/passwd\x00`
  - `{'paper_id': 'test_paper', 'save_path': '../../../../tmp'}` -> `Could not determine Zenodo record ID from: test_paper`
  - `{'paper_id': '"Aaper_id": "12345", "save_path": "/etc/passwd', 'save_path': '/etc/passwd'}` -> `Could not determine Zenodo record ID from: ...`
- Hand-check hints: real. This tool's own evidence never reached the write, but the identical code path is shown writing to a traversed path in the `read_zenodo_paper` evidence (corpus-sbx, record 24692), quoted above. Zenodo being an open-upload service makes content attacker-choosable; I did not test uploading. Record `24692` having a PDF is from the run log (2675.pdf); not re-checked.
</details>
