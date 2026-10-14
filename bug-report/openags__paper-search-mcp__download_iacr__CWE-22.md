# Path traversal in `download_iacr`: `save_path` writes the PDF outside the download directory

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_iacr` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_iacr` fetches an IACR ePrint PDF and saves it as `<save_path>/iacr_<id>.pdf`. `save_path` is used as given, so `../` sequences and absolute paths are accepted and missing directories are created. In our run, `save_path: "../../../../../tmp"` made the server write `/tmp/iacr_2009_101.pdf`.

## Details
`paper_search_mcp/server.py:511-521` passes `save_path` to `IACRSearcher.download_pdf`, `paper_search_mcp/academic_platforms/iacr.py:208-217`:

```python
pdf_url = f"{self.IACR_BASE_URL}/{paper_id}.pdf"

response = self.session.get(pdf_url)

if response.status_code == 200:
    filename = f"{save_path}/iacr_{paper_id.replace('/', '_')}.pdf"
    os.makedirs(save_path, exist_ok=True)
    with open(filename, "wb") as f:
        f.write(response.content)
    return filename
```

`/` in `paper_id` is replaced, but `save_path` is not resolved or checked against any root. The content is not checked to be a PDF either.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `eprint.iacr.org`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   mkdir -p /tmp/tofu-run && cd /tmp/tofu-run   # server working directory
   ```
3. Call the tool with a directory outside `./downloads`:

   ```json
   {"paper_id": "2009/101", "save_path": "/tmp/tofu-poc-dir"}
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
               result = await session.call_tool("download_iacr",
                   {"paper_id": "2009/101", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/iacr_2009_101.pdf` is created and its path is returned. The relative form `"../../../../../tmp"` from the fuzzing run gives `/tmp/iacr_2009_101.pdf`.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected.

## Actual behavior
The file is written wherever `save_path` points. From the fuzzing run (the tool's own tracer saw the file created at `/tmp/iacr_2009_101.pdf` with mode `0o664`):

```
{'paper_id': '2009/101', 'save_path': '../../../../../tmp'}
-> ../../../../../tmp/iacr_2009_101.pdf

{'paper_id': '2009/101', 'save_path': '/etc/passwd'}
-> Error downloading PDF: [Errno 17] File exists: '/etc/passwd'
```

The second call shows `os.makedirs` being run on an arbitrary system path.

## Impact
The LLM chooses `save_path`, and prompt injection in untrusted content can steer it. An attacker can create directories and drop IACR PDFs named `iacr_<id>.pdf` anywhere the server user can write, and overwrite an existing file of that name. The file name pattern and the content (an IACR ePrint) limit the damage. Severity: low.

## Suggested fix
Resolve `save_path` under one download root before `os.makedirs` and reject paths that leave it (`os.path.realpath` plus `os.path.commonpath`). Use the same helper for `read_iacr_paper`, which has the same code at `iacr.py:247-253`, and for the other connectors.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `iacr.py:217-220` is unchanged. Recent changes only added request timeouts and a `destructiveHint: True` tool annotation.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`, `check_url_ssrf_ip_ranges`, `check_url_structure_and_parsing`.
- Campaigns and executions: corpus-sbx 512 exec / 508 ok; repo24 35840 / 35836 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '2009/101', 'save_path': '/etc/passwd'}` -> `Error downloading PDF: [Errno 17] File exists: '/etc/passwd'`
  - `{'paper_id': '2009/101', 'save_path': '../../../../../tmp'}` -> `../../../../../tmp/iacr_2009_101.pdf`; tracer: "left 1 uncleaned temporary resource(s) on disk: ['/tmp/iacr_2009_101.pdf']", "created/modified file ... with insecure permissive mode octal '0o664'".
- Hand-check hints: real, demonstrated by the logged write to `/tmp/iacr_2009_101.pdf`. Low severity because the name is fixed to `iacr_<id>.pdf` and content comes from IACR. The SSRF sanitizers in the triggered set fired on the input pattern; `pdf_url` always targets `eprint.iacr.org` in this function.
</details>
