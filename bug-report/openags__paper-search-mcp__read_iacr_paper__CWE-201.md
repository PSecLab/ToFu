# `read_iacr_paper` writes the downloaded PDF to any caller-chosen `save_path`

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_iacr_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-201 Insertion of Sensitive Information Into Sent Data (reported); the evidence supports CWE-22 Path Traversal instead

## Summary
`read_iacr_paper` downloads an IACR ePrint PDF, saves it as `<save_path>/iacr_<id>.pdf`, reads it back and returns the text. `save_path` is used as given, so the file can be written to any directory the server user can write, and missing directories are created. Our fuzzer reported this as data exfiltration because the tool read a file and opened a network connection in the same call; on inspection the file read is the PDF the tool just downloaded, and no local data is sent anywhere.

## Details
`paper_search_mcp/server.py:588-602` calls `IACRSearcher.read_paper`, `paper_search_mcp/academic_platforms/iacr.py:243-257`:

```python
pdf_response = requests.get(paper.pdf_url, timeout=30)
pdf_response.raise_for_status()

# Create download directory if it doesn't exist
os.makedirs(save_path, exist_ok=True)

# Save the PDF
filename = f"iacr_{paper_id.replace('/', '_')}.pdf"
pdf_path = os.path.join(save_path, filename)

with open(pdf_path, "wb") as f:
    f.write(pdf_response.content)

# Extract text using PyPDF
reader = PdfReader(pdf_path)
```

There is no download root and no `realpath`/`commonpath` check on `save_path`.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `eprint.iacr.org`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
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
               result = await session.call_tool("read_iacr_paper",
                   {"paper_id": "2009/101", "save_path": "/tmp/tofu-poc-dir"})
               print(result.content[0].text[:400])

   asyncio.run(main())
   ```
4. Observe `PDF downloaded to: /tmp/tofu-poc-dir/iacr_2009_101.pdf` in the output and the new file on disk.

## Expected behavior
`save_path` must resolve inside a configured download directory, otherwise the call is rejected.

## Actual behavior
The PDF is written wherever `save_path` points. From the fuzzing run (Linux, so the backslashes became part of a directory name rather than traversal):

```
{'paper_id': '2009/101', 'save_path': '..\\..\\..\\..\\windows\\win.ini'}
-> Title: Encryption Schemes Secure under Selective Opening Attack
   Authors: Mihir Bellare, Scott Yilek
   ...
   PDF downloaded to: ..\..\..\..\windows\win.ini/iacr_2009_101.pdf
```

## Impact
Tool arguments are chosen by the LLM and can be steered by prompt injection. An attacker can create directories and write IACR PDFs named `iacr_<id>.pdf` in any writable directory. No local file content is disclosed: the text returned is the downloaded paper's. Severity: low.

## Suggested fix
Resolve `save_path` under one download root before `os.makedirs` (`os.path.realpath` plus `os.path.commonpath`) and reject anything outside it. Apply the same helper to `download_iacr` (`iacr.py:213-215`).

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `iacr.py:251-257` is unchanged (only request timeouts were added). The tool is now annotated `destructiveHint: True`.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten", and separates read tools that may download PDFs from metadata-only ones. Annotation only; no check on `save_path`, so it does not fix this.
- #128 "feat: enable keyless ACM search with validated DOI and safe tool metadata" (PR, closed 2026-09-30): marks PDF-reading tools as file-writing operations. Annotation only; no check on `save_path`.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: data-exfiltration (CWE-201). Triggered: `check_introspection_exfil`, `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_path_traversal`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 33792 / 33788 (4200 s).
- Evidence (verbatim, trimmed): all three calls are `{'paper_id': '2009/101', 'save_path': '..\\..\\..\\..\\windows\\win.ini'}` -> paper text with `PDF downloaded to: ..\\..\\..\\..\\windows\\win.ini/iacr_2009_101.pdf`; tracer: "tool READ sensitive/traversal file(s) ['..\\..\\..\\..\\windows\\win.ini/iacr_2009_101.pdf'] AND made outbound network connection(s) to ['172.67.143.219']", canonical path inside the per-tool scratch dir (`.tofu_scratch/openags__paper-search-mcp__read_iacr_paper/...`), mode 0o664, 5.3-6.2 s runtime.
- Hand-check hints: weak as CWE-201. The "read" is `PdfReader` on the file the tool just wrote, and the connection is the IACR download, so there is no read-local-then-send path. The canonical path stayed inside the server's working directory (backslashes are not separators on Linux). The real issue is the uncontained `save_path` write (CWE-22), already covered by the `download_iacr` draft; suggest merging rather than filing separately. Side note: `get_paper_details` (`iacr.py:306-316`) fetches any `paper_id` starting with `http` as a URL, which is an SSRF candidate not covered here.
</details>
