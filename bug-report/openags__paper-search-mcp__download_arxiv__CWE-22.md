# Path traversal in `download_arxiv`: `paper_id` and `save_path` can write a file anywhere on disk

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_arxiv` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_arxiv` fetches `https://arxiv.org/pdf/<paper_id>.pdf` and saves the response as `<save_path>/<paper_id>.pdf`. Neither argument is checked, so `save_path` can be any directory and `paper_id` can contain `../`. The response body is written even when arXiv returns an error page. A caller can therefore create or overwrite any `*.pdf` path the server user can write.

## Details
`paper_search_mcp/server.py:456-466` passes both arguments straight to `ArxivSearcher.download_pdf`, `paper_search_mcp/academic_platforms/arxiv.py:81-88`:

```python
def download_pdf(self, paper_id: str, save_path: str) -> str:
    pdf_url = f"https://arxiv.org/pdf/{paper_id}.pdf"
    response = requests.get(pdf_url)
    os.makedirs(save_path, exist_ok=True)
    output_file = f"{save_path}/{paper_id}.pdf"
    with open(output_file, 'wb') as f:
        f.write(response.content)
    return output_file
```

There is no download root, no `realpath` check, and no format check on `paper_id` (unlike other connectors, `/` is not even replaced). The HTTP status is not checked either, so the file is always written. `os.makedirs(save_path)` also creates any missing directories.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `arxiv.org`. No API key is needed.
2. Install the tested commit and use the README's pip start command (`python -m paper_search_mcp.server`):

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   mkdir -p /tmp/tofu-run && cd /tmp/tofu-run   # server working directory
   ```
3. Call the tool twice: once with `save_path` outside `./downloads`, once with `../` in `paper_id`:

   ```json
   {"paper_id": "2106.12345", "save_path": "/tmp/tofu-poc-dir"}
   {"paper_id": "../../../../../../../../tmp/tofu-poc", "save_path": "./downloads"}
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
               for args in (
                   {"paper_id": "2106.12345", "save_path": "/tmp/tofu-poc-dir"},
                   {"paper_id": "../../../../../../../../tmp/tofu-poc", "save_path": "./downloads"},
               ):
                   result = await session.call_tool("download_arxiv", args)
                   print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/2106.12345.pdf` and `/tmp/tofu-poc.pdf` now exist, and that the tool returns those paths. The second file holds whatever arXiv returned for the odd URL (likely an error page), which shows the write does not depend on a successful download.

## Expected behavior
`paper_id` is validated as an arXiv identifier, the target directory must resolve inside a configured download directory, and nothing is written unless the response is a PDF.

## Actual behavior
Both files are created outside `./downloads`. No fuzzing log survived for this tool, so there is no real output to quote. The behavior above follows directly from `arxiv.py:81-88`.

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in untrusted content (a paper abstract, a web page, a search result) can steer them. An attacker who controls the arguments can create directories and create or overwrite any file ending in `.pdf` that the server user can write, for example replacing a user's existing PDF with an arXiv error page. The attacker does not fully control the file content, so this is data loss and file planting rather than code execution. Severity: medium-low.

## Suggested fix
- Validate `paper_id` against the arXiv ID formats (for example `^\d{4}\.\d{4,5}(v\d+)?$` and `^[a-z-]+(\.[A-Z]{2})?/\d{7}(v\d+)?$`) and build the file name from a sanitized copy.
- Resolve the target directory under one download root and reject anything outside it. One shared helper can serve every `download_*` and `read_*` tool:

  ```python
  ROOT = os.path.realpath(os.environ.get("PAPER_SEARCH_MCP_DOWNLOAD_DIR", "./downloads"))  # new setting

  def resolve_save_dir(save_path: str) -> str:
      target = os.path.realpath(os.path.join(ROOT, save_path))
      if os.path.commonpath([ROOT, target]) != ROOT:
          raise ValueError("save_path must stay inside the download directory")
      return target
  ```
- Call `response.raise_for_status()` and check for a PDF before writing.

## Status on the default branch
Still present at `2dd3439` (2026-10-01). `arxiv.py:226-233` is unchanged. The tool is now annotated `destructiveHint: True` in `server.py`, but there is still no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_file_access`, `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_insecure_temp_permissions`, `check_introspection_sensitive_file_access`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_resource_exhaustion`.
- Campaigns and executions: e2-0922 only, 1 exec / 0 ok (60 s budget).
- Evidence: none. `log_available: false`, `n_ev: 0`. Reproduction derived from source, not run.
- Hand-check hints: real. Both arguments reach `open(..., 'wb')` unchecked, and the write happens regardless of HTTP status. The second call in step 3 relies on `os.makedirs("./downloads")` running before `open()`, which it does. I could not confirm which call triggered the sensitive-file alerts since no log exists. Many tools in this repo share the same `save_path` pattern (see the sibling drafts for `download_iacr`, `download_zenodo`, `read_biorxiv_paper`, etc.); consider filing one consolidated issue instead of many.
</details>
