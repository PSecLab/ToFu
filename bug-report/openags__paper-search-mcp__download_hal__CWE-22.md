# Path traversal in `download_hal`: `save_path` lets the caller create directories and write the PDF anywhere

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_hal` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal

## Summary
`download_hal` downloads an open-access PDF from HAL and saves it as `<save_path>/hal_<id>.pdf`. The file name is sanitized, but `save_path` is used as given: it can be absolute or contain `../`, and missing directories are created. Any caller can make the server create directories and drop a HAL PDF in any location the server user can write.

## Details
`paper_search_mcp/server.py:1228-1238` passes `save_path` to `HALSearcher.download_pdf`, `paper_search_mcp/academic_platforms/hal.py:141-150`:

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

`hal_id` is sanitized, `save_path` is not. There is no download root and no `realpath`/`commonpath` check, so `os.makedirs` and `open` act on whatever directory the caller names. The write only happens when `_resolve_pdf_url()` finds a PDF for the HAL ID (`hal.py:196-210`).

## Steps to reproduce
1. Prerequisites: Python 3.10+ and outbound HTTPS to `api.archives-ouvertes.fr` and `hal.archives-ouvertes.fr`. No API key is needed.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Find a HAL document with a PDF (`search_hal` returns `paper_id` values like `hal:<id>` with a non-empty `pdf_url`), then download it to a directory outside `./downloads`:

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
               result = await session.call_tool("download_hal",
                   {"paper_id": "<hal:id from above>", "save_path": "/tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe that `/tmp/tofu-poc-dir/` was created and holds `hal_<id>.pdf`, and that the tool returns that path. A relative value such as `../../../../tmp/tofu-poc-dir` works the same way.

## Expected behavior
`save_path` must resolve inside a configured download directory; anything else is rejected before any directory is created.

## Actual behavior
Any directory is accepted. In the fuzzing run the logged calls used IDs with no HAL PDF, so they returned before the write:

```
{'paper_id': 'normal-paper-id', 'save_path': '../../../../etc/'}
-> No open-access PDF found on HAL for normal-paper-id. The document may be metadata-only or under embargo.
```

## Impact
Tool arguments come from the LLM and can be steered by prompt injection in untrusted content such as search results. An attacker can create directories and write a HAL-hosted PDF named `hal_<id>.pdf` into any writable directory. The file name and content are not attacker-chosen, so the main effects are clutter, disk use, and planting files in unexpected places. Severity: low.

## Suggested fix
Resolve `save_path` against a single download root and reject it if it leaves that root, before calling `os.makedirs`:

```python
root = os.path.realpath(DOWNLOAD_ROOT)
target = os.path.realpath(os.path.join(root, save_path))
if os.path.commonpath([root, target]) != root:
    return "save_path must stay inside the download directory"
```

The same helper should be used by every `download_*` and `read_*` tool that takes `save_path`.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `hal.py:142-149` is unchanged. `server.py` now marks the tool `destructiveHint: True` but adds no path check.

## Prior reports
- #120 "feat(mcp): publish accurate tool annotations" (PR, closed 2026-09-22): marks download tools as local-file-writing and potentially destructive "because existing paths may be overwritten". This is the `destructiveHint: True` on the default branch. It labels the risk but adds no check on `save_path`, so it does not fix this.
- #76 "[codex] complete paper search fallback workflow" (PR, open 2026-05-19): adds a "configurable default output directory and paper filename helpers". The body does not mention rejecting `save_path` values outside that directory, so as described it would not fix this.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.
- Documentation: README.md: "`read_acm_paper` downloads a PDF into `save_path` before extracting text and can overwrite that file" (the only README mention of `save_path`; it covers the ACM tool and does not say where `save_path` may point). There is no SECURITY.md, and nothing in `docs/` or `claude-code/SKILL.md` restricts or warns about `save_path`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22). Triggered: `check_introspection_incomplete_cleanup`, `check_introspection_insecure_file_permissions`, `check_introspection_temp_file_leak`, `check_path_traversal`, `check_reflected_output`, `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 1 exec / 1 ok; repo24 12288 / 8972 (4200 s); e2-0922 1 / 1.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '/etc/passwd\x00', 'save_path': '../'}` -> `No open-access PDF found on HAL for /etc/passwd\x00. ...`
  - `{'paper_id': 'normal-paper-id', 'save_path': '../../../../etc/'}` -> `No open-access PDF found on HAL for normal-paper-id. ...`
- Hand-check hints: real at code level, low severity. The retained evidence never reached `os.makedirs`/`open` (no PDF resolved); the alert is the input-pattern check. The introspection file alerts in the triggered set suggest some repo24 call did write a file, but no such call is in the evidence. Step 3 needs a real HAL ID with a PDF, which I could not pick offline. Same pattern as `read_hal_paper` (which calls this function); consider one consolidated `save_path` issue.
</details>
