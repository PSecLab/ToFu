# `read_openalex_paper` accepts a `save_path` it never uses (reported path traversal is not reachable)

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_openalex_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal (reported; not reachable at this commit)

## Summary
`read_openalex_paper` always returns a fixed "OpenAlex papers cannot be read directly" message. It takes a `save_path` argument, but nothing uses it, so traversal values have no effect. Our fuzzer flagged it only because such inputs were accepted without an error. This is a hardening note, not a vulnerability.

## Details
`paper_search_mcp/server.py:1271-1281` returns `OpenAlexSearcher.read_paper(...)`, `paper_search_mcp/academic_platforms/openalex.py:165-172`:

```python
def read_paper(self, paper_id: str, save_path: str = "./downloads") -> str:
    """
    Not implemented for OpenAlex.
    """
    return (
        "OpenAlex papers cannot be read directly through this aggregator. "
        "Please use the paper's DOI or pdf_url to access the full text."
    )
```

No file operation uses `save_path`.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No network or API key is needed for this call.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a traversal `save_path`:

   ```json
   {"paper_id": "10.1234/validpaperid", "save_path": "../../../../tmp/tofu-poc-dir"}
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
               result = await session.call_tool("read_openalex_paper",
                   {"paper_id": "10.1234/validpaperid", "save_path": "../../../../tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the fixed message and that nothing is created on disk.

## Expected behavior
An unused `save_path` is removed from the tool schema, or validated by the same helper as the other `read_*` tools.

## Actual behavior
The fixed message is returned. From the fuzzing run:

```
{'paper_id': 'null', 'save_path': '/etc/passwd'}
-> OpenAlex papers cannot be read directly through this aggregator. Please use the paper's DOI or pdf_url to access the full text.
```

## Impact
None at this commit. The argument is LLM-chosen and could be steered by prompt injection, but it reaches no file operation.

## Suggested fix
Remove `save_path` from `read_openalex_paper`, or route it through a shared `resolve_save_dir()` helper (realpath plus a check against a configured download root) so a future implementation cannot reintroduce the uncontained pattern used by other connectors.

## Status on the default branch
Still the same at `2dd3439` (2026-10-01): `openalex.py:194-201` returns the fixed message without using `save_path`.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); only `check_path_traversal` (input-pattern "Silent Bug Alert").
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok; repo24 219136 / 219136 (4200 s); e2-0922 1024 / 1024.
- Evidence (verbatim, trimmed):
  - `{'paper_id': 'null', 'save_path': '/etc/passwd'}` -> fixed OpenAlex message
  - `{'paper_id': '10.1234/validpaperid', 'save_path': '../../../../../tmp'}` -> same
  - `{'paper_id': '10.7777/cleanup', 'save_path': '/tmp/cleanup_test/../cleanup_test'}` -> same
- Hand-check hints: weak, false positive. `save_path` is never used. Recommend not filing.
</details>
