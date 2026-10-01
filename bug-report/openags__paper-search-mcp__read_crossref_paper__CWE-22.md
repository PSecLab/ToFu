# `read_crossref_paper` accepts a `save_path` it never uses (reported path traversal is not reachable)

**Repository:** `openags/paper-search-mcp` · **Tool:** `read_crossref_paper` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal (reported; not reachable at this commit)

## Summary
`read_crossref_paper` always returns a fixed "CrossRef papers cannot be read directly" message. Its `save_path` argument is documented as the PDF directory but is never used, so traversal values have no effect. Our fuzzer flagged it only because such inputs were accepted without an error. This is a hardening note, not a vulnerability.

## Details
`paper_search_mcp/server.py:849-863` returns `CrossRefSearcher.read_paper(...)`, `paper_search_mcp/academic_platforms/crossref.py:249-264`:

```python
def read_paper(self, paper_id: str, save_path: str = "./downloads") -> str:
    ...
    message = ("CrossRef papers cannot be read directly through this tool. "
              "CrossRef is a citation database that provides metadata about academic papers. "
              "Only metadata and abstracts are available through CrossRef's API. "
              "To access the full text, please use the paper's DOI or URL to visit the publisher's website.")
    return message
```

No file operation uses `save_path`. The concern is only that other `read_*` tools take the same argument without containment, so a future implementation here could inherit that.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No network or API key is needed for this call.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with a traversal `save_path`:

   ```json
   {"paper_id": "10.1038/nature12373", "save_path": "../../../../tmp/tofu-poc-dir"}
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
               result = await session.call_tool("read_crossref_paper",
                   {"paper_id": "10.1038/nature12373", "save_path": "../../../../tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the fixed message and that nothing is created on disk.

## Expected behavior
An unused `save_path` is removed from the tool schema, or validated by the same helper as the other `read_*` tools.

## Actual behavior
The fixed message is returned. From the fuzzing run:

```
{'paper_id': '10.1000/xyz123', 'save_path': '/etc/passwd'}
-> CrossRef papers cannot be read directly through this tool. CrossRef is a citation database ...
```

## Impact
None at this commit. The argument is LLM-chosen and could be steered by prompt injection, but it reaches no file operation.

## Suggested fix
Remove `save_path` from `read_crossref_paper`, or pass it through a shared `resolve_save_dir()` helper (realpath plus a check against a configured download root) used by every tool that takes `save_path`.

## Status on the default branch
Still the same at `2dd3439` (2026-10-01): `crossref.py:272-287` returns the fixed message without using `save_path`.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); only `check_path_traversal` (input-pattern "Silent Bug Alert").
- Campaigns and executions: corpus-sbx 3072 exec / 3064 ok; repo24 217600 / 217592 (4200 s); e2-0922 512 / 504.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '10.5555/12345678', 'save_path': '../\x00'}` -> fixed CrossRef message
  - `{'paper_id': '10.1000/xyz123', 'save_path': '/etc/passwd'}` -> same
  - `{'paper_id': '10.1038/nature12373', 'save_path': '../../../../etc/passwd'}` -> same
- Hand-check hints: weak, false positive. `save_path` is unused; the alert fired on the input string alone. Recommend not filing.
</details>
