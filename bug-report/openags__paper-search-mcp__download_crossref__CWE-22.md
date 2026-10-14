# `download_crossref` accepts a `save_path` it never uses (reported path traversal is not reachable)

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_crossref` · **Tested commit:** `234678a`
**Weakness:** CWE-22 Path Traversal (reported; not reachable at this commit)

## Summary
`download_crossref` always returns a fixed "CrossRef does not provide direct PDF downloads" message. It takes a `save_path` argument, but the code never touches the filesystem with it, so traversal values like `../../../../etc/passwd` have no effect. Our fuzzer flagged the tool only because such inputs were accepted without an error. This is a hardening note, not a vulnerability.

## Details
`paper_search_mcp/server.py:714-731` calls `CrossRefSearcher.download_pdf`, `paper_search_mcp/academic_platforms/crossref.py:233-247`:

```python
def download_pdf(self, paper_id: str, save_path: str) -> str:
    ...
    message = ("CrossRef does not provide direct PDF downloads. "
              "CrossRef is a citation database that provides metadata about academic papers. "
              "To access the full text, please use the paper's DOI or URL to visit the publisher's website.")
    raise NotImplementedError(message)
```

The server catches `NotImplementedError` and returns the message. `save_path` is not read, joined, or created. Other connectors in this repo use the same `save_path` argument without containment (for example `arxiv.py:81-88`), so if a download is ever added here it would inherit that problem unless a shared check exists.

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
               result = await session.call_tool("download_crossref",
                   {"paper_id": "10.1038/nature12373", "save_path": "../../../../tmp/tofu-poc-dir"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the fixed message and that no directory or file is created.

## Expected behavior
An unused `save_path` is either removed from the tool schema or validated by the same helper as the other download tools, so the schema does not suggest a write that never happens.

## Actual behavior
The fixed message is returned. From the fuzzing run:

```
{'paper_id': '10.1038/nature12373', 'save_path': '../../../../etc/passwd'}
-> CrossRef does not provide direct PDF downloads. CrossRef is a citation database ...
```

## Impact
None at this commit. The argument is chosen by the LLM and could be steered by prompt injection, but it reaches no file operation.

## Suggested fix
Drop `save_path` from `download_crossref`, or route it through a shared `resolve_save_dir()` helper (realpath plus a check that it stays under a configured download root) used by every download tool.

## Status on the default branch
Still the same at `2dd3439` (2026-10-01): `crossref.py:256-270` still raises `NotImplementedError` without using `save_path`.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); only `check_path_traversal` (input-pattern "Silent Bug Alert").
- Campaigns and executions: corpus-sbx 3072 exec / 3064 ok; repo24 221184 / 221176 (4200 s); e2-0922 1024 / 1016.
- Evidence (verbatim, trimmed):
  - `{'paper_id': '10.1038/nature12373', 'save_path': '../../../../etc/passwd'}` -> `CrossRef does not provide direct PDF downloads. ...`
  - `{'paper_id': '10.1038/nature12373', 'save_path': './downloads/../../secret'}` -> same message.
- Hand-check hints: weak, false positive. `save_path` is never used; the alert fired on the input string alone. Recommend not filing; at most mention it inside a consolidated `save_path` issue.
</details>
