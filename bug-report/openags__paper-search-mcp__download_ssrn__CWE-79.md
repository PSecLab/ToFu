# Missing output encoding in `download_ssrn`: an invalid `paper_id` is echoed verbatim in the error text

**Repository:** `openags/paper-search-mcp` · **Tool:** `download_ssrn` · **Tested commit:** `234678a`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
When `paper_id` is not a recognizable SSRN ID, `download_ssrn` returns `Invalid SSRN paper id: <paper_id>` with the raw input inside. Markup, template braces and control characters (including ESC) come back unchanged. The output is plain text, so this only matters if an MCP client renders tool results as HTML or Markdown, or prints them to a terminal. Low severity.

## Details
`paper_search_mcp/server.py:1256-1268` returns `SSRNSearcher.download_pdf(...)` directly. `paper_search_mcp/academic_platforms/ssrn.py:120-122`:

```python
abstract_id = self._extract_abstract_id(paper_id)
if not abstract_id:
    return f"Invalid SSRN paper id: {paper_id}"
```

`paper_id` is interpolated without escaping or stripping control characters. The string becomes the tool's text result.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No network or API key is needed: the invalid-ID path returns before any request.
2. Install the tested commit and use the README's pip start command:

   ```bash
   git clone https://github.com/openags/paper-search-mcp.git
   cd paper-search-mcp && git checkout 234678a && pip install .
   ```
3. Call the tool with harmless markup and an ESC byte:

   ```json
   {"paper_id": "<b>tofu-poc</b>{{7*7}}\u001b[1mTOFU", "save_path": ""}
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
               result = await session.call_tool("download_ssrn",
                   {"paper_id": "<b>tofu-poc</b>{{7*7}}\x1b[1mTOFU", "save_path": ""})
               print(repr(result.content[0].text))

   asyncio.run(main())
   ```
4. Observe that the result is `Invalid SSRN paper id: <b>tofu-poc</b>{{7*7}}\x1b[1mTOFU`, byte for byte.

## Expected behavior
Error messages either omit the rejected value or include a neutralized form (for example `repr()` of a truncated value, with control characters escaped).

## Actual behavior
The input is reflected unchanged. From the fuzzing run:

```
{'paper_id': '"\x1b"\x1ba\x1ba{{', 'save_path': ''}
-> Invalid SSRN paper id: "\x1b"\x1ba\x1ba{{
```

## Impact
The LLM chooses `paper_id`, and prompt injection can steer it, but the reflected value only reaches the same client that sent it. Harm requires a client that renders tool output as HTML/Markdown without sanitizing, or that writes it raw to a terminal (ESC sequences). No server-side effect. Severity: low.

## Suggested fix
Return a fixed message (`Invalid SSRN paper id`) or include `repr(paper_id[:100])` so control characters and markup are visibly escaped. The same pattern exists in `read_ssrn_paper`, which calls this function.

## Status on the default branch
Still present at `2dd3439` (2026-10-01): `ssrn.py` is unchanged.

## Prior reports
None found. Searched all 41 issues and 100 pull requests (fetched 2026-10-01) and the README / docs on the default branch.
- #56 "safety improvements" (PR, open 2026-04-16): the body is empty, so the JSON does not show what it changes. Check its diff before filing.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/116); only `check_reflected_output`.
- Campaigns and executions: corpus-sbx 3072 exec / 3072 ok; repo24 182272 / 182270 (4200 s).
- Evidence (verbatim, trimmed):
  - `{'paper_id': '"\x1b"\x1ba\x1ba{{', 'save_path': ''}` -> `Invalid SSRN paper id: "\x1b"\x1ba\x1ba{{`
  - `{'paper_id': '\x1b\x1b\x1b""a){{', 'save_path': ''}` -> `Invalid SSRN paper id: \x1b\x1b\x1b""a){{`
  - `{'paper_id': '\x1b\x1b\x1b":"a){{', 'save_path': ''}` -> `Invalid SSRN paper id: \x1b\x1b\x1b":"a){{`
- Hand-check hints: weak. Only `{{` was flagged, echoed into a plain-text error string; no HTML context exists in this server. The ESC bytes are the more concrete (still minor) concern. Probably not worth filing alone; could be a line in a general hardening issue. Unrelated observation: the server docstring says `save_path` is "unused" for SSRN, but at this commit `ssrn.py:131-132` does `os.makedirs(save_path)` and `os.path.join(save_path, ...)` once a PDF link resolves, with no containment. ToFu did not flag that here.
</details>
