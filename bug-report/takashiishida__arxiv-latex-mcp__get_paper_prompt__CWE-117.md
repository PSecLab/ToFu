# Log injection in `get_paper_prompt`: CR/LF in `arxiv_id` is written unescaped to the server log

**Repository:** `takashiishida/arxiv-latex-mcp` · **Tool:** `get_paper_prompt` · **Tested commit:** `9c1d8d0`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`get_paper_prompt` passes the caller's `arxiv_id` straight to `arxiv_to_prompt.process_latex_source()`. When the source cannot be fetched, a log record `TeX source files not available for <arxiv_id>` is written on the root logger, which this server sends to stderr at INFO level. A `\r` or `\n` in `arxiv_id` ends that record early and starts a new line whose text the caller chooses. The impact is small, and the fix is a short format check on the ID.

## Details
`arxiv_latex_mcp/server.py` at `9c1d8d0`:

```python
# Configure logging
logging.basicConfig(level=logging.INFO)            # line 20
...
    arxiv_id = arguments["arxiv_id"]               # line 141

    try:
        if name == "get_paper_prompt":             # lines 144-148
            await mcp_log("info", f"Processing arXiv paper: {arxiv_id}")
            prompt = process_latex_source(arxiv_id)
            result = prompt + LATEX_RENDER_INSTRUCTIONS
            await mcp_log("info", f"Successfully processed arXiv paper: {arxiv_id}")
```

The input schema (lines 70-83) only says `arxiv_id` is a string, and `handle_call_tool` does no format check. The record itself is written inside `arxiv_to_prompt` (locked at 0.10.0 in `uv.lock`), on the `root` logger. `logging.basicConfig(level=logging.INFO)` at line 20 gives the root logger a stderr handler, so the raw value reaches the server's stderr. The `mcp_log()` calls are MCP notifications and are JSON-encoded, so they are not affected. `list_paper_sections` and `get_paper_section` call the same function with the same unchecked value.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No account or API key is needed.
2. Start the server as the README describes (`uvx arxiv-latex-mcp`). To test the exact commit: `git clone https://github.com/takashiishida/arxiv-latex-mcp && cd arxiv-latex-mcp && git checkout 9c1d8d0 && uv run arxiv-latex-mcp`. The script below starts it for you.
3. Call the tool with `{"arxiv_id": "\r\nFAKE-LOG-ENTRY"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--directory", "/path/to/arxiv-latex-mcp", "arxiv-latex-mcp"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_paper_prompt", {"arxiv_id": "\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (`stdio_client` forwards it to your terminal). The record ends after `TeX source files not available for`, and the next line starts with `FAKE-LOG-ENTRY`.

## Expected behavior
An `arxiv_id` that is not a valid arXiv identifier is rejected before use. If it is logged, CR/LF are escaped so the record stays on one line.

## Actual behavior
The raw value is logged. Logged content captured by ToFu's tracer for an `arxiv_id` of eleven `\n` characters (each `\n` was a real line break, logger `root`):

```
TeX source files not available for \n\n\n\n\n\n\n\n\n\n\n
```

## Impact
Low. `arxiv_id` is chosen by the LLM, and the LLM can be steered by prompt injection in content it reads (a web page, a paper, a README that says "fetch arXiv paper ..."). The attacker can then add or split lines in the server's stderr. If the MCP host keeps that stderr in a log file, the attacker can write fake entries into it. There is no code execution or data access from this alone.

## Suggested fix
Validate the ID once in `handle_call_tool`, before any tool uses it:

```python
import re

ARXIV_ID_RE = re.compile(r"(\d{4}\.\d{4,5}|[a-z\-]+(\.[A-Z]{2})?/\d{7})(v\d+)?")

arxiv_id = str(arguments["arxiv_id"]).strip()
if not ARXIV_ID_RE.fullmatch(arxiv_id):
    return [types.TextContent(type="text", text="Invalid arXiv ID")]
```

If you want to keep accepting other forms that `arxiv_to_prompt` supports, at least reject IDs that contain control characters (`any(not c.isprintable() for c in arxiv_id)`). It may also be worth asking `arxiv_to_prompt` to log the ID with `%r`.

## Status on the default branch
Still present at `feb7949` (2026-09-19). The only change between the tested commit and HEAD is in `uv.lock`; `arxiv_latex_mcp/server.py` is unchanged.

## Prior reports
None found. Searched all 7 issues and 25 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117). Fired: `check_introspection_log_injection` only.
- Campaigns and executions: `corpus-sbx`: 1024 execs, 1024 success, 60 s budget; `e2-0922`: 1 exec, 1 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'arxiv_id': '\n\n\n\n\n\n\n\n\n\n\n'}`, output `None`, analysis "Unneutralized CRLF newline character detected in log output (logger:root)! Logged content: 'TeX source files not available for \n\n\n\n\n\n\n\n\n\n\n'." Also `{'arxiv_id': '"\x1f\r\x07\\'}` (logged with a raw `\r`) and `{'arxiv_id': '\n\n\n\n\n\n\x06\n\n\n\n'}`.
- Hand-check hints: **real, low severity.** Caller-supplied CR/LF does reach a log record raw. The sink is in the dependency `arxiv_to_prompt`, not in this repo; I could not read its source offline, so the exact logging call, its level, and whether the message appears without network access are taken from the fuzz log, not verified in code. Line numbers in this repo are verified. Same root cause as the `get_paper_abstract` and `get_paper_section` items; one issue for the repo would cover all three (plus `list_paper_sections`, which ToFu did not flag but uses the same path).
</details>
