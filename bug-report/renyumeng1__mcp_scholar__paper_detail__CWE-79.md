# Missing output encoding in `paper_detail`: unknown `paper_id` is echoed verbatim in the error message

**Repository:** `renyumeng1/mcp_scholar` · **Tool:** `paper_detail` · **Tested commit:** `5e12e93`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
When `paper_detail` cannot find a paper, it returns an error message that contains the caller's `paper_id` unchanged. The result is serialized as JSON text, so the value stays inside a JSON string, but markup and control characters in it are not neutralized. This only matters if a client renders the tool result as HTML or Markdown. In most clients it is cosmetic.

## Details
`src/mcp_scholar/server.py:296-314`:
```python
    try:
        logger.info(f"正在获取论文ID为 {paper_id} 的详细信息...")
        detail = await get_paper_detail(paper_id)

        if detail:
            ...
            return {"status": "success", "detail": detail}
        else:
            logger.warning(f"未找到ID为 {paper_id} 的论文")
            return {"status": "error", "message": f"未找到ID为 {paper_id} 的论文"}
```
`get_paper_detail` (`src/mcp_scholar/scholar.py:248-335`) returns `None` for any non-200 response and for any exception, so every unknown or malformed ID reaches this branch. FastMCP then turns the dict into a JSON string, which escapes quotes and non-ASCII characters but leaves `<`, `>` and `{` as they are. `paper_id` is not checked against the ID formats the function accepts (DOI, OpenAlex `W...`, `arxiv:...`).

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API key. Copy `.env.example` to `.env` in the repository root (this avoids a warning that `scholar.py:40` prints to stdout at import). Network access to `api.openalex.org` is optional: without it the request fails and the same error branch is taken.
2. Start the server as the README describes:
   ```bash
   git clone https://github.com/renyumeng1/mcp_scholar && cd mcp_scholar
   git checkout 5e12e93
   cp .env.example .env
   uv --directory . run mcp-scholar   # optional: the client script below starts it
   ```
3. Call the tool with these arguments:
   ```json
   {"paper_id": "<b>tofu-poc</b>{{7*7}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uv", args=["--directory", "/path/to/mcp_scholar", "run", "mcp-scholar"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("paper_detail", {"paper_id": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `<b>tofu-poc</b>{{7*7}}` unchanged inside the `message` field of the returned JSON text.

## Expected behavior
`paper_id` is validated against the supported ID formats and rejected with a fixed message, or it is not echoed.

## Actual behavior
The ID is echoed. From the fuzzing run (input ``{'paper_id': '%`ZZ{{'}``):
```
{"status": "error", "message": "\u672a\u627e\u5230ID\u4e3a %`ZZ{{ \u7684\u8bba\u6587"}
```

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them, but the value is reflected only to the same client that sent it, inside a JSON string. Risk exists only for clients that render tool output as HTML or Markdown without escaping.

## Suggested fix
Validate `paper_id` up front (for example DOI `^10\.\d{4,9}/\S+$`, OpenAlex `^W?\d+$`, `^arxiv:[\w./-]+$`) and return a fixed error for anything else. If the ID must be echoed, strip control characters and limit its length. As a related cleanup, the `print()` calls in `scholar.py` write to stdout, which is the JSON-RPC channel in stdio mode. They should use `logger` (stderr) instead.

## Status on the default branch
Still present at `5e12e93` (2025-03-22). The tested commit is the current default branch head.

## Prior reports
- No issue or PR reports this. The repository has 0 issues and 1 pull request (fetched 2026-10-01); the README on the default branch has no security notes.
- #1 "Fix OpenAlex URL construction bugs: DOI double-prefix, duplicate filter params, malformed mailto" (PR, open 2026-04-02): changes how `paper_detail` builds `doi_url`, but does not validate `paper_id` or change the error message that echoes it. Not a fix.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (token `{{`). Tool-level triggered set also includes `check_introspection_log_injection` (the `logger.info` at `server.py:298` logs the raw `paper_id`, same pattern as the `paper_references` draft).
- Campaigns and executions: `corpus-sbx` 512 exec / 506 success (60 s).
- Evidence (verbatim, trimmed): input `{'paper_id': '"p{{"p\x00\x00'}`; output `'{"status": "error", "message": "\\u672a\\u627e\\u5230ID\\u4e3a \\"p{{\\"p\\u0000\\u0000 \\u7684\\u8bba\\u6587"}'`. Input ``{'paper_id': '%`ZZ{{'}``; output ``'{"status": "error", "message": "...ID\\u4e3a %`ZZ{{ \\u7684\\u8bba\\u6587"}'``.
- Hand-check hints: weak. Only `{{` was echoed, inside a JSON string in a text content block. JSON escaping handles quotes and NUL (`\u0000`), so this is not exploitable in a normal client. Probably not worth filing on its own. The side observation that `print()` in `scholar.py` (lines 40, 330, 334 and others) writes to stdout in stdio mode is a real reliability bug and may be the better issue to file; not run to confirm that it breaks a client. The `<b>` payload is my extrapolation; not run.
</details>
