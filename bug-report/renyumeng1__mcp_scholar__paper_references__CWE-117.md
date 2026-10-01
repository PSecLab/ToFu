# Log injection in `paper_references`: CR/LF in `paper_id` is written unneutralized to the server log

**Repository:** `renyumeng1/mcp_scholar` · **Tool:** `paper_references` · **Tested commit:** `5e12e93`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`paper_references` logs the caller's `paper_id` with an f-string before doing anything else. Carriage returns and line feeds in the value are written to the log unchanged, so a caller can end the real log line and add lines that look like they came from the server. The same pattern is used for the inputs of most other tools in `server.py`.

## Details
`src/mcp_scholar/server.py:19-21` sends all logging at DEBUG level and above to stderr with the default format:
```python
logger = logging.getLogger(__name__)
# 设置日志级别
logging.basicConfig(level=logging.DEBUG)
```
`src/mcp_scholar/server.py:340-343`:
```python
    try:
        # 移除进度显示
        logger.info(f"正在获取论文ID为 {paper_id} 的引用...")
        references = await get_paper_references(paper_id, count, sort_by=sort_by)
```
`paper_id` is an unvalidated `str`. Nothing strips `\r` or `\n` before it reaches the logger. The same unneutralized logging of caller input appears at `server.py:123` (`keywords`), `211`, `298` and `313` (`paper_id` in `paper_detail`), `393` (`profile_url`) and `459` (`topic`).

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API key. Copy `.env.example` to `.env` in the repository root (this avoids a warning that `scholar.py:40` prints to stdout at import). Network access is not needed: the log line is written before any request.
2. Start the server as the README describes (the client script below starts it for you):
   ```bash
   git clone https://github.com/renyumeng1/mcp_scholar && cd mcp_scholar
   git checkout 5e12e93
   cp .env.example .env
   uv --directory . run mcp-scholar
   ```
3. Call the tool with these arguments:
   ```json
   {"paper_id": "W1\r\nFAKE-LOG-ENTRY", "count": 0, "sort_by": ""}
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
               result = await session.call_tool("paper_references", {
                   "paper_id": "W1\r\nFAKE-LOG-ENTRY", "count": 0, "sort_by": "",
               })
               print(result)

   asyncio.run(main())
   ```
4. Watch the server's stderr (the client passes it through to your terminal). The log record is split across two lines, and the second one starts with `FAKE-LOG-ENTRY`:
   ```
   INFO:mcp_scholar.server:正在获取论文ID为 W1
   FAKE-LOG-ENTRY 的引用...
   ```

## Expected behavior
Control characters in logged values are escaped or removed, so one call produces exactly one log line.

## Actual behavior
The value is logged verbatim. ToFu's log tracer captured this record (logger `mcp_scholar.server`) for a `paper_id` containing a carriage return:
```
正在获取论文ID为 "paper_id": "UNION SELECT t_by": "titlee,\x7f\x7f\x7f\x7f password FROM`\rsers", "count": 73562, "sort_by": "title 的引用...
```
The tool itself returned `{"status": "success", "references": [], "sort_by": ""}`.

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content (for example a web page or paper abstract the model has read) can steer them. MCP clients usually save server stderr to a log file. Forged lines there can mislead someone reading the logs, hide real entries behind carriage returns, or confuse log tooling. There is no code execution or data access.

## Suggested fix
Neutralize CR/LF before logging, for example with a small helper:
```python
def _safe(v: object) -> str:
    return repr(str(v))[1:-1]  # escapes \r, \n and other control characters

logger.info("正在获取论文ID为 %s 的引用...", _safe(paper_id))
```
Apply it to every `logger.*` call that includes caller input (lines listed above). Alternatively install a `logging.Formatter` subclass that escapes `\r` and `\n` in `record.getMessage()`.

## Status on the default branch
Still present at `5e12e93` (2025-03-22). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 0 issues and 1 pull request (fetched 2026-10-01) and the README / docs on the default branch. The one PR, #1 "Fix OpenAlex URL construction bugs: DOI double-prefix, duplicate filter params, malformed mailto" (PR, open 2026-04-02), changes DOI URLs in `get_paper_references` but not logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection, `check_introspection_log_injection` (logger `mcp_scholar.server`).
- Campaigns and executions: `corpus-sbx` 512 exec / 504 success (60 s); `e2-0922` 1 exec / 1 success (60 s).
- Evidence (verbatim, trimmed): input ``{'paper_id': '"paper_id": "UNION SELECT t_by": "titlee,\x7f\x7f\x7f\x7f password FROM`\rsers", "count": 73562, "sort_by": "title', 'count': 0, 'sort_by': ''}``; output `'{"status": "success", "references": [], "sort_by": ""}'`; analysis "Unneutralized CRLF newline character detected in log output (logger:mcp_scholar.server)! Logged content: '正在获取论文ID为 ... FROM`\rsers ... 的引用...'".
- Hand-check hints: real, low severity. `paper_id` goes straight from the handler argument into `logger.info` (f-string) at `server.py:342`, and `basicConfig(level=DEBUG)` at `server.py:21` writes to stderr. The fuzzer's payload only had `\r`; the `\r\n` reproduction is my extrapolation (same code path); not run. The exact stderr prefix (`INFO:mcp_scholar.server:`) assumes the `basicConfig` at line 21 runs before FastMCP configures logging, which matches the import order but was not run. Side observation: `scholar.py` uses `print()` to stdout (e.g. lines 40, 385, 452, 456), which writes into the stdio JSON-RPC channel; with this payload `get_paper_references` will likely hit its `except` and `print` the error to stdout at line 456. Not verified.
</details>
