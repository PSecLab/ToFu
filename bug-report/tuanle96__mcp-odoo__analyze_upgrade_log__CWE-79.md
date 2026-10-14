# Missing output encoding in `analyze_upgrade_log`: `source_version` and `target_version` are echoed unvalidated

**Repository:** `tuanle96/mcp-odoo` · **Tool:** `analyze_upgrade_log` · **Tested commit:** `76ec136`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`analyze_upgrade_log` classifies lines of a pasted Odoo upgrade log into a migration worklist. It never contacts Odoo. The optional `source_version` and `target_version` labels are copied into the JSON result without any validation, so markup or control characters in them come back unchanged. The values end up inside a JSON string, so this is a small hardening item, not an exploitable bug.

## Details
`src/odoo_mcp/tools_diagnostics.py:568-587` passes the arguments through, and `src/odoo_mcp/diagnostics.py:1171-1175` returns them as-is:

```python
    return {
        "success": True,
        "tool": "analyze_upgrade_log",
        "source_version": source_version,
        "target_version": target_version,
```

Neither value is checked against a version format. Matching log lines are also echoed, as `evidence` (first 200 characters, `diagnostics.py:1142`), which is the tool's purpose. The tool is registered with `structured_output=True`, so the dict is returned both as structured content and as JSON text.

## Steps to reproduce
1. Prerequisites: Python 3.10+. No Odoo instance or `ODOO_*` variables are needed; this tool does not contact Odoo, and the server connects lazily (`src/odoo_mcp/server_core.py:90-95`).
2. Start the server as the README describes: `uvx odoo-mcp`. To test the tested commit, run `pip install -e .` in a checkout at `76ec136` and start `odoo-mcp`.
3. Call the tool:

   ```json
   {"log_text": "tofu-poc", "source_version": "<b>tofu-poc</b>", "target_version": "17.0"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["odoo-mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("analyze_upgrade_log", {"log_text": "tofu-poc", "source_version": "<b>tofu-poc</b>", "target_version": "17.0"})
               print(result)

   asyncio.run(main())
   ```
4. The result contains `"source_version": "<b>tofu-poc</b>"` with the markup unchanged.

## Expected behavior
Version labels are checked against the version formats the tool expects (for example `16.0` or `17.0`) and rejected otherwise.

## Actual behavior
Any string is accepted and echoed. From the fuzzing run:

```
input:  {'log_text': '"log,444', 'source_version': '\x7f\x7f\x7f\x7f\x7f\x7f\x7f44\x1e...\x1e{"l{$$${$$$$...', 'target_version': ''}
output: {"success": true, "tool": "analyze_upgrade_log", "source_version": "\x7f\x7f\x7f\x7f\x7f\x7f\x7f44\u001e...{\"l{$$${$$$$...", "target_version": "", ...}
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content (such as a pasted log) can steer them. The echoed value sits in a JSON string field. JSON encoding escapes quotes and the `\x1e` control characters, but not `<`, `>` or DEL (`\x7f`). This matters only if a client renders a field of the result as HTML. Very low severity.

## Suggested fix
Validate the two labels, for example with a pattern such as `^[0-9A-Za-z.~_-]{1,32}$` adjusted to the versions you support, and return an error for anything else.

## Status on the default branch
Still present at `76ec136` (2026-08-25). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 16 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `${`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2554 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'log_text': '"log,444', 'source_version': '\x7f\x7f\x7f\x7f\x7f\x7f\x7f44\x1e\x1e\x1e\x1e\x1e\x1e\x1e{"l{$$${$$$$$$$$$$$$$$$$$$', 'target_version': ''}` -> JSON text `{"success": true, "tool": "analyze_upgrade_log", "source_version": "\x7f...44\\u001e...{\\"l{$$${$$$...", "target_version": "", "summary": {"finding_count": 0, ...}, "findings": []}`
  - second sample identical except one fewer `\x7f`.
- Hand-check hints: **weak**, close to a false positive. The echo is by design (a label in a JSON report), only `${` was echoed, and it is inside a JSON string. The repo's `SECURITY.md` asks for private advisories rather than public issues for suspected vulnerabilities; this is low enough to file as a public hardening issue, or drop. Steps not executed (read-only review).
</details>
