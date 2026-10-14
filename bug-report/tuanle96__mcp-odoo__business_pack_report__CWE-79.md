# Missing output encoding in `business_pack_report`: an unknown `pack` name is echoed in the error

**Repository:** `tuanle96/mcp-odoo` · **Tool:** `business_pack_report` · **Tested commit:** `76ec136`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`business_pack_report` describes the modules and models expected for a business pack (`sales`, `crm`, `inventory`, `accounting`, `hr`). For any other `pack` value it returns `Unknown pack '<pack>'.` with the caller's string inside. `repr()` adds quotes and escapes control characters, but markup such as `<b>` passes through unchanged. The value then sits inside a JSON string, so this is a small hardening item.

## Details
`src/odoo_mcp/agent_tools.py:605-612`:

```python
    pack_key = pack.strip().lower()
    if pack_key not in BUSINESS_PACKS:
        return {
            "success": False,
            "tool": "business_pack_report",
            "error": f"Unknown pack {pack!r}.",
            "available_packs": sorted(BUSINESS_PACKS),
        }
```

The tool wrapper at `src/odoo_mcp/tools_diagnostics.py:690-727` accepts any string for `pack`. With `use_live_metadata=True` (the default) it first reads models and modules from Odoo. With `use_live_metadata=False` it goes straight to the code above.

## Steps to reproduce
1. Prerequisites: Python 3.10+. With `use_live_metadata` set to `false`, no Odoo instance or `ODOO_*` variables are needed.
2. Start the server as the README describes: `uvx odoo-mcp`. To test the tested commit, run `pip install -e .` in a checkout at `76ec136` and start `odoo-mcp`.
3. Call the tool:

   ```json
   {"pack": "<b>tofu-poc</b>", "use_live_metadata": false}
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
               result = await session.call_tool("business_pack_report", {"pack": "<b>tofu-poc</b>", "use_live_metadata": False})
               print(result)

   asyncio.run(main())
   ```
4. The result contains `"error": "Unknown pack '<b>tofu-poc</b>'."` with the markup unchanged.

## Expected behavior
`pack` is declared as an enum of the known pack names in the tool schema, so the client and server reject other values, and the error does not need to repeat the input.

## Actual behavior
The value is echoed in the error. From the fuzzing run:

```
input:  {'pack': 'akp:{{"', 'use_live_metadata': False, 'instance': 'ck""":{ "'}
output: {"success": false, "tool": "business_pack_report", "error": "Unknown pack 'akp:{{\"'.", "available_packs": ["accounting", "crm", "hr", "inventory", "sales"]}
```

## Impact
The model chooses `pack`, and prompt injection in untrusted content can steer it. The echo is inside a JSON string in a plain-text tool result. It matters only if a client renders the error field as HTML. Very low severity.

## Suggested fix
- Type `pack` as `Literal["accounting", "crm", "hr", "inventory", "sales"]` (or the keys of `BUSINESS_PACKS`) so the JSON schema advertises an enum.
- Or keep the free string and return `Unknown pack. Available: ...` without the input.

## Status on the default branch
Still present at `76ec136` (2026-08-25). The tested commit is the current head of the default branch.

## Prior reports
None found. Searched all 16 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 2549 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'pack': 'akp:{{"', 'use_live_metadata': False, 'instance': 'ck""":{ "'}` -> `{"success": false, "tool": "business_pack_report", "error": "Unknown pack 'akp:{{\"'.", "available_packs": ["accounting", "crm", "hr", "inventory", "sales"]}`
  - `{'pack': 'akp:~{{', 'use_live_metadata': False, 'instance': '\U000b6361\U00102222'}` -> `... "error": "Unknown pack 'akp:~{{'." ...`
- Hand-check hints: **weak**, close to a false positive. Only `{{` was echoed, through `repr()`, inside a JSON string. The enum suggestion is a usability improvement more than a security fix. `instance` is ignored when `use_live_metadata` is false. The repo's `SECURITY.md` asks for private advisories for suspected vulnerabilities; this is low enough for a public hardening issue, or drop. Steps not executed (read-only review).
</details>
