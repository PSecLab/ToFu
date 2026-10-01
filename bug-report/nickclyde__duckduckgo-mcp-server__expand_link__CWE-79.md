# Missing output encoding in `expand_link`: an unknown `token` is echoed raw in the error

**Repository:** `nickclyde/duckduckgo-mcp-server` · **Tool:** `expand_link` · **Tested commit:** `8182af3`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`expand_link` turns a `ref://<id>` token from search results back into the full URL. When the token is not in the registry, the tool returns an error message that quotes the raw, caller-supplied token. Markup or template syntax in `token` therefore comes back unescaped. `fetch_content` returns the same message for an unknown `ref://` URL.

## Details
`src/duckduckgo_mcp_server/server.py:102-107` and `1369-1379` at `8182af3`:

```python
def _unknown_ref_error(token: str) -> str:
    return (
        f"Error: Unknown link reference '{(token or '').strip()}'. Only ref:// tokens "
        "returned by this server's search results can be expanded, and they are "
        "forgotten when the server restarts. Run the search again to get a fresh token."
    )
...
async def expand_link(token: str) -> str:
    ...
    url = links.resolve(token)
    if url is None:
        return _unknown_ref_error(token)
    return url
```

Valid tokens are short (`ref://` plus 8 or more hex characters, see `LinkRegistry.shorten`), but nothing checks the shape or length of the input before quoting it. `fetch_and_parse` calls the same helper at line 1060 for an unknown `ref://` URL.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and `uv`. No API keys or network access are needed for this tool.
2. Install the server from source:
   ```
   git clone https://github.com/nickclyde/duckduckgo-mcp-server.git
   cd duckduckgo-mcp-server && git checkout 8182af3f2295017ca90527a924f48147fbf18d5b
   uv venv .venv && source .venv/bin/activate
   uv pip install -e .
   ```
   The client script below starts it with `duckduckgo-mcp-server` (stdio transport by default).
3. Call the tool with these arguments:
   ```json
   {"token": "<b>tofu-poc</b>{{7*7}}"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="duckduckgo-mcp-server", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("expand_link", {"token": "<b>tofu-poc</b>{{7*7}}"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `Error: Unknown link reference '<b>tofu-poc</b>{{7*7}}'.`, with the markup unchanged.

## Expected behavior
An input that is not shaped like a token (for example not matching `^(ref://)?[0-9a-f]{8,64}/?$`, case-insensitive) should get a fixed message, or the quoted value should be escaped and length-capped.

## Actual behavior
The token is reflected verbatim, including control characters. From the fuzzing run:

```
Error: Unknown link reference '\x17\x17{{"token": "'. Only ref:// tokens returned by this server's search results can be expanded, ...
```

## Impact
In MCP the LLM chooses the tool arguments, and prompt injection in search results or fetched pages can steer them. The result then carries caller-chosen markup into the client. This matters only for clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients the severity is low.

## Suggested fix
In `_unknown_ref_error`, check the token against the expected shape first and return a fixed message when it does not match. If you keep the echo, pass it through `repr()` or an escape helper and cap it at about 80 characters. This covers both `expand_link` and the `fetch_content` path at line 1060.

## Status on the default branch
Still present at `8182af3` (2026-09-04). The tested commit is the head of the default branch.

## Prior reports
- #69 "feat: shorten long result URLs to ref:// tokens with expand_link tool" (PR, closed 2026-09-04): introduced `expand_link` and the unknown-token error ("Unknown tokens return a clear error without any network call"); it does not discuss quoting the raw token. Not a report of this bug.
- #43 "[feat] local url shortening" (issue, closed 2026-09-04): the feature request behind #69; nothing about escaping.
- Documentation: SECURITY.md: "Search results and fetched page text come from external websites and are **untrusted input**." (covers prompt injection in content; says nothing about caller input echoed in error messages). SECURITY.md also asks for private reporting of vulnerabilities.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 4,096 exec / 4,096 ok (60 s); repo24-b 230,400 / 230,400 (4,200 s).
- Evidence (verbatim, trimmed): `{'token': '\x00{\x00\x00{{"token"'}` -> `'Error: Unknown link reference \'\x00{\x00\x00{{"token"\'. Only ref:// tokens ...'`; `{'token': '\x17\x17{{"token": '}` -> `... reference \'\x17\x17{{"token":\'. ...'` (trailing space stripped by `.strip()`); `{'token': '\x17\x17{{"token": "'}` -> same shape.
- Hand-check hints: weak. Only `{{` and control bytes were reflected, into a plain-text error string. The `<b>` reproduction is derived from the code (line 104), not from a logged run. The project has a careful security posture (SSRF guard, `_safe_markdown_href`/`_safe_markdown_label` for fetched content), so a small hardening issue may be welcome, but this is low severity. `SECURITY.md` asks for private reporting of vulnerabilities; this is probably fine as a normal issue given the severity. The client snippet assumes the server's own `mcp>=2.1.1` is installed in the venv; the client side only needs a compatible `mcp` client.
</details>
