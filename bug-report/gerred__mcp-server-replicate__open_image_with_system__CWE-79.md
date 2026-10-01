# Missing output encoding in `open_image_with_system`: `image_url` is echoed back unescaped (and opened with no scheme check)

**Repository:** `gerred/mcp-server-replicate` · **Tool:** `open_image_with_system` · **Tested commit:** `568024c`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`open_image_with_system` passes the caller's `image_url` to `webbrowser.open()` and returns it in the result as `url`. The value is not validated or encoded, so markup or a `javascript:` URL comes back exactly as sent. The result is JSON text, so this only matters if an MCP client renders tool output as HTML or Markdown. The same missing check means any URL scheme is handed to the system browser launcher, which is probably the more important half of this report.

## Details
`src/mcp_server_replicate/server.py:1122-1139` at `568024c`:

```python
    @mcp.tool()
    async def open_image_with_system(image_url: str) -> dict[str, Any]:
        """Open an image URL with the system's default application.
        ...
        """
        try:
            # Open URL directly with system default
            webbrowser.open(image_url)

            return {"status": "success", "message": "Image opened with system default application", "url": image_url}
        except Exception as e:
            logger.error(f"Failed to open image: {str(e)}")
            return {"status": "error", "message": f"Failed to open image: {str(e)}", "url": image_url}
```

There is no check that `image_url` is an `http`/`https` URL, or that it points at an image. FastMCP serializes the returned dict to JSON, which escapes quotes and control characters but leaves `<`, `>` and URL schemes as they are. Two smaller points on the same lines: the return value of `webbrowser.open()` (which is `False` when no browser could be started) is ignored, so the tool reports `success` even when nothing opened, and the docstring says "image" but any URL is accepted.

## Steps to reproduce
1. Prerequisites: Python 3.11+ and `uv`. The server refuses to start without `REPLICATE_API_TOKEN` (`server.py:299-303`); any value works for this tool because it makes no API call. Set `BROWSER=true` in the server's environment so Python's `webbrowser` runs the `true` command instead of opening a real browser.
2. Check out the tested commit and start the server: `git clone https://github.com/gerred/mcp-server-replicate && cd mcp-server-replicate && git checkout 568024c && REPLICATE_API_TOKEN=r8_invalid_token_for_testing BROWSER=true uv run mcp-server-replicate`. The script below starts it for you.
3. Call the tool with `{"image_url": "http://127.0.0.1:9/tofu-poc.png?<img src=x onerror=alert(1)>"}`:

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["run", "--directory", "/path/to/mcp-server-replicate", "mcp-server-replicate"],
           env={**os.environ, "REPLICATE_API_TOKEN": "r8_invalid_token_for_testing", "BROWSER": "true"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "open_image_with_system",
                   {"image_url": "http://127.0.0.1:9/tofu-poc.png?<img src=x onerror=alert(1)>"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that the text content of the result contains `"url": "http://127.0.0.1:9/tofu-poc.png?<img src=x onerror=alert(1)>"` with the `<img>` tag intact, and that `status` is `success`. Repeating with `{"image_url": "javascript:alert(1)"}` (still with `BROWSER=true`) returns the `javascript:` URL unchanged as well.

## Expected behavior
The tool accepts only `http`/`https` URLs (ideally only image URLs) and rejects anything else with an error. Any caller text echoed back is treated as data, so a client that renders it does not interpret it as markup.

## Actual behavior
Any string is accepted, passed to `webbrowser.open()`, and echoed back raw. Real output from the fuzz run:

```
{"status": "success", "message": "Image opened with system default application", "url": "javascript:alert('XSS')"}
```

## Impact
For the echo itself, low: tool results are JSON text, and a client would need to render them as HTML or Markdown for the markup to run. The argument is chosen by the LLM, which can be steered by prompt injection from untrusted content (for example a model description or a web page). For the `webbrowser.open()` call, the same attacker can make the user's desktop open an arbitrary URL with whatever handler the OS has for its scheme. The only gate is whatever tool-call approval the MCP host shows. What that leads to depends on the platform and installed handlers.

## Suggested fix
Validate the URL before opening or echoing it:

```python
from urllib.parse import urlparse

parsed = urlparse(image_url)
if parsed.scheme not in ("http", "https") or not parsed.netloc:
    return {"status": "error", "message": "Only http(s) image URLs are supported"}
if not webbrowser.open(image_url):
    return {"status": "error", "message": "No browser could be started"}
return {"status": "success", "message": "Image opened with system default application"}
```

If the URL needs to be returned, return it from the validated value, and let any client that renders it escape it for its own context.

## Status on the default branch
Still present at `568024c` (2025-02-28). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 1 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116). Fired: `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx`: 2560 execs, 2553 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'image_url': "javascript:alert('XSS')"}`, output `'{"status": "success", "message": "Image opened with system default application", "url": "javascript:alert(\'XSS\')"}'`. Analysis: "input payload token(s) ['javascript:'] echoed UNESCAPED in the tool output". Two more evidence rows only echo `{{` (`'\x7f\x7f\x7f\x7fii{{m'`), which is not meaningful.
- Hand-check hints: **weak for CWE-79** as classified: the value lands in a JSON text result, and the only strong token is the `javascript:` URL. The more interesting finding is the unvalidated `webbrowser.open(image_url)` at `server.py:1134` (closer to CWE-20/CWE-939 than CWE-79); I did not test what `webbrowser.open` does with `file:` or custom schemes on each OS, so the draft keeps that claim general. During the fuzz run this tool called `webbrowser.open` about 2.5k times inside the sandbox. `BROWSER=true` relies on documented `webbrowser` behaviour (the `BROWSER` env var is tried first); I did not run it. Consider retitling around the `webbrowser.open` issue if filing.
</details>
