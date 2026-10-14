# Missing output encoding in `image_info`: `object_url` is echoed back unchecked, including `javascript:` URLs and markup

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `image_info` · **Tested commit:** `52dd335`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`image_info` takes an image URL, appends the `imageInfo` processing command to its query string and returns the new URL. It does not check the scheme or host of `object_url`, and it only encodes the query part, so a `javascript:` URL or HTML markup in the input comes back unchanged in the output. The output is plain text (a Python `dict` repr), so this only matters if a client renders the returned URL as a link or as HTML. Severity is low.

## Details
`src/mcp_server/core/media_processing/tools.py:216-235` (tested commit):

```python
def image_info(self, **kwargs) -> list[types.TextContent]:
    object_url = kwargs.get("object_url", "")
    if object_url is None or len(object_url) == 0:
        return [types.TextContent(type="text", text="object_url is required")]

    func = "imageInfo"
    object_url = utils.url_add_processing_func(auth=self.auth, url=object_url, func=func)
    return [types.TextContent(type="text", text=str({"object_url": object_url}))]
```

`utils.url_add_processing_func` (`src/mcp_server/core/media_processing/utils.py:13-23`) parses the URL, percent-encodes only the new query (`parse.quote(new_query, safe='&=')`) and rebuilds it with `urlunparse`. Scheme, host and path are passed through as given. The only check on `object_url` is that it is non-empty. The tool description tells the client the returned URL can be fetched or opened in a browser (`_OBJECT_URL_DESC` and the `image_*` descriptions), which is why the value is likely to be rendered as a link.

## Steps to reproduce
1. Prerequisites: Python 3.12 and `uv`. No Qiniu credentials or network access are needed: the tool only builds a string.
2. Install and start the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
3. Call the tool with:

   ```json
   {"object_url": "javascript:alert(document.domain)//<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/path/to/qiniu-mcp-server", "run", "qiniu-mcp-server"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "image_info",
                   {"object_url": "javascript:alert(document.domain)//<img src=x onerror=alert(1)>"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that the returned text still starts with `javascript:` and contains the `<img ...>` markup verbatim, followed by `?imageInfo`.

## Expected behavior
The tool rejects `object_url` unless it is an `http` or `https` URL with a host (ideally one of the bucket's domains), and the returned value cannot be interpreted as script or markup by a client.

## Actual behavior
The input is returned with only `?imageInfo` appended. From the fuzzing run:

```
input:  {'object_url': 'javascript:alert(1)'}
output: {'object_url': 'javascript:alert(1)?imageInfo'}
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content (a web page, a file in a bucket) can steer it. If a client turns the returned `object_url` into a clickable link or renders tool output as HTML, a `javascript:` URL or injected markup could run in that client. Many clients render tool output as plain text or block `javascript:` links, so the practical impact is low and depends on the client.

## Suggested fix
- Parse `object_url` with `urllib.parse.urlparse` and reject it unless `scheme` is `http` or `https` and `netloc` is non-empty. Optionally require the host to be one of the configured bucket domains.
- Return structured JSON (`json.dumps`) instead of a Python `dict` repr, so clients do not have to guess how to display the value.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
- Issues and pull requests: none related. Searched all 10 issues and 52 pull requests (fetched 2026-10-01); none mentions URL validation, SSRF, escaping or security for the media-processing tools.
- Documentation: `src/mcp_server/README.md`: "图片必须存储在七牛云空间中" ("the image must be stored in a Qiniu bucket"), written for `object_url` of each image tool (the README states the requirement, but the code does not enforce it; there is no security note). The top-level README and CHANGELOG say nothing about input validation.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3034 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'object_url': 'javascript:alert(1)'}` -> `"{'object_url': 'javascript:alert(1)?imageInfo'}"` (token `javascript:`)
  - `{'object_url': '"object_ur{{{{{{{{{{{{{{{{l": '}` -> `{'object_url': '"object_ur{{{{{{{{{{{{{{{{l": ?imageInfo'}` (token `{{`)
  - Third evidence call is the same `{{` pattern with `\x7f` bytes.
- Hand-check hints: weak. The `javascript:` scheme really does pass through (urlparse keeps the scheme, only the query is quoted), and markup in the path also survives (reasoned from `utils.py`, not executed). But the sink is a plain-text `str(dict)` in a `TextContent`; there is no HTML context in the server. Two of three evidence calls are only `{{` template braces, which mean nothing here. Same root cause as the three `image_*` SSRF drafts (`utils.url_add_processing_func`); consider one combined issue for the media-processing URL handling.
</details>
