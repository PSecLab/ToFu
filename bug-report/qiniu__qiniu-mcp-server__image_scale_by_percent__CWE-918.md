# Missing URL validation in `image_scale_by_percent`: any `object_url` (loopback hosts, relative paths, NUL bytes) is returned as a fetchable image URL

**Repository:** `qiniu/qiniu-mcp-server` · **Tool:** `image_scale_by_percent` · **Tested commit:** `52dd335`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`image_scale_by_percent` appends an `imageMogr2/thumbnail/!<n>p` command to `object_url` and returns the new URL, which the tool description says can be fetched with HTTP GET or opened in a browser. The tool checks `percent` but never checks `object_url`, so loopback URLs, relative paths such as `../../../../etc/passwd` and strings with NUL bytes come back as "scaled image" URLs. The MCP server itself never requests the URL, so this is not SSRF inside the server process; the risk is that a client or agent follows the returned URL.

## Details
`src/mcp_server/core/media_processing/tools.py:48-73` (tested commit), trimmed:

```python
def image_scale_by_percent(self, **kwargs) -> list[...]:
    object_url = kwargs.get("object_url", "")
    percent = kwargs.get("percent", "")
    if object_url is None or len(object_url) == 0:
        return [types.TextContent(type="text", text="object_url is required")]

    percent_int = int(percent)
    if percent_int < 1 or percent_int > 999:
        return [types.TextContent(type="text", text="percent must be between 1 and 999")]

    func = f"imageMogr2/thumbnail/!{percent}p"
    object_url = utils.url_add_processing_func(auth=self.auth, url=object_url, func=func)
    return [types.TextContent(type="text", text=str({"object_url": object_url}))]
```

`utils.url_add_processing_func` (`src/mcp_server/core/media_processing/utils.py:13-23`) only parses the URL, adds the command to the query and rebuilds it. There is no check of scheme, host or port, and no request is made.

A related point: if the query of `object_url` already contains `e=` and `token=`, `_sign_url` (`utils.py:81-108`) re-signs the URL with the configured key pair via `auth.private_download_url`, taking the lifetime from the caller's `e=` value. With no host check, the tool will sign a URL for any host and with any expiry.

## Steps to reproduce
1. Prerequisites: Python 3.12 and `uv`. No Qiniu credentials or network access are needed.
2. Install the server from a checkout, as the README describes:
   `git clone https://github.com/qiniu/qiniu-mcp-server.git && cd qiniu-mcp-server && uv venv && uv pip install -e .`
   In a second terminal, start a local listener: `python3 -m http.server 8099 --bind 127.0.0.1`
3. Call the tool with:

   ```json
   {"object_url": "http://127.0.0.1:8099/tofu-poc", "percent": 50}
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
                   "image_scale_by_percent",
                   {"object_url": "http://127.0.0.1:8099/tofu-poc", "percent": 50},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that the tool returns `http://127.0.0.1:8099/tofu-poc?imageMogr2%2Fthumbnail%2F%2150p` as the scaled image URL, and that the listener log shows no request from the server. The GET for `/tofu-poc` appears in the listener log only when a client or agent follows the returned URL.

## Expected behavior
The tool rejects `object_url` unless it is an `http` or `https` URL whose host is one of the bucket's domains (or at least a public host), and rejects control characters.

## Actual behavior
Any non-empty string is accepted. From the fuzzing run:

```
input:  {'object_url': '../../../../etc/passwd', 'percent': 50}
output: {'object_url': '../../../../etc/passwd?imageMogr2%2Fthumbnail%2F%2150p'}

input:  {'object_url': '/etc/passwd\x00', 'percent': 300}
output: {'object_url': '/etc/passwd\x00?imageMogr2%2Fthumbnail%2F%21300p'}
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in untrusted content can steer it. Because the server never fetches the URL, there is no request from the server host. The risk is indirect: the tool presents an attacker-chosen URL (a loopback or internal address, or a local path) as a Qiniu image link, and an agent with a fetch or browser tool may then request it from the user's machine. The re-signing behaviour can also produce signed download URLs with a caller-chosen lifetime. Overall severity is low.

## Suggested fix
- Validate `object_url` with `urllib.parse.urlparse`: require `http` or `https`, a non-empty host, no control characters, and preferably a host from the configured bucket domains. A shared helper in `utils.url_add_processing_func` would cover all four `image_*` tools.
- Only re-sign URLs whose host belongs to the account, and cap the expiry instead of taking it from the input.

## Status on the default branch
Still present at `52dd335` (2025-11-26). The tested commit is the current default branch head.

## Prior reports
- Issues and pull requests: none related. Searched all 10 issues and 52 pull requests (fetched 2026-10-01); none mentions URL validation, SSRF, escaping or security for the media-processing tools.
- Documentation: `src/mcp_server/README.md`: "图片必须存储在七牛云空间中" ("the image must be stored in a Qiniu bucket"), written for `object_url` of each image tool (the README states the requirement, but the code does not enforce it; there is no security note). The top-level README and CHANGELOG say nothing about input validation.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf (CWE-918); triggered `check_strict_url_security_contract` only.
- Campaigns and executions: corpus-sbx 3584 exec / 251 ok; e2-0922 512 exec / 59 ok (60 s budgets). The low success rate is schema rejection of non-integer or out-of-range `percent` and `int(percent)` errors, not URL checks.
- Evidence (verbatim, trimmed):
  - `{'object_url': '/etc/passwd\x00', 'percent': 300}` -> `{'object_url': '/etc/passwd\\x00?imageMogr2%2Fthumbnail%2F%21300p'}`
  - `{'object_url': 'http://localhost:8080', 'percent': 1}` -> `{'object_url': 'http://localhost:8080?imageMogr2%2Fthumbnail%2F%211p'}`
  - `{'object_url': '../../../../etc/passwd', 'percent': 50}` -> `{'object_url': '../../../../etc/passwd?imageMogr2%2Fthumbnail%2F%2150p'}`
- Hand-check hints: weak, likely a false positive for SSRF. No network call exists on this path; the sanitizer is a URL-shape contract check, not an observed connection. What remains is missing input validation plus the re-signing with caller-chosen expiry (read from repo code; the SDK's `private_download_url` itself was not read). Same root cause as `image_round_corner`, `image_scale_by_size` and `image_info`; consider one combined issue.
</details>
