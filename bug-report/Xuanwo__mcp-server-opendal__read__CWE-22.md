# Possible path traversal in `read`: `..` segments in the URI reach the OpenDAL `fs` backend unchecked

**Repository:** `Xuanwo/mcp-server-opendal` · **Tool:** `read` · **Tested commit:** `f49ee92`
**Weakness:** CWE-22 Path Traversal (not confirmed, see below)

## Summary
`read` returns the content of a file from a configured OpenDAL service. The server splits the URI into scheme and path and passes the path to the operator as is: no check for `..` segments, and `%2e%2e` is decoded by `unquote()` too. For object stores such as S3 a `..` is just part of a key. For the `fs` service, whether a `..` path can leave `OPENDAL_FS_ROOT` depends on how OpenDAL joins paths to its root, which we have not verified. If it can, an LLM limited to one folder could read any file the server process can read.

## Details
`src/mcp_server_opendal/resource.py:137-147` and `src/mcp_server_opendal/server.py:113-130`, `:59-62` (tested commit):

```python
def parse_uri(uri: str) -> Tuple[OpendalResource, str]:
    parsed = urlparse(uri)
    scheme = parsed.scheme
    path = parsed.netloc + parsed.path
    path = unquote(path)  # Decode URL-encoded characters
    return (OpendalResource(scheme), path)
...
async def read(uri: str) -> Dict[str, Any]:
    resource, path = parse_uri(uri)
    return await opendal_resource(resource.scheme, path)
...
        resource = OpendalResource(scheme)
        data = await resource.read_path(path)      # -> self.op.read(path)
        metadata = await resource.stat(path)
```

For `fs://../tofu-poc.txt`, `urlparse` gives netloc `..` and path `/tofu-poc.txt`, so the path handed to `op.read()` is `../tofu-poc.txt`. Nothing in this server rejects it. Whether OpenDAL's `fs` service normalizes `..` or joins it under the root is the open question.

## Steps to reproduce
1. Prerequisites: Python 3.12+ and `uv`. Create a root and a harmless file next to it:
   `mkdir -p /tmp/tofu-root && echo tofu-poc > /tmp/tofu-poc.txt`
2. Start the server as the README describes, with an `fs` service rooted at `/tmp/tofu-root/`:
   `OPENDAL_FS_TYPE=fs OPENDAL_FS_ROOT=/tmp/tofu-root/ uvx mcp-server-opendal`. The client below does this itself.
3. Call the tool with:

   ```json
   {"uri": "fs://../tofu-poc.txt"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="uvx", args=["mcp-server-opendal"],
                                      env={"OPENDAL_FS_TYPE": "fs", "OPENDAL_FS_ROOT": "/tmp/tofu-root/"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               for uri in ["fs://../tofu-poc.txt", "fs://%2e%2e/tofu-poc.txt"]:
                   result = await session.call_tool("read", {"uri": uri})
                   print(uri, result)

   asyncio.run(main())
   ```
4. Observe the reply. If it contains `"content": "tofu-poc\n"`, the read escaped the root. A not-found or invalid-path error means OpenDAL contains it.

## Expected behavior
Only files under `OPENDAL_FS_ROOT` can be read. Paths with `..` segments are refused.

## Actual behavior
Not established. The fuzzing run had no backend configured, so every call failed before any storage access:

```
{'uri': '../../../../etc/passwd'}       -> {"error": "1 validation error for OpendalResource\nuri\n  Input should be a valid URL, relative URL without a base ..."}
{'uri': 'mys3://../../../../etc/hosts'} -> {"error": "argument 'scheme': 'NoneType' object cannot be converted to 'PyString'"}
```

## Impact
The LLM chooses `uri`, and prompt injection can steer it. If OpenDAL does not contain `..`, an `fs` service meant to expose one folder exposes every file readable by the server process. Text files come back decoded and other files base64-encoded. If OpenDAL does contain it, there is no impact.

## Suggested fix
Do not rely on the backend. In `parse_uri()`, after `unquote()`, reject any path with a `..` segment (for example `if ".." in PurePosixPath(path).parts: raise ValueError(...)`), and reject NUL and other control characters. This is cheap and also covers other local backends.

## Status on the default branch
Still present at `f49ee92` (2025-04-10). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 4 issues and 12 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The README documents only how to configure services through `OPENDAL_<ALIAS>_*` variables, and examples/README.md sets `OPENDAL_FS_ROOT=./examples/`; neither says whether paths are contained under the root. PR #16 (open) is a third-party scan badge whose only finding is base64 use.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal (CWE-22); `check_path_traversal` (input-pattern "silent bug" alert) and `check_introspection_log_injection` (pydantic multi-line message, see the `get_info` draft).
- Campaigns and executions: corpus-sbx 3072 exec / 3051 ok; e2-0922 1024 exec / 986 ok (60 s budgets).
- Evidence (verbatim, trimmed): `{'uri': '/etc/passwd\x00'}` and `{'uri': '../../../../etc/passwd'}` -> pydantic `url_parsing` error; `{'uri': 'mys3://../../../../etc/hosts'}` -> `argument 'scheme': 'NoneType' object cannot be converted to 'PyString'` (scheme `mys3` not configured).
- Hand-check hints: unclear. Source confirms the server forwards `..` unchanged. Whether that escapes the root depends on OpenDAL's `fs` service (pinned `opendal>=0.45.16,<0.46.0`), and I could not check that offline: the Python package is a compiled Rust extension and no source was available. The fuzzing run never reached storage. Run step 3 before filing; if OpenDAL contains it, drop the draft or file it as hardening.
</details>
