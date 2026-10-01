# Missing output encoding in `install_package`: `environment` and `package_name` are echoed raw

**Repository:** `yzfly/mcp-python-interpreter` · **Tool:** `install_package` · **Tested commit:** `84ac42d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`install_package` runs `pip install` in a named Python environment. If the environment name is unknown, the reply quotes the caller's `environment` value back unescaped. `package_name` is echoed the same way in the success and error replies. Markup in either argument reaches the client unchanged, which matters only for clients that render tool output as HTML or Markdown.

## Details
`mcp_python_interpreter/server.py:699-718` (tested commit):

```python
    environments = get_python_environments()
    if environment == "default" and not any(e["name"] == "default" for e in environments):
        environment = "system"
    env = next((e for e in environments if e["name"] == environment), None)
    if not env:
        return f"Environment '{environment}' not found. Available: {', '.join(e['name'] for e in environments)}"
    cmd = [env["path"], "-m", "pip", "install"]
    ...
    if result["status"] == 0:
        return f"Successfully {'upgraded' if upgrade else 'installed'} {package_name} in {environment}."
    else:
        return f"Error installing {package_name}:\n{result['stderr']}"
```

Neither value is validated or escaped before it is put into the reply. The unknown-environment branch returns before pip is started, so it can be tested without installing anything.

## Steps to reproduce
1. Prerequisites: Python 3.10+.
2. Install from the repository: `git clone https://github.com/yzfly/mcp-python-interpreter && cd mcp-python-interpreter && pip install .`
   The client below starts `mcp-python-interpreter --dir /tmp/tofu-wd` itself.
3. Call the tool with an environment name that does not exist, so no package is installed:

   ```json
   {"package_name": "tofu-poc", "environment": "<img src=x onerror=alert(1)>", "upgrade": false, "timeout": 30}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-python-interpreter", args=["--dir", "/tmp/tofu-wd"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("install_package", {
                   "package_name": "tofu-poc",
                   "environment": "<img src=x onerror=alert(1)>",
                   "upgrade": False,
                   "timeout": 30,
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe the reply `Environment '<img src=x onerror=alert(1)>' not found. Available: system` (the list depends on the host) with the tag intact.

## Expected behavior
The environment name is checked against the known list and an unknown name gets a fixed error, or the echoed value is escaped. `package_name` is validated as a requirement specifier before use.

## Actual behavior
The value is returned verbatim. From the fuzzing run:

```
input:  {'package_name': '/ec/passWd\x00', 'environment': '{{{default', 'upgrade': False, 'timeout': 0}
output: Environment '{{{default' not found. Available: system
```

## Impact
The LLM chooses both arguments and can be steered by prompt injection. The attacker gets a string reflected into the same conversation. It is a problem only where tool output is rendered as HTML or Markdown; we found no such path in this repository. Low severity.

## Suggested fix
- Return `f"Environment not found. Available: ..."` without echoing the input, or escape it (`repr()` or HTML-escape, depending on the client).
- Validate `package_name` as a requirement string (for example with `packaging.requirements.Requirement`) and reject values that start with `-`, then pass it after `--` in the pip command line.

## Status on the default branch
Still present at `84ac42d` (2026-07-02). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 8 issues and 4 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output`. `check_introspection_command_injection` also fired on this tool, but the command it saw is the fixed `['conda', 'info', '--envs', '--json']` from `get_python_environments()` (`server.py:338`). That is a false positive.
- Campaigns and executions: corpus-sbx 3072 exec / 3055 ok (60 s budget).
- Evidence (verbatim, trimmed):
  - `{'package_name': '/ec/passWd\x00', 'environment': '{{{default', 'upgrade': False, 'timeout': 0}` -> `Environment '{{{default' not found. Available: system`
- Hand-check hints: weak. Only `{{` was reflected, into a plain-text reply; the `<img>` payload is my substitution. Confirmed in source. Side observation, not tested: `package_name` goes to `pip install` as a bare argv element (`server.py:708-711`) with no `--` separator, so a value like `-r<file>` or `--index-url=...` would be parsed as a pip option (argument injection, CWE-88). I did not run this, and given that `run_python_code` already executes arbitrary code, it adds little. I put it in the suggested fix only as hardening.
</details>
