# Missing output encoding in `get_project_process_id`: `project` is echoed raw into the error text

**Repository:** `Vortiago/mcp-azure-devops` · **Tool:** `get_project_process_id` · **Tested commit:** `1ce5376`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_project_process_id` looks up the process template of an Azure DevOps project. When the lookup fails for any reason, the tool returns an error string that contains the caller's `project` argument exactly as given. Markup or template syntax in `project` therefore comes back unchanged in the tool result. The reply is plain text, so this is low severity; it matters only for clients that render tool output as Markdown or HTML.

## Details
`src/mcp_azure_devops/features/work_items/tools/process.py:21-44` (tested commit):

```python
def _get_project_process_id_impl(project: str) -> str:
    """Implementation of project process ID retrieval."""
    try:
        # Get project details with process information
        core_client = get_core_client()
        project_details = core_client.get_project(
            project, include_capabilities=True)
        # ...
        if not process_id:
            return f"Could not determine process ID for project {project}."
        # ...
    except Exception as e:
        return (f"Error retrieving process ID for project '{project}': "
                f"{str(e)}")
```

`project` is interpolated into the error string at line 43 (and into the "could not determine" message at line 35) with no escaping or validation. The success path of the same tool builds Markdown (`# Process for Project: ...` at line 37), so a client that renders this tool's output as Markdown will render the error text the same way. The same pattern appears in `get_process_details` (`process.py:91`) and in the work item type tools (`types.py:137`, `types.py:217`).

## Steps to reproduce
1. Prerequisites: Python 3.10+. No Azure DevOps account is needed: run the server without `AZURE_DEVOPS_PAT` and `AZURE_DEVOPS_ORGANIZATION_URL` set, which takes the error path at line 43.
2. Install as the README describes:

   ```bash
   git clone https://github.com/Vortiago/mcp-azure-devops.git
   cd mcp-azure-devops && git checkout 1ce5376
   uv pip install -e ".[dev]"
   ```
3. Call the tool with:

   ```json
   {"project": "<b>tofu-poc</b>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-azure-devops", args=[])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_project_process_id", {"project": "<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe `<b>tofu-poc</b>` unchanged inside the returned error text.

## Expected behavior
The error message either omits the raw argument or includes it in an escaped or quoted form (for example `repr(project)` with Markdown/HTML special characters escaped). Clearly invalid project names are rejected before the API call.

## Actual behavior
From the fuzzing run (no credentials configured):

```
input:  {"project": "{{{{{{{{{{{{"}
output: Error retrieving process ID for project '{{{{{{{{{{{{': Azure DevOps PAT or organization URL not found in environment variables.
```

## Impact
The LLM chooses `project`, and prompt injection from untrusted content (for example a work item description) can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup into the chat view; in a plain-text client it has no effect. It does not give access to Azure DevOps data. Low severity.

## Suggested fix
- Do not interpolate the raw `project` value into messages. If it is useful for the user, include an escaped form, for example `html.escape(repr(project))`, or a fixed message such as "Error retrieving process ID for the requested project".
- Reject values that cannot be a project name or GUID before calling `get_project`.
- Apply the same change to the other error strings that echo caller arguments (`process.py:91`, `types.py:137`, `types.py:217`).

## Status on the default branch
Still present at `1ce5376` (2025-10-29). The default branch head is the tested commit. The README at that commit states the repository is no longer maintained and points users to `microsoft/azure-devops-mcp`.

## Prior reports
- No related issue or PR. Searched all 11 issues and 21 pull requests (fetched 2026-10-01); none mention escaping, error-message content or `get_project_process_id` input handling.
- Documentation: README.md: "This repository is no longer maintained." (the notice at `1ce5376` sends users to `microsoft/azure-devops-mcp`; no README text covers this behaviour)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 3072 exec / 3066 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'project': '{{{{{{{{{{{{'}` -> `"Error retrieving process ID for project '{{{{{{{{{{{{': Azure DevOps PAT or organization URL not found in environment variables."`
  - `{'project': '{{{{{{{{{{C{'}` -> same message with `{{{{{{{{{{C{`
  - `{'project': '{{{{}{{{{{C{'}` -> same message with `{{{{}{{{{{C{`
- Hand-check hints: weak. The only evidence is `{{` echoed into a plain-text error string, and the fuzzer ran without credentials, so every call took the "PAT not found" path. No HTML/Markdown-rendering sink is involved in the server. The echo itself is real (`process.py:43`). The `<b>tofu-poc</b>` reproduction is derived from code and was not run. The README says the repository is unmaintained, so a filed issue is unlikely to be acted on; recommend not filing, or at most a single low-priority note.
</details>
