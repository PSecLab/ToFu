# Missing output encoding in `git_summary`: `owner` and `repo` are echoed raw in the error message

**Repository:** `puravparab/Gitingest-MCP` · **Tool:** `git_summary` · **Tested commit:** `c3b630a`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`git_summary` builds `https://github.com/{owner}/{repo}` from the tool arguments and summarises the repository with gitingest. When that fails, the tool returns `{"error": "Failed to get repository summary: <exception>. Try https://gitingest.com/<url> instead"}`, with the caller's `owner` and `repo` inserted verbatim, both through the exception text and through the "Try ..." suggestion. Nothing is validated or escaped, so a client that renders tool output as HTML or Markdown would render caller-supplied markup.

## Details
`src/gitingest_mcp/server.py:27-46`:

```python
url = f"https://github.com/{owner}/{repo}"
try:
    ingester = GitIngester(url, branch=branch)
    await ingester.fetch_repo_data()
    ...
except Exception as e:
    return {
        "error": f"Failed to get repository summary: {str(e)}. Try https://gitingest.com/{url} instead"
    }
```

`owner` and `repo` are never checked against GitHub's naming rules, so any string, including markup, quotes and control characters, ends up in the returned text. The same pattern is in `git_tree` (`server.py:62-72`) and `git_files` (`server.py:90-108`).

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`, `git`, outbound access to `github.com` (gitingest may try `git ls-remote` / `git clone` before failing). Python with the `mcp` package for the client.
2. Start the server as the README describes: `uvx --from git+https://github.com/puravparab/gitingest-mcp gitingest-mcp` (append `@c3b630a07304fb02e98eec12d38640a8c024a4ed` to the URL to match the tested commit).
3. Call the tool with `{"owner": "<b>tofu-poc</b>", "repo": ""}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uvx",
           args=["--from", "git+https://github.com/puravparab/gitingest-mcp@c3b630a07304fb02e98eec12d38640a8c024a4ed",
                 "gitingest-mcp"],
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("git_summary", {"owner": "<b>tofu-poc</b>", "repo": ""})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the `error` string ends with `Try https://gitingest.com/https://github.com/<b>tofu-poc</b>/ instead`, markup unchanged.

## Expected behavior
Invalid owner or repository names are rejected up front with a fixed message, and any caller text that is echoed back is neutralised.

## Actual behavior
The raw value is echoed. Logged output from fuzzing, for ``owner = '"branch": {{br`nch": "[obj'`` and `repo = ''`:

```
{"error": "Failed to get repository summary: Invalid repository URL '/\"branch\": {{br`nch\": \"[obj/'. Try https://gitingest.com/https://github.com/\"branch\": {{br`nch\": \"[obj/ instead"}
```

## Impact
Tool arguments come from the model and can be steered by prompt injection, and the text goes back to the client. The result is JSON in a text block, so most MCP clients display it as plain text and nothing renders. It matters only for a client or UI that renders tool output as HTML or Markdown without escaping. Severity is low; this is a hardening issue.

## Suggested fix
Validate `owner`, `repo` and `branch` before building the URL (for example owner `^[A-Za-z0-9][A-Za-z0-9-]{0,38}$`, repo `^[A-Za-z0-9._-]{1,100}$`) and return a fixed error otherwise. Then the "Try https://gitingest.com/..." hint can only contain valid names. Apply the same check in `git_tree` and `git_files`.

## Status on the default branch
Still present at `c3b630a` (2025-03-21). The default branch has no commits after the tested one.

## Prior reports
None found. Searched all 4 issues and 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` (token `{{`). Also fired for this tool: `check_introspection_command_injection`, `check_introspection_incomplete_cleanup`, `check_introspection_log_injection`, `check_introspection_temp_file_leak`; not part of this draft.
- Campaigns and executions: corpus-sbx 2048 exec / 2039 success.
- Evidence (verbatim, trimmed):
  - ``{'owner': '"branch": {{br`nch": "[obj', 'repo': '', 'branch': ''}`` -> ``{"error": "Failed to get repository summary: Invalid repository URL '/\"branch\": {{br`nch\": \"[obj/'. Try https://gitingest.com/https://github.com/\"branch\": {{br`nch\": \"[obj/ instead"}``
  - `{'owner': '{{{{...{{"bra?ch"2 "ran)]', 'repo': '', 'branch': ''}` -> same shape, `{{` echoed.
- Hand-check hints: weak. Only template braces `{{` were echoed, into a JSON error string returned as plain text; no HTML/Markdown rendering in this server. The `<b>tofu-poc</b>` reproduction is derived from `server.py:45`; I did not confirm whether gitingest raises "Invalid repository URL" or a clone error for it, but either way the server appends the raw `url`. Consider one combined "validate owner/repo/branch" issue covering `git_summary`, `git_tree` and `git_files`. Not run.
</details>
