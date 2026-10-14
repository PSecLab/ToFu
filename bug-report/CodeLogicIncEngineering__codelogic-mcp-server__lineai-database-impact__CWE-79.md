# Missing output encoding in `lineai-database-impact`: `name` is echoed unescaped into the Markdown report

**Repository:** `CodeLogicIncEngineering/codelogic-mcp-server` · **Tool:** `lineai-database-impact` · **Tested commit:** `6fdff87`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`lineai-database-impact` looks up a database table, view or column on the Lineai server and returns a Markdown report. The caller's `name` and `table_or_view` values are pasted into Markdown headings and sentences without any escaping. If a client renders the tool result as Markdown or HTML, markup in those arguments is rendered as markup. This depends on the client, and our fuzzer only saw template braces (`{{`) echoed back, so the impact is low.

## Details
`src/lineai_mcp_server/handlers/database_impact.py:52-60` builds the "not found" answer straight from the arguments:

```python
    if not search_results:
        table_view_text = f" in {table_or_view}" if table_or_view else ""
        return [
            types.TextContent(
                type="text",
                text=f"# No {entity_type}s found matching '{name}'{table_view_text}\n\nNo database {entity_type}s were found matching the name '{name}'"
                     + (f" in {table_or_view}" if table_or_view else "") + "."
            )
        ]
```

The "found" branch does the same in `src/lineai_mcp_server/utils.py:833-834` (`generate_combined_database_report`):

```python
    table_view_text = f" in {table_or_view}" if table_or_view else ""
    report = f"# Database Impact Analysis: {entity_type.capitalize()}s matching '{search_name}'{table_view_text}\n\n"
```

`search_database_entity` (`utils.py:415-469`) returns `[]` on any exception, including a failed login or an unreachable host, so the "not found" text above is also what the tool returns when the backend cannot be reached. `entity_type` is checked against `column`/`table`/`view` (`database_impact.py:33`), but `name` and `table_or_view` are not escaped or validated.

## Steps to reproduce
1. Prerequisites: Python 3.13 or 3.14 (`requires-python = ">=3.13,<3.15"`) and `uv`. No Lineai account is needed for this check. With an unreachable `LINEAI_SERVER_HOST`, the search fails, returns an empty list, and the tool answers with the "not found" text. A real server gives the same echo in the report heading.
2. Install and start the server from a checkout, as in the README's `uv --directory ... run lineai-mcp-server` example:

   ```bash
   git clone https://github.com/CodeLogicIncEngineering/codelogic-mcp-server.git
   cd codelogic-mcp-server
   uv sync
   ```
3. Call the tool with these arguments:

   ```json
   {"entity_type": "view", "name": "<b>tofu-poc</b> [link](http://127.0.0.1:9/)"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv",
           args=["--directory", "/path/to/codelogic-mcp-server", "run", "lineai-mcp-server"],
           env={"LINEAI_SERVER_HOST": "http://127.0.0.1:9", "LINEAI_WORKSPACE_NAME": "tofu-poc"},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "lineai-database-impact",
                   {"entity_type": "view", "name": "<b>tofu-poc</b> [link](http://127.0.0.1:9/)"},
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe: the returned text contains the HTML tag and the Markdown link unchanged, inside a Markdown heading: `# No views found matching '<b>tofu-poc</b> [link](http://127.0.0.1:9/)'`. In a client that renders tool output as Markdown, the name shows as bold text plus a clickable link.

## Expected behavior
Values taken from tool arguments should be encoded for the output format before they go into the report. For Markdown, that means putting them in a code span (or escaping Markdown and HTML metacharacters) so they show as literal text.

## Actual behavior
The arguments are copied into the Markdown as-is. From the fuzzing run, input `{"entity_type": "view", "name": "\"ent{{\"", "table_or_view": ""}` returned:

```
# No views found matching '"ent{{"'

No database views were found matching the name '"ent{{"'.
```

## Impact
In MCP, tool arguments are chosen by the LLM, and prompt injection in code, SQL or documents the model reads can steer them. If the client renders tool results as Markdown or HTML, an injected `name` can add links, images or formatting to the report. An image link would make the client fetch an attacker-chosen URL. Many clients show tool results as plain text or only pass them to the model, and in that case there is no effect. There is no server-side impact. Low severity.

## Suggested fix
Wrap user-supplied values in a code span before putting them into Markdown, for example:

```python
def md_literal(value: str) -> str:
    value = str(value).replace("`", "'").replace("\r", " ").replace("\n", " ")
    return f"`{value}`"
```

Use it for `name` and `table_or_view` in `handlers/database_impact.py:57-58` and for `search_name` and `table_or_view` in `utils.py:833-834`. Entity names that come back from the server are already put in code spans (`utils.py:855-864`), but a backtick in a name would close the span early, so the same backtick handling helps there too.

## Status on the default branch
Still present at `6fdff87` (2026-08-12). The tested commit is the current head of the default branch.

## Prior reports
- No issue or PR reports unescaped arguments in this tool's output. Searched all 8 issues and 49 pull requests (fetched 2026-10-01) and the README, SECURITY.md, CONTRIBUTING.md, `.cursor/rules/` and `.github/copilot-instructions.md` on the default branch. #1 "[Feature]: Database Impact Analysis" and #2 "initial code for database impact analysis" (closed 2025-04-08) added the tool and say nothing about escaping. #10 and #13 (MseeP.ai badge PRs, closed 2025-09-02) report a third-party scan score of 100/100 with no findings.
- Documentation: .github/copilot-instructions.md: "Return markdown-formatted text in tool responses" (Markdown output is intended, so encoding for Markdown is the relevant fix).
- Documentation: SECURITY.md: "Please do not disclose security vulnerabilities publicly until they have been handled by the team." (reports go by email to devops@lineai.net; affects how this is filed).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: `reflected-xss` (CWE-79), fired by `check_reflected_output` only (the payload token `{{` echoed unescaped). Triggered list: `check_reflected_output`.
- Campaigns and executions: corpus-sbx: 3072 exec / 3059 ok (budget 60s); repo24: 225792 exec / 225783 ok (budget 4200s).
- Evidence (verbatim, trimmed):
  - [corpus-sbx] input `{'entity_type': 'view', 'name': '"ent{{"', 'table_or_view': ''}` -> output `'# No views found matching \'"ent{{"\'\n\nNo database views were found matching the name \'"ent{{"\'.'`
  - [corpus-sbx] input `{'entity_type': 'view', 'name': '"ent{{e', 'table_or_view': ''}` -> output `'# No views found matching \'"ent{{e\'\n\nNo database views were found matching the name \'"ent{{e\'.'`
  - [corpus-sbx] input `{'entity_type': 'view', 'name': 'y\x08{{y\x08', 'table_or_view': ''}` -> output `"# No views found matching 'y\x08{{y\x08'\n\nNo database views were found matching the name 'y\x08{{y\x08'."`
- Hand-check hints: weak. Only `{{` was echoed, into a plain-text MCP `TextContent` that is formatted as Markdown. `{{` means nothing to a Markdown renderer. The echo itself is real (f-string at `database_impact.py:57`), and HTML/Markdown in `name` would pass through unchanged by code reading. Whether any client renders this tool's output is not verified. The echo is in the "not found" path, which the fuzzer reached because the backend was unreachable (search errors are swallowed and return `[]`).
- Side observation, not part of this finding: `utils.py:468` writes `name` to stderr unneutralized (`Error searching for {entity_type} '{name}': ...`), a minor log-injection.
- Repo naming: at this commit the package and tools are branded "Lineai" (`lineai-mcp-server`, tool `lineai-database-impact`; `pyproject.toml` documentation URL points to `lineai-intelligence/lineai-mcp-server`). Confirm where the project now takes issues before filing.
- Fuzzed commit `6fdff87b4265ddbb69ccce149b7c845a65351718`; `head_sha` is the same commit.
- Install step `uv sync` is my assumption for a local checkout; the README only shows `uvx lineai-mcp-server@latest` and `uv --directory <repo> run lineai-mcp-server`.

</details>
