# Missing output encoding in `analyze_player_fixtures`: `player_name` is echoed raw into the error result

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `analyze_player_fixtures` · **Tested commit:** `fdaef00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`analyze_player_fixtures` looks up a player by name and returns a fixture difficulty analysis. When no player matches, it builds the error message by inserting the caller's `player_name` into the result as-is. The result is serialized to JSON text, which escapes quotes and control characters but leaves markup and template syntax (`<`, `>`, `{{`, `${`) intact. A client that renders tool output as Markdown or HTML will render whatever the caller put in the name.

## Details
`src/fpl_mcp/fpl/tools/fixtures.py:19-37` at `fdaef00`:

```python
    @mcp.tool()
    async def analyze_player_fixtures(player_name: str, num_fixtures: int = 5) -> Dict[str, Any]:
        ...
        logger.info(f"Tool called: analyze_player_fixtures({player_name}, {num_fixtures})")

        player_name = unwrap(player_name, "player_name", "query")
        num_fixtures = unwrap(num_fixtures, "num_fixtures", default=5)

        # Find the player
        player_matches = await players.find_players_by_name(player_name)
        if not player_matches:
            return {"error": f"No player found matching '{player_name}'"}
```

Nothing escapes or limits `player_name` before it goes into the `error` string (line 37). Line 29 also writes the raw value to the log, so CR/LF in the name start new log lines.

## Steps to reproduce
1. Prerequisites: Python 3.10 or later and outbound access to the public FPL API (`https://fantasy.premierleague.com/api`). You do not need an FPL account.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"player_name": "<b>tofu-poc</b>{{7*7}}${7*7}", "num_fixtures": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="python", args=["-m", "fpl_mcp"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("analyze_player_fixtures", {"player_name": "<b>tofu-poc</b>{{7*7}}${7*7}", "num_fixtures": 1})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result text contains `No player found matching '<b>tofu-poc</b>{{7*7}}${7*7}'` with the markup unchanged. If you add `\r\nFAKE-LOG-ENTRY` to the name, the server's stderr log shows `FAKE-LOG-ENTRY` at the start of its own line.

## Expected behavior
The tool should not reflect caller-supplied markup verbatim. It can return a fixed message ("No player found"), or escape or strip the name before putting it in the result.

## Actual behavior
The name is copied into the result unchanged. From the fuzzing run (the input started with `{\x7f"\x7f{"{{{`):

```
{"error": "No player found matching '{\u007f\"\u007f{\"{{{\u007f\"\u007f{\u0001'"}
```

## Impact
In MCP the LLM picks the tool arguments, and prompt injection in content it has read can steer them. A steered call can put markup or template syntax into a tool result. This only matters if the client renders tool results as HTML or Markdown, or passes them to a template engine. In a plain-text client the impact is low.

## Suggested fix
- Return a fixed error message, or escape the name for the output context (for example `html.escape(player_name)`) and cap its length.
- Strip CR/LF from values before logging them (`fixtures.py:29`), or log with `%r`.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 9 issues and 20 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. The tool also triggered `check_introspection_log_injection` (logger `fpl_mcp.fpl.tools.fixtures`) and `check_introspection_insecure_file_permissions`. I did not examine the file-permissions signal; it is probably the diskcache store.
- Campaigns and executions: corpus-sbx 512 exec / 503 ok (60 s). repo24-b 103,936 / 103,827 and 74,240 / 74,158 (4200 s each).
- Evidence (verbatim, trimmed):
  - corpus-sbx input `{'player_name': '{\x7f"\x7f{"{{{\x7f"\x7f{\x01', 'num_fixtures': 0}` -> output `'{"error": "No player found matching \'{\\u007f\\"\\u007f{\\"{{{\\u007f\\"\\u007f{\\u0001\'"}'`, token `{{`.
  - repo24-b input `{'player_name': '"pemerso\x12\x11_\x1c\x10\r\r\x1bia da{"player_name": "adm${"pla', 'num_fixtures': 0}`: token `${` reflected. Log alert: `Tool called: analyze_player_fixtures("pemerso...\r\r...adm${"pla, 0)` with raw CR.
- Hand-check hints: weak. Only `{{` and `${` were reflected, inside a JSON error string. This server has no HTML rendering context. The `<b>` reproduction comes from reading the code, not from a logged run. The CR/LF log line (`fixtures.py:29`, logging to stderr through `basicConfig` in `__main__.py:12`) is the more concrete finding. Consider filing it as CWE-117 instead of, or together with, this one.
</details>
