# Missing output encoding in `compare_players`: an unmatched player name is echoed raw into the error result

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `compare_players` · **Tested commit:** `fdaef00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`compare_players` takes a list of player names and compares their stats. If any name matches no player, the tool returns an error that contains the name verbatim. Markup and template syntax in a name come back unescaped. The same names are also logged without neutralizing CR/LF.

## Details
`src/fpl_mcp/fpl/tools/analysis.py:324-332` at `fdaef00`:

```python
        if not player_names or len(player_names) < 2:
            return {"error": "Please provide at least two player names to compare"}

        # Find all players by name
        players_data = {}
        for name in player_names:
            matches = await players.find_players_by_name(name, limit=3)  # Get more matches to find active players
            if not matches:
                return {"error": f"No player found matching '{name}'"}
```

The name is not escaped or length-limited before it goes into the error. The raw list is also logged at `analysis.py:306`, and each name is logged again by `find_players_by_name` (`src/fpl_mcp/fpl/resources/players.py:152`).

## Steps to reproduce
1. Prerequisites: Python 3.10 or later and outbound access to the public FPL API (`https://fantasy.premierleague.com/api`). You do not need an FPL account.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"player_names": ["<b>tofu-poc</b>{{7*7}}", "Salah"], "include_fixture_analysis": false}
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
               result = await session.call_tool("compare_players", {"player_names": ["<b>tofu-poc</b>{{7*7}}", "Salah"], "include_fixture_analysis": False})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is `{"error": "No player found matching '<b>tofu-poc</b>{{7*7}}'"}` with the markup unchanged. If the first name contains `\r\nFAKE-LOG-ENTRY`, `FAKE-LOG-ENTRY` appears on its own line in the stderr log.

## Expected behavior
The error should not reflect caller markup verbatim. It can use a fixed message, or an escaped and truncated copy of the name.

## Actual behavior
The name is copied into the result. From the fuzzing run:

```
{"error": "No player found matching '\"play{{\"playe\"player_names\": [\"../../../../etc/passwd\", \"Mohamed Salah\"'"}
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call can put markup into the tool result. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. Otherwise it is low severity.

## Suggested fix
- Escape the name for the output context and cap its length, or report the index of the unmatched entry instead of its text.
- Strip CR/LF before logging names (`analysis.py:306`, `resources/players.py:152`), or log with `%r`.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 9 issues and 20 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. The tool also triggered `check_introspection_log_injection` (logger `fpl_mcp.fpl.resources.players`), `check_introspection_insecure_file_permissions` and `check_resource_exhaustion`. I did not examine the last two.
- Campaigns and executions: corpus-sbx 512 exec / 506 ok (60 s). repo24-b 20,992 / 20,986 (4200 s).
- Evidence (verbatim, trimmed):
  - corpus-sbx input `{'player_names': ['"play{{"playe"player_names": ["../../../../etc/passwd", "Mohamed Salah"', ', r_names""met: ric', '', ''], 'metrics': [], ...}` -> `'{"error": "No player found matching \'\\"play{{\\"playe\\"player_names\\": [\\"../../../../etc/passwd\\", \\"Mohamed Salah\\"\'"}'`. The `../` is just reflected text; no file is opened.
  - repo24-b input with `\r` in the first name: log alert `Finding players by name: "player\x1dnames": [Br\ryn\x1ae"], ...{{{{...` with raw CR.
- Hand-check hints: weak. Only `{{` was reflected, in a JSON error string. This server has no HTML rendering context. The `<b>` reproduction comes from reading the code, not from a run. The CR log line through `resources/players.py:152` is the more concrete issue. It is shared by every tool that calls `find_players_by_name`.
</details>
