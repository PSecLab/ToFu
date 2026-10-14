# Missing output encoding in `analyze_players`: `team` and `position` are echoed raw into the summary

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `analyze_players` · **Tested commit:** `fdaef00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`analyze_players` filters the FPL player list and returns a summary that names the filters it applied. The `team` value is always copied verbatim into `filters_applied`. The `position` value is copied verbatim either into `filters_applied` (when it matches no known position) or into `position_note` (when it partially matches one). Markup and template syntax in these arguments therefore come back unescaped in the tool result.

## Details
`src/fpl_mcp/fpl/tools/analysis.py` at `fdaef00`:

```python
        # Build filter description                                   # line 167
        applied_filters = []
        if normalized_position:
            applied_filters.append(f"Position: {normalized_position}")
        if team:
            applied_filters.append(f"Team: {team}")
        ...
        # Add position normalization note if relevant                # line 203
        if position_changed:
            result["summary"]["position_note"] = f"'{position}' was interpreted as '{normalized_position}'"
```

`normalize_position` (`src/fpl_mcp/fpl/utils/position_utils.py:23-49`) returns its input unchanged when nothing matches. It also does substring matching, so `defenders<b>x</b>` becomes `DEF` and the raw string ends up in `position_note`. The function also logs `position` and `team` unchanged at line 62.

## Steps to reproduce
1. Prerequisites: Python 3.10 or later and outbound access to the public FPL API (`https://fantasy.premierleague.com/api`). You do not need an FPL account.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"position": "defenders<b>tofu-poc</b>", "team": "<b>tofu-poc</b>{{7*7}}", "limit": 1}
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
               result = await session.call_tool("analyze_players", {"position": "defenders<b>tofu-poc</b>", "team": "<b>tofu-poc</b>{{7*7}}", "limit": 1})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: `summary.filters_applied` contains `"Team: <b>tofu-poc</b>{{7*7}}"`, and `summary.position_note` is `"'defenders<b>tofu-poc</b>' was interpreted as 'DEF'"`.

## Expected behavior
Filter values echoed in the summary should be escaped or replaced by their normalized form. `position` can be reported as the normalized code only. `team` can be reported as the matched team name, or dropped from the summary when it matches no team.

## Actual behavior
The values are copied verbatim. From the fuzzing run:

```
"filters_applied": ["Position: DEF", "Team: Chelse{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{a", ...],
"position_note": "'\"pocition\": \"defenders\",' was interpreted as 'DEF'"
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call can make the tool result carry arbitrary markup. This is only a problem in clients that render tool results as HTML or Markdown, or feed them into a template engine. Otherwise it is low severity.

## Suggested fix
- Report `position` only as the normalized code. Do not quote the raw input in `position_note`, or escape it first.
- Resolve `team` against the team list and report the canonical team name. If you echo the raw value, escape it and cap its length.
- Strip CR/LF before logging at `analysis.py:62`.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 9 issues and 20 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. The tool also triggered `check_introspection_log_injection` and `check_resource_exhaustion`. I did not examine either.
- Campaigns and executions: repo24-b 193,536 exec / 22,310 ok (4200 s). The low success ratio was not investigated.
- Evidence (verbatim, trimmed):
  - input `{'position': '"pocition": "defenders",', 'team': 'Chelse{{{{...{{a', 'min_price': '1.5', 'max_price': '5.5', ...}` -> output `{"summary": {"total_matches": 0, "filters_applied": ["Position: DEF", "Team: Chelse{{{{...a", ...], "position_note": "'\"pocition\": \"defenders\",' was interpreted as 'DEF'"}, "players": []}`.
  - input `{'position': '"p{{{{{{{{{{{{{{{{{{{{{{', 'team': 'Chelsea', ...}` -> `"filters_applied": ["Position: \"p{{{{{{{{{{{{{{{{{{{{{{", ...]`. The position matched nothing and was returned raw.
- Hand-check hints: weak. Only `{{` was reflected, in a JSON result. This server has no HTML rendering context. The `<b>` reproduction comes from reading the code: `normalize_position` substring-matches `def`, so `position_note` is produced. Reflecting filter values is arguably expected behavior.
</details>
