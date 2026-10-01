# Missing output encoding in `search_fpl_players`: `query` is echoed raw in the result

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `search_fpl_players` · **Tested commit:** `fdaef00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`search_fpl_players` searches players by name, with optional position and team filters. The result object always repeats the caller's `query`, `position` and `team` verbatim. Markup and template syntax in these values come back unescaped. The query is also logged without neutralizing CR/LF.

## Details
`src/fpl_mcp/fpl/tools/players.py` at `fdaef00`. The tool (lines 306-328) passes its arguments straight to `search_players` (lines 216-263):

```python
    logger = logging.getLogger(__name__)
    logger.info(f"Searching players: query={query}, position={position}, team={team}")
    ...
    return {
        "query": query,
        "filters": {
            "position": position,
            "team": team,
        },
        "total_matches": len(matches),
        "players": matches
    }
```

None of the three values is escaped or limited before it goes back to the client (line 255 onward) or into the log (line 235).

## Steps to reproduce
1. Prerequisites: Python 3.10 or later and outbound access to the public FPL API (`https://fantasy.premierleague.com/api`). You do not need an FPL account.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"query": "<b>tofu-poc</b>{{7*7}}", "limit": 1}
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
               result = await session.call_tool("search_fpl_players", {"query": "<b>tofu-poc</b>{{7*7}}", "limit": 1})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result starts with `{"query": "<b>tofu-poc</b>{{7*7}}", ...}`. If the query contains `\r\nFAKE-LOG-ENTRY`, `FAKE-LOG-ENTRY` appears on its own line in the stderr log.

## Expected behavior
Echoed search terms should be escaped for the output context, or left out of the result. Logged values should have CR/LF neutralized.

## Actual behavior
The query is copied into the result unchanged. From the fuzzing run:

```
{"query": "{{", "filters": {"position": "", "team": ""}, "total_matches": 0, "players": []}
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call can put markup into the tool result. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. Echoing a search term is common, so this is low severity.

## Suggested fix
- Leave `query` out of the result (the caller already has it), or escape it and cap its length.
- Strip CR/LF before logging at `players.py:235`, or log with `%r`.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 9 issues and 20 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. The tool also triggered `check_introspection_log_injection` and `check_introspection_insecure_file_permissions`. I did not examine the second.
- Campaigns and executions: corpus-sbx 1,536 exec / 1,530 ok (60 s). repo24-b 198,656 / 198,319 (4200 s).
- Evidence (verbatim, trimmed):
  - corpus-sbx input `{'query': '{{', 'position': '', 'team': '', 'limit': 0}` -> `'{"query": "{{", "filters": {"position": "", "team": ""}, "total_matches": 0, "players": []}'`.
  - repo24-b input `{'query': '"query": "Bruno Fernan{{~es", "po', ...}` -> `'{"query": "\\"query\\": \\"Bruno Fernan{{~es\\", \\"po", ...}'`.
- Hand-check hints: weak, and the weakest of this repo's set. Repeating the search term in a search result is ordinary behavior. Only `{{` was reflected, inside JSON. Consider dropping this one or folding it into a single fantasy-pl-mcp "output encoding + CR/LF in logs" issue.
</details>
