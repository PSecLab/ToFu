# Missing output encoding in `get_price_changes`: an invalid `direction` is echoed raw into the error result

**Repository:** `rishijatia/fantasy-pl-mcp` · **Tool:** `get_price_changes` · **Tested commit:** `fdaef00`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_price_changes` lists players whose price rose or fell this gameweek, optionally filtered by `direction` (`risers` or `fallers`). Any other value makes the tool return an error that contains that value verbatim, apart from lowercasing. Markup and template syntax in `direction` come back unescaped. This path returns before any API call, so no network access is needed to trigger it.

## Details
`src/fpl_mcp/fpl/tools/players.py:347-353` at `fdaef00`:

```python
        direction = unwrap(direction, "direction", default=None)
        limit = unwrap(limit, "limit", default=20)

        if direction is not None:
            direction = str(direction).lower()
            if direction not in ("risers", "fallers"):
                return {"error": f"Invalid direction: {direction}. Use 'risers' or 'fallers'"}
```

The value is checked against an allow-list, which is good. The rejected value is then still copied into the error string.

## Steps to reproduce
1. Prerequisites: Python 3.10 or later. You need no account and no network access for this path.
2. Install and start the server:
   ```
   pip install "git+https://github.com/rishijatia/fantasy-pl-mcp.git@fdaef005143347455fc500cb1f934d451f95251a"
   python -m fpl_mcp
   ```
3. Call the tool with these arguments:
   ```json
   {"direction": "<b>tofu-poc</b>{{7*7}}", "limit": 1}
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
               result = await session.call_tool("get_price_changes", {"direction": "<b>tofu-poc</b>{{7*7}}", "limit": 1})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is `{"error": "Invalid direction: <b>tofu-poc</b>{{7*7}}. Use 'risers' or 'fallers'"}`.

## Expected behavior
A rejected enum value should produce a fixed message such as `Invalid direction. Use 'risers' or 'fallers'`. If the value is echoed at all, it should be escaped.

## Actual behavior
The rejected value is copied into the result. From the fuzzing run:

```
{"error": "Invalid direction: \"{{\"direction\":. Use 'risers' or 'fallers'"}
```

## Impact
The LLM chooses tool arguments, and prompt injection can steer them. A steered call can put markup into the tool result. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. Otherwise it is low severity.

## Suggested fix
Drop the rejected value from the message, or escape it and cap its length. You could also declare the parameter as `Optional[Literal["risers", "fallers"]]` so that schema validation rejects other values before the handler runs.

## Status on the default branch
Still present at `fdaef00` (2026-08-02). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 9 issues and 20 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. The tool also triggered `check_introspection_insecure_file_permissions`, which I did not examine.
- Campaigns and executions: corpus-sbx 3,584 exec / 3,573 ok (60 s). repo24-b 373,248 / 372,889 (4200 s).
- Evidence (verbatim, trimmed):
  - input `{'direction': '"{{"direction":', 'limit': -1289589216}` -> `'{"error": "Invalid direction: \\"{{\\"direction\\":. Use \'risers\' or \'fallers\'"}'`.
  - input `{'direction': '"{{"\x00!rection":', 'limit': -1289589216}` -> `'{"error": "Invalid direction: \\"{{\\"\\u0000!rection\\":. Use \'risers\' or \'fallers\'"}'`.
- Hand-check hints: weak. Only `{{` was reflected, in a JSON error string. This server has no HTML rendering context. The `<b>` reproduction comes from reading the code (the value is lowercased first, which does not change this payload). The `Literal` suggestion is mine, not from the repo.
</details>
