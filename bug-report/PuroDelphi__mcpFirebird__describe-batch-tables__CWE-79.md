# Missing output encoding in `describe-batch-tables`: table names are echoed raw into the reply

**Repository:** `PuroDelphi/mcpFirebird` · **Tool:** `describe-batch-tables` · **Tested commit:** `0b0980f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`describe-batch-tables` describes several tables and returns one JSON entry per requested name. Each entry includes the caller's `tableName` exactly as given, on both the success and the error path. The reply is JSON inside a plain MCP text block, so this only matters for a client that renders tool output as Markdown or HTML. Low severity.

## Details
`src/tools/database.ts:424-456` (tested commit) returns the batch result as pretty JSON:

```ts
tableNames.forEach(checkAllowedTable);
const results = await describeBatchTables(tableNames, undefined, maxConcurrent);
...
return { content: [{ type: "text", text: formatForClaude(results) }] };
```

`describeBatchTables` (`src/db/queries.ts:989-1074`) puts the name back into each entry, including on failure:

```ts
return { tableName, schema: null, error: errorMessage, errorType };
```

`formatForClaude` is `JSON.stringify(result, null, 2)` (`src/utils/jsonHelper.ts:37-51`), which escapes quotes and control characters but not `<`, `>` or `{{`. The per-name checks before that (`validateSql` and `checkAllowedTable`) look for SQL patterns and an optional allow list; they do not restrict table names to identifier characters.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No Firebird server is needed: the error path echoes the name too.
2. Install and build: `git clone https://github.com/PuroDelphi/mcpFirebird.git && cd mcpFirebird && git checkout 0b0980f && npm install && npm run build`
3. Call the tool with:

   ```json
   {"tableNames": ["<b>tofu-poc</b>"], "maxConcurrent": 1}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="node", args=["dist/cli.js", "--database", "/tmp/tofu-none.fdb"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("describe-batch-tables",
                   {"tableNames": ["<b>tofu-poc</b>"], "maxConcurrent": 1})
               print(result)

   asyncio.run(main())
   ```
4. Observe `"tableName": "<b>tofu-poc</b>"` unchanged in the reply.

## Expected behavior
Names that are not valid Firebird identifiers are rejected before use, or the value is encoded for the context it will be shown in.

## Actual behavior
The name comes back as given. From the fuzzing run (no database reachable):

```
[
  {
    "tableName": "{{{{{{{aaa",
    "schema": null,
    "error": "Connection refused at 127.0.0.1:3050. Verify that the Firebird server is running and accessible at this address.",
    "errorType": "DATABASE_CONNECTION_ERROR"
  }
]
```

## Impact
The LLM chooses `tableNames`, and prompt injection can steer it. The echoed value goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup into the chat view. In a plain-text client there is no effect. Low severity.

## Suggested fix
Validate each name as a Firebird identifier (for example `/^[A-Za-z][A-Za-z0-9_$]{0,62}$/`, or allow a quoted identifier form explicitly) before calling `describeTable`. If arbitrary text must be echoed, encode it for the rendering context.

## Status on the default branch
Still present at `bf1b3bf` (2026-09-29). The handler is at `src/tools/database.ts:452` and `describeBatchTables` at `src/db/queries.ts:1031`; both still return `tableName` unchanged.

## Prior reports
None found. Searched all 25 issues and 9 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: repo24-b 235520 exec / 8797 ok and 181248 / 4374 (4200 s each). Not seen in corpus-sbx or e2-0922.
- Evidence (verbatim, trimmed):
  - `{'tableNames': ["SELE{{{{...{{CTs(aOR 'a(aa"], 'maxConcurrent': 5}` -> `"tableName": "SELE{{{{...CTs(aOR 'a(aa", "schema": null, "error": "Connection refused at 127.0.0.1:3050. ..."`
  - `{'tableNames': ["SELE{{{{{{{{{{{{{{{{{{{{{{{{CTs(aOR 'a(aa"], 'maxConcurrent': 5}` -> same shape.
  - `{'tableNames': ['{{{{{{{aaa'], 'maxConcurrent': 1}` -> same shape.
- Hand-check hints: weak. Only `{{` template braces were echoed, inside a JSON string in a plain-text reply. The echo is real (confirmed at `queries.ts:1050-1063` and `database.ts:438-443`). The `<b>` payload in the repro is my substitution and was not run; I assumed `validateSql` accepts it (it starts with `<`, so the SELECT quote-balance branch does not apply). Probably not worth filing as XSS; at most a "validate identifiers" hardening note.
</details>
