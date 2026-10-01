# Missing output encoding in `get-execution-plan`: the SQL text is echoed raw into the reply

**Repository:** `PuroDelphi/mcpFirebird` · **Tool:** `get-execution-plan` · **Tested commit:** `0b0980f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get-execution-plan` does not compute a plan. It returns a fixed explanation and copies the caller's `sql` into the `query` field of the JSON reply. Markup or template braces in the SQL text come back unchanged. The reply is JSON in a plain MCP text block, so this only matters for a client that renders tool output as Markdown or HTML. Low severity.

## Details
`src/tools/database.ts:310-341` (tested commit) passes `sql` to `getExecutionPlan` and returns the result through `formatForClaude` (`JSON.stringify(result, null, 2)`, `src/utils/jsonHelper.ts:37-51`):

```ts
if (!validateSql(sql)) throw new FirebirdError('Potentially unsafe SQL query', 'SECURITY_ERROR');
assertSqlOperationAllowed(sql);
const result = await getExecutionPlan(sql, params || []);
return { content: [{ type: "text", text: formatForClaude(result) }] };
```

`getExecutionPlan` (`src/db/queries.ts:618-710`) returns the SQL as given, without contacting the database:

```ts
return {
    query: sql,
    plan: "Execution plan not available",
    planDetails: [],
    success: true,
    analysis: "Node.js Firebird drivers do not expose the execution plan API.\n\n" + ...
```

`JSON.stringify` escapes quotes and control characters but not `<`, `>`, `{{` or `${`.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No Firebird server is needed; the tool does not query the database.
2. Install and build: `git clone https://github.com/PuroDelphi/mcpFirebird.git && cd mcpFirebird && git checkout 0b0980f && npm install && npm run build`
3. Call the tool with:

   ```json
   {"sql": "SELECT '<b>tofu-poc</b>' FROM RDB$DATABASE", "params": []}
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
               result = await session.call_tool("get-execution-plan",
                   {"sql": "SELECT '<b>tofu-poc</b>' FROM RDB$DATABASE", "params": []})
               print(result)

   asyncio.run(main())
   ```
4. Observe `"query": "SELECT '<b>tofu-poc</b>' FROM RDB$DATABASE"` in the reply.

## Expected behavior
The tool either omits the query from the reply or encodes it for the rendering context.

## Actual behavior
The SQL is echoed. From the fuzzing run (trimmed):

```
{
  "query": "SELECT\u0017XX/_\n]\nS${,",
  "plan": "Execution plan not available",
  "planDetails": [],
  "success": true,
  ...
}
```

## Impact
The LLM writes the `sql` argument, and prompt injection can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup; in a plain-text client there is no effect. Low severity.

## Suggested fix
Drop `query` from the reply (the caller already has it), or encode it for the rendering context if it has to stay.

## Status on the default branch
Changed at `bf1b3bf` (2026-09-29). `validateSql` was replaced by `prepareUserQuery` (`src/security/sqlPolicy.ts`), a strict lexer that rejects `{` and a `$` outside an identifier. The fuzzer's payloads (`{{`, `${`) would now be rejected. The reply still copies the SQL into `query` (`src/db/queries.ts:719`). Markup inside a quoted string literal, as in the repro above, should still pass the lexer and be echoed. We have not run this against the default branch.

## Prior reports
- No related issue or pull request among all 25 issues and 9 pull requests (fetched 2026-10-01).
- Documentation: CHANGELOG.md: "Simplified to return informative message instead of attempting unsupported operations" (documents that the tool returns a fixed explanation instead of a plan; it does not mention that the SQL text is copied into the reply)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: repo24-b 233984 exec / 15019 ok and 258560 / 15947 (4200 s each). Not seen in corpus-sbx or e2-0922.
- Evidence (verbatim, trimmed):
  - `{'sql': 'SELECT\x17XX/_\n]\nS${,', 'params': []}` -> `"query": "SELECT\u0017XX/_\n]\nS${,", "plan": "Execution plan not available", ... "success": true`
  - `{'sql': "SELECT{{SELECTFRi\x068e!'4e#AAAA...", 'params': []}` -> `"query": "SELECT{{SELECTFRi\u00068e!'4e#AAAA..."`
  - Third input of the same shape, same result.
- Hand-check hints: weak. Only `{{` / `${` were echoed, inside a JSON string in a plain-text reply. The echo is real (`queries.ts:671-672`). The `<b>` repro is my substitution and was not run; I did not verify that `checkAllowedOperation('SELECT')` passes under the default security config or that HEAD's `prepareUserQuery` accepts `RDB$DATABASE`. Probably not worth filing on its own.
</details>
