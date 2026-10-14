# `search-todos-by-title`: CR/LF in `title` flagged as log injection, but the search term never reaches a log (likely false positive)

**Repository:** `RegiByte/todo-list-mcp` · **Tool:** `search-todos-by-title` · **Tested commit:** `a04a792`
**Weakness:** CWE-117 Improper Output Neutralization for Logs (as flagged by the fuzzer; not confirmed)

## Summary
`search-todos-by-title` runs a case-insensitive `LIKE` search over todo titles. Our fuzzer flagged it because search terms containing CR/LF were accepted and the call succeeded. Reading the code, the search term is never written to a log: it only goes into a bound SQLite parameter, and the server's only log call on this path prints a fixed message plus an exception. I could not find a log injection here. This draft records the alert and the review so it can be closed or dropped.

## Details
The handler, `src/index.ts:320-332`, and the query, `src/services/TodoService.ts:218-229`:

```ts
  searchByTitle(title: string): Todo[] {
    // Add wildcards to the search term for partial matching
    const searchTerm = `%${title}%`;

    const db = databaseService.getDb();

    // COLLATE NOCASE makes the search case-insensitive
    const stmt = db.prepare('SELECT * FROM todos WHERE title LIKE ? COLLATE NOCASE');
    const rows = stmt.all(searchTerm) as any[];

    return rows.map(row => this.rowToTodo(row));
  }
```

The only logging in the server is `console.error` in `safeExecute` (`src/index.ts:76`), at startup (`:444-445`, `:477`, `:479`) and on shutdown (`:457`, `:463`). `safeExecute` logs a fixed string and the thrown error. Neither contains the search term on this path. The `services/` and `utils/` files have no logging at all.

## Steps to reproduce
1. Prerequisites: Node.js. Use a scratch database directory: `TODO_DB_FOLDER=/tmp/tofu-poc-todo` (`src/config.ts:46`).
2. Install and start the server as the README describes: `npm install && npm run build`, then `node dist/index.js`, with stderr captured.
3. Call the tool:

   ```json
   {"title": "tofu\r\nFAKE-LOG-ENTRY"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/todo-list-mcp/dist/index.js"], env={"TODO_DB_FOLDER": "/tmp/tofu-poc-todo"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("search-todos-by-title", {"title": "tofu\r\nFAKE-LOG-ENTRY"})
               print(result)

   asyncio.run(main())
   ```
4. Expected per the code: the result is `No todos found.` and stderr shows only the startup lines. No line contains `FAKE-LOG-ENTRY`.

## Expected behavior
Search terms are not written to logs, or are neutralized if they are.

## Actual behavior
The code matches the expected behavior: no log record contains the term. From the fuzzing run:

```
input:  {'title': 'test\nCRLF_injection'}
output: No todos found.
```

## Impact
None found for CWE-117. A side note that is not a security issue: `%` and `_` in the search term act as `LIKE` wildcards, so a search for `a_c` also matches `abc`, and a search for `%` matches every todo. If literal matching is intended, escape them and add `ESCAPE '\'` to the query.

## Suggested fix
No security fix needed. Optionally escape `LIKE` wildcards as noted above.

## Status on the default branch
Unchanged at `a04a792` (2025-03-12). The tested commit is the current head of the default branch.

## Prior reports
None found. The repository has no issues; searched both pull requests (fetched 2026-10-01) and the README / docs on the default branch. Neither pull request (#1 badge, #2 "Refactor/use sql alchemy (ORM)", closed 2026-01-19, no description) is about logging or search input, and the docs say nothing about logging.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117) via `check_log_injection`, the only sanitizer that fired. It is an input-pattern check reported as a "Silent Bug Alert" (input contained CR/LF and the call did not raise). No introspection log sink fired.
- Campaigns and executions: `corpus-sbx` 2560 executions / 1887 successful; `e2-0922` 2048 / 1884; 60 s budgets.
- Evidence (verbatim, trimmed):
  - `{'title': 'test\nCRLF_injection'}` -> `{'content': [{'type': 'text', 'text': 'No todos found.'}]}`
  - `{'title': '\r\rt{{"'}` -> `No todos found.`
  - `{'title': '^"ttt\x00\n'}` -> `No todos found.`
- Hand-check hints: **weak, false positive** for CWE-117. No log sink receives `title`; the SQL is parameterized. Recommend not filing. The `LIKE` wildcard note is a correctness nit only. Steps not executed (read-only review); the "expected per the code" observation is from reading `src/index.ts` and `src/services/TodoService.ts`.
</details>
