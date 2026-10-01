# Missing output encoding in `create-todo`: `title` and `description` are inserted raw into the Markdown response and stored

**Repository:** `RegiByte/todo-list-mcp` · **Tool:** `create-todo` · **Tested commit:** `a04a792`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`create-todo` stores a todo in SQLite and returns it formatted as Markdown: a `## <title>` heading, an ID and timestamps, then the description. Title and description are inserted unchanged. The description is meant to be Markdown, so raw Markdown there is expected. The title, though, has no checks at all: markup passes through, and a newline in it lets the caller add lines of their own, for example a second `ID:` line. The values are stored, so every later `list-todos`, `get-todo` or search call returns them again. The impact is low.

## Details
`src/utils/formatters.ts:31-41`:

```ts
export function formatTodo(todo: Todo): string {
  return `
## ${todo.title} ${todo.completed ? '✅' : '⏳'}

ID: ${todo.id}
Created: ${new Date(todo.createdAt).toLocaleString()}
Updated: ${new Date(todo.updatedAt).toLocaleString()}

${todo.description}
  `.trim();
}
```

The schema only requires non-empty strings (`src/index.ts:102-105`, `src/models/Todo.ts:50-53`). The handler returns `✅ Todo Created:\n\n${formatTodo(...)}` (`src/index.ts:106-118`). `formatTodoList` (`formatters.ts:52-59`) reuses `formatTodo` for the list and search tools. The insert itself uses bound parameters (`src/services/TodoService.ts:45-58`), so there is no SQL injection.

## Steps to reproduce
1. Prerequisites: Node.js. Use a scratch database directory so the reporter's real todo list is not touched: `TODO_DB_FOLDER=/tmp/tofu-poc-todo` (`src/config.ts:46`).
2. Install and start the server as the README describes: `npm install && npm run build`, then `node dist/index.js` (with the environment variable above).
3. Call the tool:

   ```json
   {"title": "<b>tofu-poc</b>", "description": "<i>tofu-poc</i>"}
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
               result = await session.call_tool("create-todo", {"title": "<b>tofu-poc</b>", "description": "<i>tofu-poc</i>"})
               print(result)
               print(await session.call_tool("list-todos", {}))

   asyncio.run(main())
   ```
4. The `create-todo` result contains the heading `## <b>tofu-poc</b>` and ends with `<i>tofu-poc</i>`, both unchanged. `list-todos` returns the same markup.

## Expected behavior
The title is a single line of plain text: CR/LF are rejected or stripped, and Markdown/HTML-significant characters are escaped when the title is placed in a heading. If descriptions are raw Markdown by design, that is documented so clients know to sanitize when rendering.

## Actual behavior
Both fields are echoed verbatim. From the fuzzing run:

```
input:  {'title': '"titl', 'description': '{{{{{{{C{"of'}
output: ✅ Todo Created:

        ## "titl ⏳

        ID: b4698a68-678b-463d-b80e-368603c99573
        ...
        {{{{{{{C{"of
```

## Impact
The model chooses the arguments, and prompt injection in untrusted content can steer it. The result is plain text that the server itself calls Markdown. It matters if a client renders tool output as Markdown with raw HTML enabled. Because todos persist, injected content is replayed on every listing. A newline in the title can also fake lines such as `ID: ...`, which could make the model act on the wrong todo ID. Low severity.

## Suggested fix
- Reject CR/LF in `title`, for example `z.string().min(1).regex(/^[^\r\n]+$/)` in both `create-todo` and `update-todo`.
- Escape Markdown-significant characters in the title inside `formatTodo` (at least `<`, `>`, `[`, `]`, `` ` ``, `#`, `*`, `_`).
- Document that `description` is returned as raw Markdown.

## Status on the default branch
Still present at `a04a792` (2025-03-12). The tested commit is the current head of the default branch.

## Prior reports
None found. The repository has no issues; searched both pull requests (fetched 2026-10-01) and the README / docs on the default branch. #1 adds a listing badge; #2 "Refactor/use sql alchemy (ORM)" (PR, closed 2026-01-19) has no description and the default branch is still `a04a792`.
- Documentation: README.md: "Add new tasks with title and markdown description" (documents `description` as Markdown by design; nothing about the title or escaping)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79). Only `check_reflected_output` fired, on `{{`.
- Campaigns and executions: `corpus-sbx`, 2560 executions, 1122 successful, 60 s budget.
- Evidence (verbatim, trimmed):
  - `{'title': '"t', 'description': 'tl{{{{{{{{{{{{{{{ ":ype C{"of'}` -> `✅ Todo Created:\n\n## "t ⏳\n\nID: 520d8fc9-60aa-4f1f-89b0-402a9688d3a2\nCreated: 9/26/2026, 3:03:14 PM\nUpdated: 9/26/2026, 3:03:14 PM\n\ntl{{{{{{{{{{{{{{{ ":ype C{"of`
  - `{'title': '"t', 'description': 'tl{{{{{{{{C{"of'}` -> same shape
  - `{'title': '"titl', 'description': '{{{{{{{C{"of'}` -> same shape
- Hand-check hints: **weak**. Only `{{` was echoed, and in `description`, which is Markdown by design (`src/models/Todo.ts:30` comment). The title-newline/fake-ID point is from code reading, not from the evidence. Stored, so it is persistent, but no rendering context exists in the server. Steps not executed (read-only review).
</details>
