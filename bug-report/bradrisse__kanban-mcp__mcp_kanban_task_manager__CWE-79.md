# Missing output encoding in `mcp_kanban_task_manager`: `batch_create` echoes task fields back unescaped

**Repository:** `bradrisse/kanban-mcp` · **Tool:** `mcp_kanban_task_manager` · **Tested commit:** `4aead19`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`mcp_kanban_task_manager` with `action: "batch_create"` creates Planka tasks and returns a JSON summary. For every task that fails, the summary includes the caller's original task object, so `name` and `cardId` come back exactly as sent, including HTML and template markup. The reply is JSON text, so this only matters in a client that renders tool output as HTML or Markdown. Our fuzzer saw `{{` and `<` echoed back.

## Details
`operations/tasks.ts:194-221` (tested commit), returned through `index.ts:611-615` and `index.ts:650-652`:

```ts
            try {
                const result = await createTask(task);
                results.push({ success: true, result });
                successes.push(result);
            } catch (error) {
                const errorMessage = error instanceof Error ? error.message : String(error);
                results.push({ success: false, error: { message: errorMessage } });
                failures.push({
                    index: i,
                    task,
                    error: errorMessage,
                });
            }
        ...
        return { results, successes, failures };
```

The handler serializes this with `JSON.stringify(result)` and returns it as a text content item. `JSON.stringify` escapes quotes and control characters but leaves `<`, `>` and `{` as they are. The task fields are only typed as strings by the zod schema (`index.ts:580-589`); there is no format check.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No Planka instance is needed to see the echo: without credentials every task fails and is echoed in `failures`.
2. Install and build: `git clone https://github.com/bradrisse/kanban-mcp.git && cd kanban-mcp && npm install && npm run build`, then the server is `node dist/index.js`.
3. Call the tool with:

   ```json
   {"action": "batch_create", "tasks": [{"cardId": "1", "name": "<b>TOFU-POC</b>{{7*7}}"}]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("mcp_kanban_task_manager", {"action": "batch_create", "tasks": [{"cardId": "1", "name": "<b>TOFU-POC</b>{{7*7}}"}]})
               print(result.content[0].text)

   asyncio.run(main())
   ```
4. Observe that `failures[0].task.name` in the returned JSON is `<b>TOFU-POC</b>{{7*7}}`, unchanged.

## Expected behavior
Either the tool does not echo caller input back in its result (an index and error message are enough), or clients treat the JSON as text. Task names are stored as plain text in Planka, so escaping is mainly the renderer's job.

## Actual behavior
Caller fields are returned verbatim inside the JSON. From the fuzzing run (trimmed):

```
{"results":[{"success":false,"error":{"message":"Failed to create task: Failed to get authentication token: PLANKA_AGENT_EMAIL and PLANKA_AGENT_PASSWORD environment variables are required"}}, ...],
 "successes":[],
 "failures":[{"index":0,"task":{"cardId":"{{{{{{","name":"{{{{{{","position":8.671225709335876e+307}, ...}]}
```

## Impact
The LLM chooses the arguments, and prompt injection can steer it. The value is echoed back to the same client that sent it, inside a JSON string. An attacker gains nothing unless the MCP client renders tool output as HTML. Very low severity.

## Suggested fix
Drop the `task` object from `failures` or limit it to `index` and the error message. If the input must be echoed, keep it as JSON and document that it is untrusted text. Validating `cardId` against Planka's ID format would also stop malformed IDs from reaching the API path in `createTask` (`operations/tasks.ts:123-124`).

## Status on the default branch
Still present at `4aead19` (2025-03-25). The tested commit is the current default branch head.

## Prior reports
- #10 "Fix: Planka v2 (2.x) API route compatibility" (PR, open 2026-06-20): changes `createTask` to post to `/api/task-lists/:taskListId/tasks`. Its body says nothing about the `failures` echo in `batch_create` or about output encoding. Not related to this bug; line numbers here would shift if it merges.
- Documentation: none relevant. README.md, wiki/*.md and tool-reduction-plan.md describe `batch_create` but say nothing about how results are rendered or about untrusted input.

Searched all 4 issues and 6 pull requests (fetched 2026-10-01).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); `check_reflected_output` (token `{{`) on all three, plus `check_invalid_json` on the first.
- Campaigns and executions: repo24-b 67072 exec / 12729 ok and 69120 exec / 9509 ok (4200 s budgets).
- Evidence (verbatim, trimmed):
  - `{'action': 'batch_create', 'id': '\x04...+{{{{...', 'cardId': '', 'name': '{', 'isCompleted': True, 'position': 8.671225709335876e+307, 'tasks': [{'cardId': '{{{{...{{{<\x08\x01\x00\x00\x00\x00', 'name': '', 'position': 0.0}, {'cardId': '', 'name': '', 'position': 0.0}]}` -> `..."failures":[{"index":0,"task":{"cardId":"{{{{...{{{<\\b\\u0001\\u0000\\u0000\\u0000\\u0000","name":"","position":65535},...`
  - `{'action': 'batch_create', ..., 'tasks': [{'cardId': '{{{{{{', 'name': '{{{{{{', 'position': 8.671225709335876e+307}, ...]}` -> `"task":{"cardId":"{{{{{{","name":"{{{{{{","position":8.671225709335876e+307}`
- Hand-check hints: weak, likely low or no severity. The echo is inside a JSON string in plain text MCP output, back to the caller who sent it; only `{{` and `<` were observed. Every evidence call failed at authentication (no Planka credentials), so no task was created. Side note: `if (!task.position)` in `batchCreateTasks` treats `0` as missing, so an explicit position of 0 becomes 65535 * (i + 1) (functional bug). Probably not worth filing on its own.
</details>
