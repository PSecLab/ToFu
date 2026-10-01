# Missing output encoding in `manage_state`: `session_id` is echoed raw into the tool reply

**Repository:** `MushroomFleet/DeepLucid3D-MCP` · **Tool:** `manage_state` · **Tested commit:** `6a8f12d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`manage_state` controls session state for the server. On the `reset` and `status` actions it puts the caller's `session_id` into the reply text with no format check and no encoding. `session_id` is an optional free string, so any value is accepted, and `reset` echoes it even when no such session exists. This only matters if an MCP client renders tool output as HTML or Markdown. Low severity.

## Details
`src/index.ts:547-566` at the tested commit (`build/index.js` is the compiled form):

```ts
case "reset":
  if (sessionId) {
    stateManager.clearSession(sessionId);
    resultText = `Session '${sessionId}' has been reset`;
  } else {
    stateManager.clearAllSessions();
    resultText = "All sessions have been reset";
  }
  break;

case "status":
  ...
  if (sessionId) {
    const hasSession = stateManager.hasSession(sessionId);
    resultText += `\nSession '${sessionId}': ${hasSession ? "exists" : "not found"}`;
  }
  break;
```

`session_id` is a plain optional string in the schema (`src/index.ts:410-413`), cast at line 529, with no validation. `reset` reports it regardless of whether the session existed.

## Steps to reproduce
1. Prerequisites: Node.js 18+. No credentials or network access needed.
2. Install and build as the README describes: `git clone <repo> && cd DeepLucid3D-MCP && npm install && npm run build`. The server is `node build/index.js`.
3. Call the tool with:

   ```json
   {"action": "reset", "session_id": "<img src=x onerror=alert(1)>"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("manage_state",
                   {"action": "reset", "session_id": "<img src=x onerror=alert(1)>"})
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the reply text `Session '<img src=x onerror=alert(1)>' has been reset`, with the markup unchanged.

## Expected behavior
`session_id` is validated to a known-safe shape (for example a UUID), or is escaped before being placed in the reply.

## Actual behavior
The value is returned verbatim. From the fuzzing run:

```
Session '"?{{^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^' has been reset
```

and on `status`:

```
State management is currently disabled
Number of active sessions: 0
Session '"?{{': not found
```

## Impact
In MCP the LLM chooses tool arguments, and prompt injection in content the model reads can steer them. The reply returns to the same client. In a client that renders tool output as HTML or Markdown, injected markup in `session_id` would render in the user's view. In a plain-text client there is no effect. The tool reads no files and makes no requests; `reset` with a non-existent id has no state effect either.

## Suggested fix
Validate `session_id` against an expected format and reject anything else, or escape HTML/Markdown special characters before interpolating it into `resultText`.

## Status on the default branch
Still present at `6a8f12d` (2026-04-07). This is the tested commit and the current default-branch head; the handler is unchanged.

## Prior reports
None found. Searched all 1 issues and 2 pull requests (fetched 2026-10-01) and the README / docs (`README.md`, `DeepLucid3D.md` and the three analysis notes) on the default branch. The README shows `session_id` only as an optional value (`"session_id": "optional-session-id"`) and says nothing about its format or escaping.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116); `check_reflected_output` only.
- Campaigns and executions: `corpus-sbx`, 3,584 executions, 3,501 successful, 60 s budget.
- Evidence (verbatim, trimmed): `{'action': 'status', 'session_id': '"?{{'}` -> `...Session '"?{{': not found`; `{'action': 'reset', 'session_id': '"?{{^^^...'}` -> `Session '"?{{^^^...' has been reset`. Token matched: `{{`.
- Hand-check hints: weak. Clean, simple reflection of a caller string into an MCP `text` reply; no `<`/`>` seen in evidence but the code does no encoding, so markup would pass through. Exploitable only if the client renders tool output as HTML/Markdown. Low severity.
</details>
