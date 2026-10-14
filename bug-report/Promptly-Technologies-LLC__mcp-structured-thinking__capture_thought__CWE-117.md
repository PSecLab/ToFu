# Log injection check in `capture_thought`: CR/LF in `thought` is accepted unneutralized (no log sink found at the tested commit)

**Repository:** `Promptly-Technologies-LLC/mcp-structured-thinking` · **Tool:** `capture_thought` · **Tested commit:** `d00143e`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`capture_thought` stores a thought and returns an analysis of it. A fuzzer flagged that a `thought` containing a newline followed by a fake log line (`\nCRITICAL: system failure`) is accepted and stored without any CR/LF handling. I traced the code and found no place where the `thought` text is written to a log at this commit, so this is a hardening note rather than a working log injection. I am filing it so the gap is known before logging is added.

## Details
The handler copies the arguments into `inputData` with no checks on string content, `index.ts:79-96`:

```ts
const captureParams = params.arguments as z.infer<typeof captureThoughtSchema>;
const inputData = {
  thought: captureParams.thought,
  ...
  branchId: captureParams.branch_id,
  ...
  tags: captureParams.tags || []
};
return thinkingServer.captureThought(inputData);
```

`validateThoughtData` (`src/SequentialThinkingServer.ts:170-201`) checks only the numeric fields and the score range. The zod schema in `src/tools.ts:6-19` is used for the listed `inputSchema` but the handler does not call `.parse()` on the arguments. The only logger on this path is `handleError` (`src/SequentialThinkingServer.ts:540-541`):

```ts
private handleError(e: unknown): any {
  console.error(`Error: ${e instanceof Error ? e.message : String(e)}`);
```

The error messages that reach it on this path are fixed strings (for example "Thought number must be positive"). The `thought` text is not written to stderr, to `server.log`, or to any other file. `branch_id` and `tags` are returned inside `JSON.stringify` output, which escapes CR/LF.

## Steps to reproduce
1. Prerequisites: Node.js and npm. No accounts or env vars.
2. Start the server as the README describes: `npx -y structured-thinking` (or from a checkout: `npm install && npm run build && node dist/index.js`).
3. Call the tool with these arguments:

   ```json
   {"thought": "Normal thought\r\nFAKE-LOG-ENTRY", "thought_number": 2, "total_thoughts": 3, "next_thought_needed": false, "stage": "Synthesis", "branch_id": "tofu-poc", "tags": ["poc"]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "structured-thinking"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("capture_thought", {
                   "thought": "Normal thought\r\nFAKE-LOG-ENTRY",
                   "thought_number": 2,
                   "total_thoughts": 3,
                   "next_thought_needed": False,
                   "stage": "Synthesis",
                   "branch_id": "tofu-poc",
                   "tags": ["poc"],
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe: the call succeeds and the thought is stored with the CR/LF intact. Check the server's stderr (or the MCP client's server log): at this commit no line containing `FAKE-LOG-ENTRY` appears.

## Expected behavior
Free-text fields that may later be logged are stored and logged with CR/LF neutralized (escaped or stripped).

## Actual behavior
The `thought` is accepted and stored as-is. The tool returns a normal analysis. Excerpt from the fuzzing run (input `'Normal thought; injected log\nCRITICAL: system failure'`):

```
"currentThought": { "thoughtNumber": 2, "totalThoughts": 3, "nextThoughtNeeded": false,
  "stage": "Synthesis", ... "branch": "log_injection" }
```

The thought text itself does not appear in the output or in any log.

## Impact
Low at this commit. Tool arguments are chosen by the LLM and can be steered by prompt injection, so the text is attacker-influenced. Today nothing writes it to a log, so there is no forged log line. The risk appears only if a later change logs thoughts (for example a debug `console.error` of the input, or a persisted thought log).

## Suggested fix
If thoughts are ever logged, escape CR/LF (`text.replace(/\r/g, "\\r").replace(/\n/g, "\\n")`) or log them through `JSON.stringify`. Validating the arguments with the existing `captureThoughtSchema.parse()` in `index.ts` would also enforce the declared types.

## Status on the default branch
Still present at `d00143e` (2025-03-22). The default branch has no newer commits than the tested one. No log sink for `thought` exists there either.

## Prior reports
None found. Searched all 5 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch. The open issues are feature ideas (#1-#4) and a Glama Dockerfile request (#5); the pull requests add badges. #3 "Store the data in a file or database that can be accessed by the client" (issue, open) proposes persisting thoughts, which would create the kind of sink this draft is about, but it does not mention neutralization.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection; `check_log_injection` only.
- Campaigns and executions: corpus-sbx 2560 calls / 1088 succeeded; e2-0922 512 / 188.
- Evidence (verbatim, trimmed):
  - input `{'thought': 'Normal thought; injected log\nCRITICAL: system failure', 'thought_number': 2, 'total_thoughts': 3, 'next_thought_needed': False, 'stage': 'Synthesis', ..., 'branch_id': 'log_injection', ..., 'tags': ['log', 'injection']}` → normal `thoughtAnalysis` JSON, `isError` absent.
  - Analysis for all three samples: `Silent Bug Alert: Sanitizers ['check_log_injection'] flagged this input as malicious, but the target tool executed successfully without raising any exception.`
  - The other two samples contain `\x0b`, `\x10`, `\n` inside a JSON-like `thought` string; same result.
- Hand-check hints: weak, likely a false positive. The alert is an input-pattern match ("flagged this input"), not an observed log write. I found no logger that receives `thought`, `branch_id` or `tags`: the only `console.error` calls print fixed messages or `e.message` from fixed-string errors. `server.log` in the repo is empty and nothing writes to it. Recommend not filing unless the maintainer wants a hardening note.
</details>
