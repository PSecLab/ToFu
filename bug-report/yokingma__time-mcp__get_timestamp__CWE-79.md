# Missing output encoding in `get_timestamp`: unparseable `time` is echoed raw and reported as `NaN ms`

**Repository:** `yokingma/time-mcp` · **Tool:** `get_timestamp` · **Tested commit:** `5bc003e`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_timestamp` converts a `time` string to a Unix timestamp in milliseconds. It does not check that the string parses. For any input it returns a success message that repeats `time` exactly as given, followed by the result, which is `NaN` when parsing fails. Markup in `time` therefore comes back unchanged, and the caller gets `NaN` instead of an error. The reply is plain text, so the encoding issue is low severity; the missing validation is the more useful fix.

## Details
`src/index.ts:43-45` and `src/index.ts:149-161` (tested commit):

```ts
function getTimestamp(time?: string) {
  return time ? dayjs.utc(time).valueOf() : dayjs().valueOf();
}
// ...
  (args) => {
    const result = getTimestamp(args.time);
    return {
      content: [
        {
          type: 'text' as const,
          text: args.time
            ? `The timestamp of ${args.time} (parsed as UTC) is ${result} ms.`
            : `The current timestamp is ${result} ms.`,
```

The schema (`src/tools.ts:47-49`) is `z.string()` with the format only in the description (`YYYY-MM-DD HH:mm:ss.SSS`). There is no `dayjs(...).isValid()` check, so invalid input produces `NaN`, and `args.time` is interpolated into the reply at line 156 with no escaping. `convert_time` echoes `sourceTimezone` and `targetTimezone` the same way at line 177.

## Steps to reproduce
1. Prerequisites: Node.js 20+ and npm. No accounts or env vars.
2. Build from source at the tested commit (the README's `npx -y time-mcp` runs the published package instead):

   ```bash
   git clone https://github.com/yokingma/time-mcp.git
   cd time-mcp && git checkout 5bc003e
   npm install && npm run build
   ```
3. Call the tool from the repository root with:

   ```json
   {"time": "2024-06-01 12:00:00.000<b>tofu-poc</b>"}
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
               result = await session.call_tool("get_timestamp", {"time": "2024-06-01 12:00:00.000<b>tofu-poc</b>"})
               print(result)

   asyncio.run(main())
   ```
4. Observe a non-error reply that contains `<b>tofu-poc</b>` unchanged and ends in `is NaN ms.`

## Expected behavior
An unparseable `time` is rejected with an error result (`isError: true`) and a fixed message such as "Invalid time, expected YYYY-MM-DD HH:mm:ss.SSS", without echoing the raw input.

## Actual behavior
From the fuzzing run:

```
input:  {"time": "2024-06-01 12:00:00.000<script>alert(1)</script>"}
output: The timestamp of 2024-06-01 12:00:00.000<script>alert(1)</script> (parsed as UTC) is NaN ms.
```

## Impact
The LLM chooses `time`, and prompt injection can steer it. The echoed text goes back to the same LLM and user. In a client that renders tool output as HTML or Markdown it could inject markup into the chat view; in a plain-text client it has no effect. Separately, returning `NaN ms` as a success can mislead the model into using a bad value. Low severity.

## Suggested fix
- In the `get_timestamp` handler, parse once with `const d = dayjs.utc(args.time)`, and if `!d.isValid()` return `{ isError: true, content: [{ type: 'text', text: 'Invalid time, expected YYYY-MM-DD HH:mm:ss.SSS' }] }`.
- For valid input, echo the normalized value (for example `d.toISOString()`) rather than the raw string.
- Apply the same validation to the other date arguments (`relative_time`, `days_in_month`, `get_week_year`, `convert_time`).

## Status on the default branch
Still present at `5bc003e` (2026-01-31). The default branch head is the tested commit.

## Prior reports
- No issue or PR reports the unvalidated `time` or the raw echo. Searched all 5 issues and 6 pull requests (fetched 2026-10-01).
- #3 "Fix get_timestamp" (PR, closed 2025-07-08, fixes #2) and #5 "fix: get_timestamp uses current time if no arg" (PR, closed 2025-08-11, fixes #4) changed this tool's time-zone handling and default. Neither adds an `isValid()` check or stops echoing the input.
- #8 "Fix for Issues 7 (https://github.com/yokingma/time-mcp/issues/7)" (PR, closed 2026-01-31) reworked `convertTime` "to fix time difference calculation and improve error handling". It concerns `convert_time` only; `get_timestamp` is unchanged.
- #10 "FastMCP JSON format error" (issue, open 2026-03-29) already reports the `Starting Time MCP server...` stdout line mentioned in the internal notes. Not this bug.
- Documentation: CLAUDE.md says the server "Uses Zod for automatic runtime validation (no manual type guards needed)", but the `time` schema is a plain `z.string()`, so the date format is not validated. README.md only lists "`get_timestamp`: Get timestamp for the time". No SECURITY.md or `docs/`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79), `check_reflected_output` only.
- Campaigns and executions: corpus-sbx 2560 exec / 2560 ok (60 s).
- Evidence (verbatim, trimmed):
  - `{'time': '2024-06-01 12:00:00.000<script>alert(1)</script>'}` -> `The timestamp of 2024-06-01 12:00:00.000<script>alert(1)</script> (parsed as UTC) is NaN ms.`
  - `{'time': '{{'}` -> `The timestamp of {{ (parsed as UTC) is NaN ms.`
  - `{'time': '\x1a{{\x7f\x7f\x7f\x7f\x7f'}` -> `The timestamp of \x1a{{\x7f\x7f\x7f\x7f\x7f (parsed as UTC) is NaN ms.`
- Hand-check hints: weak. Input is echoed into plain MCP text; there is no HTML/Markdown sink in the server. The better framing for the maintainer is input validation (invalid time returns `NaN` as a success), with the echo as a side point. The `<b>tofu-poc</b>` reproduction is derived from code and the evidence shape and was not run. I did not check whether the published npm package matches commit `5bc003e`. Aside, not flagged by ToFu: `src/index.ts:206` writes `Starting Time MCP server...` to stdout, which is the stdio JSON-RPC channel; the fuzzer's client tolerated it (2560/2560 ok).
</details>
