# `edit-rule-sequence`: log-injection flag on `ruleName` could not be confirmed (no log sink); tool is also broken

**Repository:** `ryaker/outlook-mcp` · **Tool:** `edit-rule-sequence` · **Tested commit:** `95d6ff2`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
A fuzzer flagged `edit-rule-sequence` for log injection because `ruleName` accepted a value containing a
newline. On reading the code, `ruleName` is not written to any logger or log file, so the log-injection
report does not hold as-is. The same evidence does expose a separate, genuine bug: the handler references
`ensureAuthenticated` and `callGraphAPI` without importing them, so the tool throws a `ReferenceError` on
every call that passes validation.

## Details
`handleEditRuleSequence` reads `ruleName` and `sequence`, validates them, then calls `ensureAuthenticated()`
and `callGraphAPI(...)` (`rules/index.js:15`):

```js
async function handleEditRuleSequence(args) {
  const { ruleName, sequence } = args;
  if (!ruleName) { return /* "Rule name is required." */ }
  if (!sequence || isNaN(sequence) || sequence < 1) { return /* "A positive sequence number..." */ }
  const accessToken = await ensureAuthenticated();        // rules/index.js:38 - not imported
  const rules = await getInboxRules(accessToken);
  const rule = rules.find(r => r.displayName === ruleName);
  // ...
}
```

`rules/index.js` imports only `./list` and `./create` (lines 4-8); it never requires `ensureAuthenticated`
(from `../auth`) or `callGraphAPI` (from `../utils/graph-api`), unlike sibling modules such as
`onedrive/upload.js`. `ruleName` is used only in a `.find()` comparison and in strings returned in the MCP
response; it is never passed to `console.*` or any file logger. The server's request handler logs the tool
name only (`index.js:89: console.error(\`TOOL CALL: ${name}\`)`), not the arguments. So there is no path by
which CR/LF in `ruleName` reaches a log.

## Steps to reproduce
1. Prerequisites: Node 18+. `npm install`. No Microsoft account is needed to see the behavior below.
2. Start the server: `node index.js`.
3. Call the tool. Arguments as JSON: `{"ruleName": "test\r\nFAKE-LOG-ENTRY", "sequence": 42}`
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "edit-rule-sequence",
                   {"ruleName": "test\r\nFAKE-LOG-ENTRY", "sequence": 42})
               print(result)

   asyncio.run(main())
   ```
4. Observe the server's stderr. It prints `TOOL CALL: edit-rule-sequence` only; the `ruleName` value does
   not appear in any log line. The tool returns an error, not a forged log entry.

## Expected behavior
Any caller input written to a log should have CR/LF stripped or encoded. (Separately: the handler should
import its dependencies.)

## Actual behavior
The response is `{'content': [{'type': 'text', 'text': 'Error updating rule sequence: ensureAuthenticated is
not defined'}]}` - a `ReferenceError`, because `ensureAuthenticated` is not imported. No log line is emitted
from the `ruleName` value.

## Impact
As written, the log-injection concern has no sink to exploit: `ruleName` is not logged. The real defect this
input surfaces is a functional one - `edit-rule-sequence` is broken and cannot change a rule's sequence,
because its Graph-API dependencies are not imported.

## Suggested fix
1. Import the missing functions in `rules/index.js`:
   `const { ensureAuthenticated } = require('../auth');` and
   `const { callGraphAPI } = require('../utils/graph-api');`.
2. If any caller-supplied field (here `ruleName`) is later added to a log line, neutralize CR/LF first
   (e.g. `String(v).replace(/[\r\n]/g, ' ')`).

## Status on the default branch
Still present at `95d6ff2` (2026-03-30). The current default branch head is the same commit that was tested;
`rules/index.js` still omits the imports and still does not log `ruleName`.

## Prior reports
- #55 "feat(rules): add delete-rule tool and fix edit-rule-sequence imports" (PR, open 2026-04-11): reports the same `ReferenceError: ensureAuthenticated is not defined` in `rules/index.js` and adds the missing imports. Not merged: `rules/index.js` on the default branch still lacks them. It does not touch logging.
- #54 "feat: add delete-rule tool" (PR, open 2026-04-07): adds `delete-rule` following the `edit-rule-sequence` pattern; the body does not say whether it adds the missing imports.
- #53 "Use of a Logging Framework with envar controlled configuration" (issue, open 2026-04-05): asks for a logging framework with configurable format and level. Not about neutralizing caller input in logs.
- #42 "Security hardening: token logging, OAuth CSRF, XSS, file permissions" (issue, closed 2026-03-29) and #43 (PR of the same title, closed 2026-03-08): removed token contents from debug logs. About secrets in logs, not CR/LF injection, and not about rules.
- Documentation: README.md's tool table lists `list-rules` and `create-rule` but not `edit-rule-sequence`; no docs say anything about logging tool arguments.

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: the missing-import `ReferenceError` (the real bug here) is already reported and fixed in open PR #55, not merged as of 2026-10-01. No prior report of the log-injection claim.
- ToFu class / sanitizers: log-injection (CWE-117); `check_log_injection` fired.
- Campaigns and executions: corpus-sbx (2,560 / 2,558, 60s) and e2-0922 (512 / 510, 60s).
- Evidence (verbatim, trimmed): input `{'ruleName': 'test\nCRLFInjection', 'sequence': 42}` -> output
  `Error updating rule sequence: ensureAuthenticated is not defined`. Two other rows had `sequence: 0.0` and
  were rejected at the validation check ("A positive sequence number is required.") before any further code.
- Hand-check hints: WEAK / likely false positive for CWE-117. No logger receives `ruleName`; the server logs
  only the tool name (index.js:89). The sanitizer fired on the newline in the input, not on an observed log
  write. The one solid finding is the un-imported `ensureAuthenticated`/`callGraphAPI` ReferenceError, which
  is a correctness bug, not a security issue. Recommend filing as a bug report (broken tool) rather than a
  log-injection advisory, or dropping it.
</details>
