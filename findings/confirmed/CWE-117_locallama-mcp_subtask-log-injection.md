# Unsanitised Log Write of Caller-Controlled Task Text (Log Injection, Unbounded Growth)

- **Project**: Heratiki/locallama-mcp
- **Commit**: 3af4d831c80b61a15d81b8526db46c4185299714 (v1.31.4)
- **Tools (entry)**: `preemptive_route_task`, `route_task` (any path reaching the code-task coordinator)
- **Class**: CWE-117 (Improper Output Neutralization for Logs); CWE-779 (unbounded log)
- **Status**: CONFIRMED by on-disk inspection of the produced log
- **Severity**: Medium

## Summary
`codeTaskCoordinator.logSubtaskResult()` appends caller-supplied task text and
model output to `subtask_results.log` using an unsanitised template literal,
inside a Markdown code fence, via `appendFileSync`. The task text originates
from the LLM-supplied tool argument. No neutralisation of newlines/control
characters, no fence-escaping, and no size cap (the file is only reset at
startup).

## Affected code
`src/modules/decision-engine/services/codeTaskCoordinator.ts`
```js
const logEntry = `
## Subtask: ${subtask.description}
- **ID**: ${subtask.id}
...
\`\`\`
${result}
\`\`\`
---
`;
fs.appendFileSync(SUBTASK_LOG_PATH, logEntry, 'utf-8');
```
Reached from `src/modules/api-integration/routing/index.ts:1046-1094`.

## Evidence (on disk after ~1.4h fuzzing, see evidence/locallama-subtask_results.log.head)
- 602 KB, no cap
- 644 lines containing NUL bytes
- 6 `## Subtask:` headings split by injected control chars (\x0b \x10 \x13), so
  the record structure is broken; e.g. a heading
  `## Subtask: "task": "Read file ../../../../etc/passwd..."` followed by a raw
  `\x0b\x10ut_length": 50, ...` continuation line.
- ToFu's `check_log_injection` flagged 43 inputs on `preemptive_route_task`,
  5 on `rate_model`.

## Suggested fix
Neutralise control characters (at least `\r\n`, C0 controls) and escape/deny
code-fence sequences before logging; cap the file size / rotate; consider
structured (JSON-lines) logging instead of Markdown assembled from user text.

## NOT claimed
No ANSI terminal-escape sequences were observed in the output, so a
terminal-hijack angle is not asserted.
