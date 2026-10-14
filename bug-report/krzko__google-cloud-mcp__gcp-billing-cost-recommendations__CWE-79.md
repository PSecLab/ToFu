# Missing output encoding in `gcp-billing-cost-recommendations`: `billingAccountName` and `projectId` are echoed verbatim into the Markdown report

**Repository:** `krzko/google-cloud-mcp` · **Tool:** `gcp-billing-cost-recommendations` · **Tested commit:** `85eeb65`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`gcp-billing-cost-recommendations` builds a Markdown report (currently from mock recommendations) and interpolates `billingAccountName` and `projectId` into it without validation or escaping. Any Markdown or HTML in those strings reaches the client as-is. Impact depends on how the MCP client renders tool output. In a plain-text client it is cosmetic.

## Details
`src/services/billing/tools.ts:1020-1023`:
```ts
        let response = `# Cost Optimisation Recommendations\n\n`;
        response += `**Billing Account:** ${billingAccountName}\n`;
        response += `**Minimum Savings:** ${formatCurrency(minSavingsAmount)}\n`;
        response += `**Priority Filter:** ${priority}\n\n`;
```
`projectId` is copied into each mock recommendation (`tools.ts:956-970`) and printed by `formatCostRecommendations`:

`src/services/billing/types.ts:410`
```ts
    result += `**Project:** ${rec.projectId}\n`;
```
The input schema (`tools.ts:933-952`) only requires `billingAccountName` and `projectId` to be strings. The code checks neither against the `billingAccounts/...` format the description asks for or the Google Cloud project ID format.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No Google Cloud credentials are needed for this call, because the tool uses mock data and `projectId` is supplied (authentication is lazy by default, `src/index.ts:131`). Use a throwaway `HOME` so the server's state files do not touch your real config.
2. Build the server as the README describes:
   ```bash
   git clone https://github.com/krzko/google-cloud-mcp && cd google-cloud-mcp
   git checkout 85eeb65
   pnpm install && pnpm build
   ```
3. From the repository root, call the tool with these arguments (`priority: "all"` so the mock recommendations, and with them `projectId`, are printed):
   ```json
   {"billingAccountName": "billingAccounts/<b>tofu-poc</b>{{7*7}}", "projectId": "<i>tofu-poc</i>", "minSavingsAmount": 0, "priority": "all"}
   ```

   ```python
   import asyncio
   import os
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       os.makedirs("/tmp/tofu-gcp-home", exist_ok=True)
       server = StdioServerParameters(
           command="node",
           args=["dist/index.js"],
           env={"HOME": "/tmp/tofu-gcp-home", "PATH": os.environ["PATH"]},
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("gcp-billing-cost-recommendations", {
                   "billingAccountName": "billingAccounts/<b>tofu-poc</b>{{7*7}}",
                   "projectId": "<i>tofu-poc</i>",
                   "minSavingsAmount": 0,
                   "priority": "all",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe `**Billing Account:** billingAccounts/<b>tofu-poc</b>{{7*7}}` and `**Project:** <i>tofu-poc</i>` in the text.

## Expected behavior
Arguments are validated against their documented formats, or escaped for Markdown before they are interpolated, so they render as literal text.

## Actual behavior
The arguments appear verbatim. From the fuzzing run:
```
# Cost Optimisation Recommendations

**Billing Account:** "billingAc{{{{{{{{{{{countName"5 "../../../../etc/passwd./../etjed", "projectId": "test-pronSa*vinAccountName": ".gsAmount": 09,
**Minimum Savings:** USD 0.00
**Priority Filter:** low
```
Other fuzzed inputs also passed raw control characters (`\x1b`, `\x0b`, `\x7f`) through to the output unchanged.

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. If the client renders tool output as Markdown or HTML, an attacker who steers the arguments can inject links, images or formatting into what the user sees. An image fetched on render could leak data in its URL. Raw ANSI escape bytes (`\x1b`) could also alter terminal output in clients that print tool results to a terminal. The tool currently returns mock data, so nothing sensitive is reflected besides what the caller supplied.

## Suggested fix
Validate the inputs before use: `billingAccountName` against `^billingAccounts/[A-Z0-9-]+$` and `projectId` against the Google Cloud project ID rules (lowercase letters, digits and hyphens). Reject anything else with an error. Where free text must be echoed, escape Markdown control characters (backslash, backtick, `*`, `_`, `[`, `]`, `<`, `>`, `|`) and strip C0 control characters with a small shared helper used by all the billing formatters.

## Status on the default branch
Still present at `85eeb65` (2025-07-31). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 5 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (token `{{`); `check_invalid_json` also fired (input-side heuristic, not a finding about the tool).
- Campaigns and executions: `corpus-sbx` 2048 exec / 960 success (60 s).
- Evidence (verbatim, trimmed): input `{'billingAccountName': '"billingAc{{{{{{{{{{{countName"5 "../../../../etc/passwd./../etjed", "projectId": "test-pronSa*vinAccountName": ".gsAmount": 09,', 'projectId': '\\\\win.ini": "a', 'minSavingsAmount': 0.0, 'priority': 'low'}`; output `# Cost Optimisation Recommendations\n\n**Billing Account:** "billingAc{{{{{{{{{{{countName"5 "../../../../etc/passwd./../etjed", "projectId": "test-pronSa*vinAccountName": ".gsAmount": 09,\n**Minimum Savings:** USD\xa00.00\n**Priority Filter:** low\n...`, ending in `No cost optimisation recommendations available.` (so `projectId` was not printed in that run). Two more evidence inputs carried raw bytes (`\x1b\x0b\x15\x1a\x1b]S`, `\x7f`) in `billingAccountName`; they were echoed unchanged.
- Hand-check hints: weak. ToFu only saw `{{` echoed into a Markdown text block, which is not a template sink here. The `<b>`/`<i>` payloads and the `**Project:**` echo with `priority: "all"` are my reading of the code; I did not run them. Whether this matters depends on the client renderer. The tool is a mock implementation. The `../../etc/passwd` text in the evidence is never used as a path. File, if at all, as one low-severity issue together with the `gcp-billing-analyse-costs`, `gcp-billing-service-breakdown` and `gcp-utils-set-project-id` drafts.
</details>
