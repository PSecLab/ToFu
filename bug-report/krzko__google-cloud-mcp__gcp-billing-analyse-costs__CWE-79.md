# Missing output encoding in `gcp-billing-analyse-costs`: arguments are echoed verbatim into the Markdown report

**Repository:** `krzko/google-cloud-mcp` · **Tool:** `gcp-billing-analyse-costs` · **Tested commit:** `85eeb65`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`gcp-billing-analyse-costs` builds a Markdown report (currently from mock data) and interpolates `billingAccountName`, `startDate`, `endDate` and `projectId` into it without validation or escaping. Any Markdown or HTML in those strings reaches the client as-is, and a `|` in `projectId` breaks the cost table. Impact depends on how the MCP client renders tool output. In a plain-text client it is cosmetic.

## Details
`src/services/billing/tools.ts:744-747` writes the arguments straight into the header:
```ts
        let response = `# Cost Analysis\n\n`;
        response += `**Billing Account:** ${billingAccountName}\n`;
        response += `**Period:** ${startDate} to ${endDate}\n`;
        response += `**Grouped By:** ${groupBy}\n\n`;
```
`projectId` flows into `mockCostData` (`tools.ts:695-705`) and is then written into the table and the trends section:

`src/services/billing/types.ts:325` (`formatCostData`)
```ts
    result += `| ${projectId} | ${serviceId} | ${formattedCost} | ${usage} | ${period} |\n`;
```
`src/services/billing/tools.ts:739`
```ts
          trendsAnalysis += `**${cost.projectId} (${cost.serviceId}):** `;
```
The input schema (`tools.ts:655-679`) only requires these fields to be strings. `serviceId` is handled the same way. The code checks nothing against the `billingAccounts/...` format the description asks for, or against the Google Cloud project ID format.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No Google Cloud credentials are needed for this call, because the tool uses mock data and `projectId` is supplied (authentication is lazy by default, `src/index.ts:131`). Use a throwaway `HOME` so the server's state files do not touch your real config.
2. Build the server as the README describes:
   ```bash
   git clone https://github.com/krzko/google-cloud-mcp && cd google-cloud-mcp
   git checkout 85eeb65
   pnpm install && pnpm build
   ```
3. From the repository root, call the tool with these arguments:
   ```json
   {"billingAccountName": "billingAccounts/<b>tofu-poc</b>", "startDate": "2023-02-01", "endDate": "2023-02-28", "projectId": "project-{{7*7}} | injected-cell", "groupBy": "project"}
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
               result = await session.call_tool("gcp-billing-analyse-costs", {
                   "billingAccountName": "billingAccounts/<b>tofu-poc</b>",
                   "startDate": "2023-02-01",
                   "endDate": "2023-02-28",
                   "projectId": "project-{{7*7}} | injected-cell",
                   "groupBy": "project",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe `**Billing Account:** billingAccounts/<b>tofu-poc</b>` in the text, and table rows where `injected-cell` appears as an extra column.

## Expected behavior
Arguments are validated against their documented formats, or escaped for Markdown before they are interpolated, so they render as literal text.

## Actual behavior
The arguments appear verbatim. From the fuzzing run (input `projectId: 'project-{{{{...{{xyz'`, `billingAccountName: '../../../.. '`):
```
**Billing Account:** ../../../.. 
**Period:** eId": "service-2", "groupBy": "proje to 2023-02-28
...
| project-{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{xyz | compute.googleapis.com | USD 1,250.50 | 100 hours | Invalid Date - 27/02/2023 |
```

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. If the client renders tool output as Markdown or HTML, an attacker who steers the arguments can inject links, images or formatting into what the user sees. An image fetched on render could leak data in its URL. The tool currently returns mock data, so nothing sensitive is reflected besides what the caller supplied.

## Suggested fix
Validate the inputs before use: `billingAccountName` against `^billingAccounts/[A-Z0-9-]+$`, `projectId` against the Google Cloud project ID rules (lowercase letters, digits and hyphens), and the dates against `YYYY-MM-DD`. Reject anything else with an error. Where free text must be echoed, escape Markdown control characters (backslash, backtick, `*`, `_`, `[`, `]`, `<`, `>`, `|`) with a small shared helper used by all the billing formatters.

## Status on the default branch
Still present at `85eeb65` (2025-07-31). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 5 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (token `{{`).
- Campaigns and executions: `corpus-sbx` 2048 exec / 168 success (60 s).
- Evidence (verbatim, trimmed): input `{'billingAccountName': '../../../.. ', 'startDate': 'eId": "service-2", "groupBy": "proje', 'endDate': '2023-02-28', 'projectId': 'project-{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{xyz', 'serviceId': '', 'groupBy': 'project'}`; output starts `# Cost Analysis\n\n**Billing Account:** ../../../.. \n**Period:** eId": "service-2", ...` and contains `| project-{{{{...xyz | compute.googleapis.com | ...`.
- Hand-check hints: weak. ToFu only saw `{{` echoed into a Markdown text block, which is not a template sink here. The `<b>` and `|` payloads in the reproduction are my extrapolation from the code (plain template-string interpolation, no escaping); I did not run them. Whether this matters depends on the client renderer. The tool is a mock implementation. File, if at all, as one low-severity "validate/escape inputs in billing tools" issue together with the `gcp-billing-cost-recommendations`, `gcp-billing-service-breakdown` and `gcp-utils-set-project-id` drafts.
</details>
