# Missing output encoding in `gcp-billing-service-breakdown`: `billingAccountName` and `projectId` are echoed verbatim into the Markdown report

**Repository:** `krzko/google-cloud-mcp` · **Tool:** `gcp-billing-service-breakdown` · **Tested commit:** `85eeb65`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`gcp-billing-service-breakdown` builds a Markdown report (currently from demonstration data) and interpolates `billingAccountName` and `projectId` into the header and into every table row without validation or escaping. Any Markdown or HTML in those strings reaches the client as-is, and a `|` in `projectId` breaks the tables. Impact depends on how the MCP client renders tool output. In a plain-text client it is cosmetic.

## Details
`src/services/billing/tools.ts:1159-1162`:
```ts
        let response = `# Service Cost Breakdown\n\n`;
        response += `**Billing Account:** ${billingAccountName}\n`;
        response += `**Project:** ${actualProjectId || "All projects"}\n`;
        response += `**Time Range:** ${timeRange}\n`;
```
`actualProjectId` is the caller's `projectId` (`tools.ts:1083-1086`). It is copied into each demo row and written into the table:

`src/services/billing/tools.ts:1195,1207`
```ts
            const project = costData.projectId || "Unknown";
            ...
            response += `| ${project} | ${skuId} | ${cost} | ${usage} | ${labels} |\n`;
```
The input schema (`tools.ts:1064-1078`) only requires these fields to be strings. The code checks neither against the `billingAccounts/...` format the description asks for or the Google Cloud project ID format.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No Google Cloud credentials are needed for this call, because the tool uses demo data and `projectId` is supplied (authentication is lazy by default, `src/index.ts:131`). Use a throwaway `HOME` so the server's state files do not touch your real config.
2. Build the server as the README describes:
   ```bash
   git clone https://github.com/krzko/google-cloud-mcp && cd google-cloud-mcp
   git checkout 85eeb65
   pnpm install && pnpm build
   ```
3. From the repository root, call the tool with these arguments:
   ```json
   {"billingAccountName": "billingAccounts/<b>tofu-poc</b>", "projectId": "{{7*7}} | injected-cell", "timeRange": "1y"}
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
               result = await session.call_tool("gcp-billing-service-breakdown", {
                   "billingAccountName": "billingAccounts/<b>tofu-poc</b>",
                   "projectId": "{{7*7}} | injected-cell",
                   "timeRange": "1y",
               })
               print(result)

   asyncio.run(main())
   ```
4. Observe `**Billing Account:** billingAccounts/<b>tofu-poc</b>` in the header and `| {{7*7}} | injected-cell | ...` rows where the injected text forms an extra table column.

## Expected behavior
Arguments are validated against their documented formats, or escaped for Markdown before they are interpolated, so they render as literal text.

## Actual behavior
The arguments appear verbatim. From the fuzzing run (input `billingAccountName: '筻筻筻筻筻筻'`, `projectId: '{{{{{{'`):
```
# Service Cost Breakdown

**Billing Account:** 筻筻筻筻筻筻
**Project:** {{{{{{
**Time Range:** 1y
...
| {{{{{{ | CP-COMPUTEENGINE-VMIMAGE-N1-STANDARD-1 | USD 1,847.25 | 744 hours | environment:production, ... |
```

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. If the client renders tool output as Markdown or HTML, an attacker who steers the arguments can inject links, images or formatting into what the user sees. An image fetched on render could leak data in its URL. The tool currently returns demo data, so nothing sensitive is reflected besides what the caller supplied.

## Suggested fix
Validate the inputs before use: `billingAccountName` against `^billingAccounts/[A-Z0-9-]+$` and `projectId` against the Google Cloud project ID rules (lowercase letters, digits and hyphens). Reject anything else with an error. Where free text must be echoed, escape Markdown control characters (backslash, backtick, `*`, `_`, `[`, `]`, `<`, `>`, `|`) with a small shared helper used by all the billing formatters.

## Status on the default branch
Still present at `85eeb65` (2025-07-31). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 5 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (token `{{`); `check_invalid_json` also fired on the same input (input-side heuristic, not a finding about the tool).
- Campaigns and executions: `corpus-sbx` 2048 exec / 571 success (60 s).
- Evidence (verbatim, trimmed): input `{'billingAccountName': '筻筻筻筻筻筻', 'projectId': '{{{{{{', 'timeRange': '1y'}`; output `# Service Cost Breakdown\n\n**Billing Account:** 筻筻筻筻筻筻\n**Project:** {{{{{{\n**Time Range:** 1y\n...| {{{{{{ | CP-COMPUTEENGINE-VMIMAGE-N1-STANDARD-1 | ...`.
- Hand-check hints: weak. ToFu only saw `{{` echoed into a Markdown text block, which is not a template sink here. The `<b>` and `|` payloads are my extrapolation from the code (plain template-string interpolation, no escaping); I did not run them. Whether this matters depends on the client renderer. The tool returns demo data. File, if at all, as one low-severity issue together with the `gcp-billing-analyse-costs`, `gcp-billing-cost-recommendations` and `gcp-utils-set-project-id` drafts.
</details>
