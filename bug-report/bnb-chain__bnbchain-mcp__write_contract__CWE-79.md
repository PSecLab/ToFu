# Missing validation and output encoding in `write_contract`: the confirmation preview echoes unvalidated `contractAddress` and `functionName` text

**Repository:** `bnb-chain/bnbchain-mcp` · **Tool:** `write_contract` · **Tested commit:** `a133675`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
By default `write_contract` does not send a transaction. It returns a preview of the call plus a `confirmToken` that the user passes to `confirm_transfer`. The preview copies `contractAddress`, `functionName`, `args` and `network` from the caller without any validation, so free text, markup or template syntax comes back unescaped in the preview, and a confirm token is issued for it. The preview is the step the user is meant to review before money moves, so it should show only validated values.

## Details
`src/evm/modules/contracts/tools.ts:134-208` at `a133675`:

```ts
      contractAddress: z
        .string()
        .describe("The address of the smart contract to interact with"),
      ...
      functionName: z
        .string()
        .describe("The name of the function to call on the contract"),
      ...
        const { token: confirmToken, expiresAt } = createPendingIntent({
          type: "write_contract",
          params: { contractAddress, abi: parsedAbi, functionName, args },
          network
        })
        return mcpToolRes.success({
          preview: { contractAddress, functionName, args, network },
```

`contractAddress` is never checked with `isAddress`, `functionName` is never checked against the supplied ABI, and `network` (`requiredNetworkParam`) accepts an empty string. `mcpToolRes.success` (`src/utils/helper.ts:59-67`) serialises the preview with `JSON.stringify`, which escapes quotes and control characters but leaves `<`, `>` and `{{` as they are.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and Bun 1.2.10 or later. No funded key or network access is needed, because the preview path sends nothing. Pass `privateKey: ""` when `PRIVATE_KEY` is not set in the environment, since the schema requires a string.
2. Install and start the server:
   ```
   git clone https://github.com/bnb-chain/bnbchain-mcp.git
   cd bnbchain-mcp && git checkout a133675365d5d941d891b17a42f2ca587c33922a
   bun install && bun run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"contractAddress": "<b>tofu-poc</b>{{7*7}}", "abi": [{}], "functionName": "<i>tofu-poc</i>", "args": [], "privateKey": "", "network": "bsc-testnet"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {
       "contractAddress": "<b>tofu-poc</b>{{7*7}}",
       "abi": [{}],
       "functionName": "<i>tofu-poc</i>",
       "args": [],
       "privateKey": "",
       "network": "bsc-testnet",
   }

   async def main():
       server = StdioServerParameters(command="node", args=["dist/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("write_contract", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result is a preview with `"contractAddress": "<b>tofu-poc</b>{{7*7}}"` and `"functionName": "<i>tofu-poc</i>"`, and a valid `confirmToken`.

## Expected behavior
The tool should reject an invalid address (`isAddress`), an unknown function name, and an empty network before it issues a confirm token. Values shown in the preview should be the validated ones.

## Actual behavior
The free-text values are echoed and a token is issued. From the fuzzing run (trimmed):

```
"preview": {
  "contractAddress": "\"contractAddress\": \"0x2222222222222222222222222(22222222222222\", ... \"args\"{{\": [\"../../..",
  "functionName": "../<...>\", 0, false,",
  ...
  "network": ""
},
"confirmToken": "<48 hex chars>",
"message": "Call confirm_transfer with this confirmToken and your privateKey to execute the contract write."
```

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. Markup in the preview matters only in clients that render tool results as HTML or Markdown. In plain-text clients the rendering risk is low. The broader point is that the preview is the human checkpoint before a contract write, and it currently displays whatever text the caller supplied, including text that is not an address. The later `confirm_transfer` call would fail for an invalid address, so this does not move funds by itself.

## Suggested fix
- Validate `contractAddress` with viem's `isAddress` and normalise it with `getAddress` before building the preview.
- Check that `functionName` names a `function` entry in the supplied ABI, and require a non-empty, known `network`.
- Build the preview only from validated values. If a client renders tool output, escape or code-fence user-supplied strings.

## Status on the default branch
Still present at `a133675` (2026-04-17). The tested commit is the head of the default branch.

## Prior reports
- #65 "Security Audit: Comprehensive Vulnerability Assessment — 8 Findings (1C, 2H, 3M, 2L)" (issue, open 2026-03-20): finding SAR-01, "`write_contract` tool allows arbitrary smart contract execution with server private key", reports that any contract address, ABI, function name and arguments are accepted for this tool. It overlaps with the missing `contractAddress`/`functionName` validation here, but its code excerpt has no preview step, and it does not mention the preview echo or output encoding. SAR-03 reports missing address validation in the wallet transfer tools. Open.
- #64 "chore: Enhance documentation and tools for transfer/payment confirmation" (PR, closed 2026-04-15, labelled released): introduced the preview plus `confirmToken` flow this draft is about; it does not validate the previewed values.
- #53 "Type writeContract params properly" (PR, closed 2026-04-08): types the service-layer `writeContract` params. The default branch now types them (`WriteContractInput` in `src/evm/services/contracts.ts`), but that adds no validation of the tool inputs, so it does not fix this.
- Documentation: README.md: "Review the preview, then call `confirm_transfer` with `confirmToken` and `privateKey` to execute the transfer." (documents the preview as the user's checkpoint, for the transfer tools; `write_contract` uses the same flow)
- Documentation: CLAUDE.md (repository root): "Validate all external input at the system boundary (Zod schemas at tool layer)." (the project's own rule; `contractAddress` and `functionName` are plain `z.string()`)

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: partly reported. #65 SAR-01 (open) covers the unvalidated `write_contract` arguments from the arbitrary-execution angle; the preview echo and confirm token for invalid input are not reported. Not fixed.
- ToFu class / sanitizers: reflected-xss via `check_reflected_output`; `check_invalid_json` fired on the same inputs (silent-bug alert).
- Campaigns and executions: corpus-sbx 512 exec / 512 ok (60 s).
- Evidence (verbatim, trimmed): input `{'contractAddress': '"contractAddress": "0x2222222222222222222222222(22222222222222", "abi": [{"name": "update", "type": "function"}], "functionName": "update", "args"{{": ["../../..', 'abi': [{}, {}, {}, {}, {}], 'functionName': '../etc/passwd", 0, false,', 'args': [<long non-BMP unicode string>, '', '', '', ''], 'privateKey': '', 'network': '', 'skipConfirmation': False}` -> preview JSON echoing `contractAddress` (with `{{`), `functionName` and `args`, plus a `confirmToken`. The other two logged inputs have the same shape.
- Hand-check hints: weak. The reflection is inside a JSON-encoded preview in plain MCP text; only `{{` was flagged. Calling it XSS overstates it; the more defensible issue is that a confirm token is issued for unvalidated, non-address input. The `<b>`/`<i>` reproduction follows from the code but was not run. `abi: [{}]` passes the `z.array(z.record(z.unknown()))` schema, as in the logged input.
</details>
