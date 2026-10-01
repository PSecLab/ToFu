# Missing output encoding in `get_block_by_hash`: an invalid `blockHash` is echoed back raw inside the RPC error text

**Repository:** `bnb-chain/bnbchain-mcp` · **Tool:** `get_block_by_hash` · **Tested commit:** `a133675`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_block_by_hash` looks up block metadata by hash. The `blockHash` argument is any string. It is sent to the RPC node as is, and when the node rejects it, the tool returns viem's full error message. That message contains the JSON request body, so the caller's string comes back unescaped in the tool result, together with the RPC URL and the viem version.

## Details
`src/evm/modules/blocks/tools.ts:43-64` at `a133675`:

```ts
      blockHash: z.string().describe("The block hash to look up"),
      ...
      try {
        const block = await services.getBlockByHash(
          blockHash as Hash,
          network,
          ...
        return mcpToolRes.success(blockSummaryToJson(block))
      } catch (error) {
        return mcpToolRes.error(error, "fetching block by hash")
      }
```

`blockHash` is only checked as a string and then cast to `Hash`. `src/evm/services/blocks.ts:66-69` passes it to `client.getBlock({ blockHash, ... })`, which sends `eth_getBlockByHash`. When the node returns "invalid params", viem builds an error whose message includes `Request body: ${stringify(body)}`. `src/utils/helper.ts:48-56` then returns that message verbatim:

```ts
          text: `Error ${operation}: ${error instanceof Error ? error.message : String(error)}`
```

`JSON.stringify` escapes quotes but not `<`, `>` or `{{`, so markup in `blockHash` survives.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and Bun 1.2.10 or later. No private key is needed. The call goes to the public BSC RPC endpoint that the server uses for `network: "bsc"`, so the machine needs outbound network access.
2. Install and start the server:
   ```
   git clone https://github.com/bnb-chain/bnbchain-mcp.git
   cd bnbchain-mcp && git checkout a133675365d5d941d891b17a42f2ca587c33922a
   bun install && bun run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"blockHash": "<b>tofu-poc</b>{{7*7}}", "network": "bsc"}
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
               result = await session.call_tool(
                   "get_block_by_hash",
                   {"blockHash": "<b>tofu-poc</b>{{7*7}}", "network": "bsc"},
               )
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content starts with `Error fetching block by hash: Invalid parameters were provided to the RPC method.` and contains `Request body: {"method":"eth_getBlockByHash","params":["<b>tofu-poc</b>{{7*7}}",false]}`, plus the RPC URL and the viem version.

## Expected behavior
A value that is not a 32-byte hex hash should be rejected before any RPC call, with a fixed message such as "blockHash must be a 0x-prefixed 32-byte hex string".

## Actual behavior
The raw input is sent to the node and reflected back in the error. From the fuzzing run (trimmed):

```
Error fetching block by hash: Invalid parameters were provided to the RPC method.
...
URL: https://bsc-dataseed.binance.org
Request body: {"method":"eth_getBlockByHash","params":["\"blockHach\": ... \"inc{{{{{ludeTransactionHashes\": true, ...",false]}

Details: unmarshalerDecoder: json: cannot unmarshal hex string without 0x prefix into Go value of type common.Hash, ...
Version: viem@2.27.2
```

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The result then carries caller-chosen markup or template syntax. This matters only in clients that render tool results as HTML or Markdown, or feed them into a template engine. In plain-text clients it is low severity. The error text also discloses the RPC URL and library version, which is minor.

## Suggested fix
- Validate `blockHash` in the zod schema, for example `z.string().regex(/^0x[0-9a-fA-F]{64}$/)`, or with viem's `isHash`, so malformed values never reach the RPC node.
- In `mcpToolRes.error`, prefer viem's `error.shortMessage` (no request body or URL) over `error.message`, or return a fixed message per operation. If any caller text is kept, escape it and cap its length.

## Status on the default branch
Still present at `a133675` (2026-04-17). The tested commit is the head of the default branch.

## Prior reports
- #51 "Fix: Add input validation for block numbers" (PR, closed 2026-04-08): validates `parseInt` block numbers, not `blockHash`; does not fix this.
- #49 "SECURITY: Sanitize private key from error messages" (PR, closed 2026-04-08): proposed redacting 64-character hex strings in error text returned to the client through the same error path; no escaping of caller text, and not present in `src/utils/helper.ts` at `a133675`.
- #50 "SECURITY: Mask API keys in RPC URLs" (PR, closed 2026-04-08): masks credentials in the RPC URL returned by `get_chain_info`; the viem error returned here also carries the RPC URL and is not covered.
- Documentation: CLAUDE.md (repository root): "Validate all external input at the system boundary (Zod schemas at tool layer)." (the project's own rule; `blockHash` is a plain `z.string()`)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`; `check_invalid_json` also fired on the same input (silent-bug alert, not a separate finding).
- Campaigns and executions: corpus-sbx 512 exec / 54 ok (60 s).
- Evidence (verbatim, trimmed): input `{'blockHash': '"blockHach": "../../../../etc/passwd", "network":lllllllllllllllllllll "bsc", "inc{{{{{ludeTransactionHashes": true, "maxTransactionHashes": 1', 'network': 'bsc', 'includeTransactionHashes': False, 'maxTransactionHashes': 100}` -> `Error fetching block by hash: Invalid parameters were provided to the RPC method. ... Request body: {"method":"eth_getBlockByHash","params":["\"blockHach\": ... \"inc{{{{{ludeTransactionHashes\": true, \"maxTransactionHashes\": 1",false]} ... Version: viem@2.27.2`.
- Hand-check hints: weak. Only `{{` was reflected, inside the JSON-encoded request body of a viem error, in plain MCP text content. The reflection is built by viem (`metaMessages: [URL, Request body]`), not by repo code; the repo's part is the missing hash validation and forwarding `error.message`. The `<b>` reproduction is derived from reading viem's `_esm/errors/request.js:93` in the local target copy (`eval/sandbox/targets/bnb-chain__bnbchain-mcp`, which has viem 2.56.3, while the logged run reported viem 2.27.2); it was not run. The repro depends on the public BSC RPC node returning an "invalid params" error for a non-hex hash, as it did in the log.
</details>
