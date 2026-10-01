# Missing output encoding in `get_erc8004_agent_wallet`: a non-numeric `agentId` is echoed raw in the error

**Repository:** `bnb-chain/bnbchain-mcp` · **Tool:** `get_erc8004_agent_wallet` · **Tested commit:** `a133675`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_erc8004_agent_wallet` returns the payment wallet registered for an ERC-8004 agent. The schema accepts any string as `agentId` and the handler converts it with `BigInt(agentId)`. For a non-numeric string, V8 throws `Cannot convert <input> to a BigInt`, and the tool returns that message verbatim. Caller text, including markup and template syntax, comes back unescaped in the tool result.

## Details
`src/evm/modules/agents/tools.ts:104-124` at `a133675`:

```ts
    "get_erc8004_agent_wallet",
    ...
      agentId: z
        .union([z.string(), z.number()])
        .describe("The ERC-8004 agent ID (token ID)"),
      network: defaultNetworkParam
    },
    async ({ agentId, network }) => {
      try {
        const id = BigInt(agentId)
        const wallet = await services.getAgentWallet(id, network)
        ...
      } catch (error) {
        return mcpToolRes.error(error, "getting ERC-8004 agent wallet")
      }
```

`src/utils/helper.ts:53` formats the error as `` `Error ${operation}: ${error.message}` ``. There is no check that `agentId` is a decimal integer, and no escaping or length cap on the message. The conversion fails before any RPC call.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and Bun 1.2.10 or later. No private key or network access is needed for this call.
2. Install and start the server:
   ```
   git clone https://github.com/bnb-chain/bnbchain-mcp.git
   cd bnbchain-mcp && git checkout a133675365d5d941d891b17a42f2ca587c33922a
   bun install && bun run build
   node dist/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"agentId": "<b>tofu-poc</b>{{7*7}}", "network": "bsc-testnet"}
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
                   "get_erc8004_agent_wallet",
                   {"agentId": "<b>tofu-poc</b>{{7*7}}", "network": "bsc-testnet"},
               )
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the text content is `Error getting ERC-8004 agent wallet: Cannot convert <b>tofu-poc</b>{{7*7}} to a BigInt`.

## Expected behavior
A non-numeric `agentId` should be rejected by the schema, or produce a fixed message such as "agentId must be a non-negative integer".

## Actual behavior
The input is reflected verbatim. From the fuzzing run (trimmed):

```
Error getting ERC-8004 agent wallet: Cannot convert "{"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ to a BigInt
```

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The result then carries caller-chosen markup or template syntax. This matters only in clients that render tool results as HTML or Markdown, or pass them to a template engine. In plain-text clients it is low severity.

## Suggested fix
Validate `agentId` in the schema, for example `z.union([z.string().regex(/^\d+$/), z.number().int().nonnegative()])`, so `BigInt` never sees free text. In the catch block, return a fixed message for conversion errors instead of `error.message`. `get_erc8004_agent` (`tools.ts:90`) and `set_erc8004_agent_uri` (`tools.ts:60`) have the same pattern.

## Status on the default branch
Still present at `a133675` (2026-04-17). The tested commit is the head of the default branch.

## Prior reports
- #30 "Fix: Remove dead ternary in agentId" (PR, closed 2026-04-08): simplifies the `agentId` conversion to a direct `BigInt()`; adds no validation, does not fix this.
- #49 "SECURITY: Sanitize private key from error messages" (PR, closed 2026-04-08): proposed redacting 64-character hex strings in error text returned through the same `mcpToolRes.error` path; no escaping of caller text, and not present at `a133675`.
- Documentation: CLAUDE.md (repository root): "Validate all external input at the system boundary (Zod schemas at tool layer)." (the project's own rule; `agentId` is `z.union([z.string(), z.number()])` with no integer check)

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`, the only sanitizer that fired for this tool.
- Campaigns and executions: corpus-sbx 512 exec / 494 ok (60 s).
- Evidence (verbatim, trimmed): input `{'agentId': '"{"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{', 'network': ''}` -> `{'content': [{'type': 'text', 'text': 'Error getting ERC-8004 agent wallet: Cannot convert "{"{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{{ to a BigInt'}]}`. Two more inputs (one with a NUL byte) gave the same shape.
- Hand-check hints: weak. Same root cause as `get_erc8004_agent`: V8's `BigInt` SyntaxError text forwarded as plain MCP text; only `{{` reflected in the log. The `<b>` reproduction follows from the code path but was not run. Consider filing the three agent tools as one issue.
</details>
