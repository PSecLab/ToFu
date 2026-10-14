# Missing output encoding in `get_block`: `blockName` is echoed unescaped into the block description and usage text

**Repository:** `Jpisnice/shadcn-ui-mcp-unofficial` · **Tool:** `get_block` · **Tested commit:** `45d615f`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_block` fetches a shadcn/ui block from GitHub and returns its files, dependencies and usage instructions as JSON text. The caller's `blockName` is copied unescaped into `name`, `description` and the human-readable `usage` instructions, and into the error message when the lookup fails. Names that do not exist are not rejected; in our run they came back as an empty "complex" block that still carries the caller's text. HTML or Markdown in `blockName` therefore reaches any client that renders tool output.

## Details
`src/utils/axios.ts` (tested commit). The complex-block result is built from `blockName` (lines 656-660), and the usage text interpolates it again (lines 559-562, called at line 760):

```ts
        const blockStructure: any = {
            name: blockName,
            type: 'complex',
            description: `Complex block: ${blockName}`,
// ...
function generateComplexBlockUsage(blockName: string, structure: any[]): string {
    const hasComponents = structure.some(item => item.name === 'components');

    let usage = `To use the ${blockName} block:\n\n`;
```

`src/tools/blocks/get-block.ts:26-28` returns this object via `JSON.stringify`, which escapes quotes and control characters but not `<`, `>` or Markdown. The simple-block branch (line 636) and the error paths (`get-block.ts:31-35`, `axios.ts:766`) interpolate `blockName` the same way. The only validation is in `src/utils/validation.ts`, and `handler.ts:369-375` only applies the generic `call_tool` schema, so `blockName` is not checked against a name pattern.

## Steps to reproduce
1. Prerequisites: Node.js 18+, network access to `api.github.com` and `raw.githubusercontent.com`. `GITHUB_PERSONAL_ACCESS_TOKEN` is optional (raises the rate limit).
2. Install and start from a checkout:
   ```bash
   git clone https://github.com/Jpisnice/shadcn-ui-mcp-unofficial.git
   cd shadcn-ui-mcp-unofficial && npm install && npm run build
   # server entry point: node build/index.js  (stdio is the default mode)
   ```
3. Call the tool:
   ```json
   {"blockName": "<img src=x onerror=alert(1)>-tofu-poc", "includeComponents": false}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_block",
                   {"blockName": "<img src=x onerror=alert(1)>-tofu-poc", "includeComponents": False})
               print(result)

   asyncio.run(main())
   ```
4. Observe: the returned JSON has `"name": "<img src=x onerror=alert(1)>-tofu-poc"`, `"description": "Complex block: <img ...>"` and a `usage` string starting `To use the <img src=x onerror=alert(1)>-tofu-poc block:`, with the markup unchanged. If the lookup errors instead, the error text `Failed to get block "<img ...>"` carries it the same way.

## Expected behavior
`blockName` is validated against the real naming scheme (e.g. `^[a-z0-9-]+$`) and unknown names return a clear "not found" error. Any caller text placed into descriptions or instructions is escaped.

## Actual behavior
The name is reflected unchanged, and an unknown name produces an empty block instead of an error. From the fuzzing run:

```
"name": "\"blockName\": \"dasjboard-01\", \"includeCompo{{{nents\": fals",
"type": "complex",
"description": "Complex block: \"blockName\": \"dasjboard-01\", \"includeCompo{{{nents\": fals",
"files": {},
...
"usage": "To use the \"blockName\": \"dasjboard-01\", \"includeCompo{{{nents\": fals block:\n\n1. Copy the main files to your project:\n\n2. Update import paths as needed\n..."
```

## Impact
Low. Tool results are usually treated as plain text and `blockName` is chosen by the LLM, so the main risk is a client that renders tool output as Markdown or HTML: a name steered by prompt injection can then inject markup or links into what the user sees, inside text that looks like official usage instructions. There is no server-side effect.

## Suggested fix
- Validate `blockName` with a strict pattern such as `/^[a-z0-9][a-z0-9-]{0,99}$/` in `handleGetBlock` before any request, and return "not found" for anything else.
- Treat a non-array GitHub contents response (e.g. a 404 body) as "not found" instead of building an empty complex block.
- Escape or code-span any caller-derived text in `description` and `usage`, and avoid echoing raw input in error messages.

## Status on the default branch
Still present at `45d615f` (2026-05-16). The tested commit is the current head of the default branch.

## Prior reports
- #62 "fix: validate tool arguments and return invalid input as a tool error" (PR, open 2026-09-26): would apply the existing per-tool Joi schemas, including `get_block`, before the handler runs. The `get_block` schema on the default branch is only `blockName: Joi.string().required().min(1).max(200)`, so markup in `blockName` would still pass. Related (same missing-validation root), not a fix.
- #61 "get_component / get_component_demo crash (raw TypeError) on missing or wrong-type componentName" (issue, open 2026-09-08): missing argument validation in sibling tools; about type errors, not about echoing markup. Not this bug.
- #28 "Shadcn - get_block (MCP)(blockName: "dashboard-01", includeComponents: true) - Faild" (issue, closed 2025-12-25): user report of the same empty "complex" block result that this draft shows for unknown names; no mention of escaping. Not a fix.
- Documentation: SSE_IMPLEMENTATION.md lists "**Request Validation**: Input validation and sanitization" under Security Features; `blockName` is neither pattern-checked nor escaped, so the claim does not hold for this tool.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss; `check_reflected_output` only. The token it matched was `{{`, not HTML.
- Campaigns and executions: corpus-sbx 512 exec / 511 ok (60 s budget).
- Evidence (verbatim, trimmed), corpus-sbx, all returning an empty `complex` block that echoes the name in `name`, `description` and `usage`:
  - `{'blockName': '"blockName": "dasjboard-01", "includeCompo{{{nents": fals', 'includeComponents': False}`
  - `{'blockName': '"blockName": "dasjboard-01", "includ\x11Compo{{{nents": fals', 'includeComponents': False}` (control char came back JSON-escaped as `\u0011`)
  - `{'blockName': '"blockName": "dasjboaudeComponents": "yepo{{{nents": fals', 'includeComponents': False}`
- Hand-check hints: weak. Only `{{` was echoed, inside a JSON string in a plain-text MCP `text` item; the HTML payload in the repro is ours, inferred from the code, not observed in a run. The "unknown name gives an empty complex block" behavior is from the evidence; we believe it is because `githubApi`/`githubRaw` are created with `new Axios({...})` (axios.ts:23-51) without `validateStatus`, so 404s resolve instead of throwing, but we did not verify that against the axios source. The repro needs live GitHub access; results can differ under rate limiting. `blockName` is also placed into the GitHub API path (line 650) unencoded by the server; not explored here.
</details>
