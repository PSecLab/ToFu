# Missing output encoding in `AoT`: `atomId` is echoed back unescaped in the tool result

**Repository:** `kbsooo/MCP_Atom_of_Thoughts` · **Tool:** `AoT` · **Tested commit:** `923e66d`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
The `AoT` tool stores a reasoning "atom" and returns a JSON summary that includes the caller's `atomId`. `atomId` only has to be a non-empty string, so any markup or template syntax comes back exactly as sent. `JSON.stringify` escapes quotes and most control characters, but not `<`, `>` or braces. The result is a plain-text content block, so this only matters if an MCP client renders tool output as HTML or Markdown. This is a low-severity output-encoding report.

## Details
`src/index.ts` at `923e66d`. Validation (lines 44-46) only checks the type:

```ts
    if (!data.atomId || typeof data.atomId !== 'string') {
      throw new Error('Invalid atomId: must be a string');
    }
```

The result (lines 423-429) echoes it back:

```ts
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            atomId: validatedInput.atomId,
            atomType: validatedInput.atomType,
            isVerified: validatedInput.isVerified,
            ...
```

The input schema (lines 611-614) also has no `pattern` or `maxLength` for `atomId`. The `AoT` tool is dispatched at line 776 to `processAtom()` (line 352).

## Steps to reproduce
1. Prerequisites: Node.js. No accounts or network access are needed.
2. Install and start the server as the README describes: `git clone https://github.com/kbsooo/MCP_Atom_of_Thoughts && cd MCP_Atom_of_Thoughts && git checkout 923e66d && npm install && node build/index.js` (`build/index.js` is committed; `npm run build` regenerates it).
3. Call the tool with `{"atomId": "<img src=x onerror=alert(1)>", "content": "tofu poc", "atomType": "premise", "dependencies": [], "confidence": 0.5}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/MCP_Atom_of_Thoughts/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool(
                   "AoT",
                   {
                       "atomId": "<img src=x onerror=alert(1)>",
                       "content": "tofu poc",
                       "atomType": "premise",
                       "dependencies": [],
                       "confidence": 0.5,
                   },
               )
               print(result)

   asyncio.run(main())
   ```
4. Observe that the text content contains `"atomId": "<img src=x onerror=alert(1)>"` with the tag unchanged.

## Expected behavior
`atomId` is restricted to a short identifier format (the tool description, line 580, gives `A1` and `H2` as examples), and anything else is rejected. If free text must be echoed, a client that renders it escapes it for its own context.

## Actual behavior
Any string is accepted and echoed back raw. Real output from the fuzz run (trimmed):

```
{
  "atomId": "\"at{{{{{{{{{{{{{{{{{{{{{{{{{{{omId\": \"A2\", \"content\": ...",
  "atomType": "premise",
  ...
```

## Impact
Low. `atomId` is chosen by the LLM, which can be steered by prompt injection from untrusted content. Script would only run if an MCP client rendered the tool's text output as HTML without escaping. In a normal chat client the echoed text is shown as plain text.

## Suggested fix
Constrain `atomId` both in the schema and in `validateAtomData`:

```ts
const ATOM_ID_RE = /^[A-Za-z0-9_-]{1,32}$/;
if (typeof data.atomId !== 'string' || !ATOM_ID_RE.test(data.atomId)) {
  throw new Error('Invalid atomId: use 1-32 letters, digits, "_" or "-"');
}
```

and add `"pattern": "^[A-Za-z0-9_-]{1,32}$"` to the `atomId` property in the input schema. The same validator is used by `AoT-light`, so both tools are covered.

## Status on the default branch
Still present at `923e66d` (2025-05-14). The default branch has no commits after the tested one.

## Prior reports
None found. Searched the 1 issue and all 3 pull requests (fetched 2026-10-01) and the README / docs on the default branch. README.md only describes `atomId` as "Unique identifier for the atom (e.g., 'A1', 'H2')", with no stated format limit and nothing on escaping.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79/CWE-116). Fired: `check_reflected_output`, plus `check_invalid_json` (the input `atomId` looked like broken JSON).
- Campaigns and executions: `corpus-sbx`: 2560 execs, 1557 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'atomId': '"at{{{{{{{{{{{{{{{{{{{{{{{{{{{omId": "A2", "content": "..\\\\.e": "reasoning", ...', 'content': '...', 'atomType': 'premise', 'dependencies': [], 'confidence': 0.0, 'isVerified': False, 'depth': 0.0}`, output `{"atomId": "\"at{{{{...omId\": \"A2\", ...", "atomType": "premise", ..., "atomsCount": 808, ...}`. Analysis: "input payload token(s) ['{{'] echoed UNESCAPED in the tool output". Other rows are the same pattern.
- Hand-check hints: **weak.** Only `{{` was observed, inside a JSON string in a `text` content block; the `<img ...>` echo in the repro follows from `JSON.stringify` semantics but was not run. No HTML rendering context exists in this server. Two side observations from the code, not part of this draft: (a) `processAtom` also prints `atomId` and `content` unescaped to stderr via `formatAtom` + `console.error` (lines 103, 396), which is a CWE-117 shape; (b) atoms are kept in memory forever with no limit (`atomsCount` reached 1016 in the run), a possible slow memory growth issue. Probably not worth filing the CWE-79 part on its own.
</details>
