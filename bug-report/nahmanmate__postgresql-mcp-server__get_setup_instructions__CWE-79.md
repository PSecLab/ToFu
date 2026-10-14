# Missing output encoding in `get_setup_instructions`: `version` echoed unescaped into an install command

**Repository:** `nahmanmate/postgresql-mcp-server` · **Tool:** `get_setup_instructions` · **Tested commit:** `7726bfb`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`get_setup_instructions` returns PostgreSQL install steps for a given `platform`, `version`, and `useCase`. The caller-supplied `version` is interpolated directly into an `apt-get install postgresql-<version>` line and returned without encoding. Caller-controlled input is reflected into the output text. Exploitability depends on how the MCP client renders the output; in the captured evidence it lands in a plain-text/Markdown instruction string.

## Details
`version` is interpolated into the install step with no validation (`src/tools/setup.ts:7-26`):

```ts
export function getSetupInstructions(platform, version = 'latest', useCase = 'development') {
  ...
  case 'linux':
    instructions.steps = [
      ...
      `sudo apt-get install postgresql${version === 'latest' ? '' : `-${version}`}`,
```

The steps are joined and returned as text (`src/index.ts:151-165`). The only constraint on `version` is `type: 'string'` in the input schema; any string flows through.

## Steps to reproduce
1. Prerequisites: Node.js. Build the server: `npm install && npm run build`.
2. Start the server as the README describes:
   ```json
   { "command": "node", "args": ["/path/to/postgresql-mcp-server/build/index.js"] }
   ```
3. Call the tool with markup in `version`. Arguments as JSON:
   ```json
   {"platform": "linux", "version": "<img src=x onerror=alert(1)>", "useCase": "development"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="node", args=["/path/to/postgresql-mcp-server/build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("get_setup_instructions", {"platform": "linux", "version": "<img src=x onerror=alert(1)>", "useCase": "development"})
               print(result)

   asyncio.run(main())
   ```
4. Observe the payload returned verbatim inside the `sudo apt-get install postgresql-...` line. If a downstream client renders the output as HTML or Markdown, the markup is not escaped.

## Expected behavior
`version` should be validated (for example, match `^[0-9.]+$` or `latest`) or encoded for the rendering context before being placed in the returned text.

## Actual behavior
The input is returned unescaped. From the fuzz evidence (`version` contained `{{"`):

```
sudo apt-get install postgresql-{{"
```

## Impact
MCP tool arguments are LLM-controlled and can be steered by prompt injection. If an MCP client renders this output as HTML/Markdown/SVG, reflected markup could execute there. There is also a lesser risk that a user who copy-pastes the returned command runs attacker-chosen shell text. In a plain-text/JSON client there is no script execution, so severity is low and conditional.

## Suggested fix
Validate `version` against an allowlist pattern (digits, dots, or `latest`) and reject anything else; HTML-encode any caller input that may be rendered.

## Status on the default branch
Still present at `7726bfb` (2025-05-01). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 6 pull requests (fetched 2026-10-01); the only security-related items are two third-party badge PRs (#6, #7) listing dependency advisories (vitest, vite, esbuild, brace-expansion). Note: the export's issue URLs point to `jamesjohnsdev/postgresql-mcp-server`, so the repository has been renamed or transferred; file there.
- #5 "Feature/tool consolidation" (PR, merged/closed 2025-05-25): the body is a single line asking to merge the consolidated version, with no details. It was closed after the tested commit, yet the default branch head is still `7726bfb`, so I could not tell from the export whether it changed `get_setup_instructions`. Check the current tool list before filing.
- Documentation: `README.md` lists `version` as "Optional: PostgreSQL version" with the example `"15"`; its "Security Considerations" section covers connection strings and SQL queries only, and says nothing about validating or escaping tool arguments echoed in output.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss (CWE-79); triggered `check_reflected_output`. Campaign: corpus-sbx (3072/3072).
- Evidence (verbatim, trimmed): inputs `version='{{"'`, `version='"version": {{"..\\'`, `version='"version: {": {{"..\\'` (platform linux) → each echoed into the `apt-get install postgresql-<version>` line; flagged token `{{`.
- Hand-check hints: WEAK. Necessary condition only (unescaped reflection into a plain-text/Markdown instruction). No rendering context verified; echoed token is `{{`. Real smell: unvalidated `version` interpolated into a shell command string that is handed back to the user/model. Severity low unless client renders HTML/MD. Secondary copy-paste-into-shell angle worth a mention but minor.
</details>
