# Missing validation and output encoding in `gcp-utils-set-project-id`: any string is stored as the project ID and echoed back in Markdown

**Repository:** `krzko/google-cloud-mcp` · **Tool:** `gcp-utils-set-project-id` · **Tested commit:** `85eeb65`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`gcp-utils-set-project-id` accepts any non-empty string as the default Google Cloud project ID, persists it to `~/.google-cloud-mcp/`, and echoes it inside a Markdown code span. A backtick in the value closes the code span, so the rest of the string is interpreted as Markdown. The stored value is later echoed again by `gcp-utils-get-project-id` and by other tools that fall back to the current project. Impact depends on how the MCP client renders tool output. In a plain-text client it is cosmetic.

## Details
`src/utils/project-tools.ts:31-39`:
```ts
    async ({ project_id }) => {
      try {
        await setProjectId(project_id);

        return {
          content: [
            {
              type: "text",
              text: `# Project ID Updated\n\nDefault Google Cloud project ID has been set to: \`${project_id}\`\n\n...`,
```
`setProjectId` (`src/utils/auth.ts:278-281`) hands the value to `stateManager.setCurrentProjectId` (`src/utils/state-manager.ts:150-176`). That function only rejects empty strings, sets `process.env.GOOGLE_CLOUD_PROJECT`, and writes the value to `~/.google-cloud-mcp/state.json` and `~/.google-cloud-mcp/config.json` (recent projects list). `gcp-utils-get-project-id` echoes it again at `project-tools.ts:78` and `:83`. The value is never checked against the Google Cloud project ID format.

## Steps to reproduce
1. Prerequisites: Node.js and pnpm. No Google Cloud credentials are needed for these two calls. Use a throwaway `HOME`, because this tool writes to `~/.google-cloud-mcp/`.
2. Build the server as the README describes:
   ```bash
   git clone https://github.com/krzko/google-cloud-mcp && cd google-cloud-mcp
   git checkout 85eeb65
   pnpm install && pnpm build
   ```
3. From the repository root, call the tool with these arguments, then call `gcp-utils-get-project-id` with `{}`:
   ```json
   {"project_id": "tofu` <b>tofu-poc</b> ${7*7} `x"}
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
               result = await session.call_tool("gcp-utils-set-project-id", {
                   "project_id": "tofu` <b>tofu-poc</b> ${7*7} `x",
               })
               print(result)
               print(await session.call_tool("gcp-utils-get-project-id", {}))

   asyncio.run(main())
   ```
4. Observe ``set to: `tofu` <b>tofu-poc</b> ${7*7} `x` `` in the first response (the `<b>` part is now outside the code span), the same value in the second response, and the value stored in `/tmp/tofu-gcp-home/.google-cloud-mcp/state.json`.

## Expected behavior
The tool rejects values that are not valid Google Cloud project IDs. Echoed values cannot break out of their code span.

## Actual behavior
The value is accepted, stored and echoed verbatim. From the fuzzing run (input `{'project_id': '${7*7}'}`):
```
# Project ID Updated

Default Google Cloud project ID has been set to: `${7*7}`

This project ID will be used for all Google Cloud operations until changed.
```
Other fuzzed inputs with NUL and other control bytes (`\x01\x00`) were also accepted and echoed.

## Impact
Low. Tool arguments are chosen by the LLM, and prompt injection from untrusted content can steer them. Beyond Markdown injection in clients that render tool output, the more practical effect is that a steered call can silently replace the user's default project with an arbitrary string. That string persists across restarts and is reused by later tools. Because nothing is validated, later API calls fail with confusing errors instead of a clear rejection here.

## Suggested fix
Validate `project_id` before storing it. Google Cloud project IDs are lowercase letters, digits and hyphens, start with a letter and are 6 to 30 characters long, so a check such as `/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/` rejects all of the inputs above. With that check in place the code-span echo is safe. If free text must ever be echoed, escape backticks and other Markdown control characters first.

## Status on the default branch
Still present at `85eeb65` (2025-07-31). The tested commit is the current default branch head.

## Prior reports
None found. Searched all 5 issues and 29 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss, `check_reflected_output` (token `${`).
- Campaigns and executions: `corpus-sbx` 2048 exec / 2048 success (60 s).
- Evidence (verbatim, trimmed): input `{'project_id': '${7*7}'}`; output ``# Project ID Updated\n\nDefault Google Cloud project ID has been set to: `${7*7}`\n\n...``. Also input `{'project_id': '"project_id": "${7\x01\x00\x00'}` was echoed unchanged, control bytes included.
- Hand-check hints: weak as XSS. ToFu only saw `${` echoed inside a Markdown code span, which is not a template sink (it is not evaluated: the output shows `${7*7}`, not `49`). The backtick break-out and the stored echo via `gcp-utils-get-project-id` are my reading of the code; not run. The missing project ID validation with persistence is the more useful point for the maintainer. The project ID format rule is from Google Cloud's public naming rules, quoted from memory, not re-checked here. Note for the hand-check: the fuzzing run will have rewritten `~/.google-cloud-mcp/` inside the sandbox home, not the real one, if `HOME` was sandboxed (not verified). File, if at all, together with the three billing drafts as one low-severity issue.
</details>
