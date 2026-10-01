# Missing output encoding in `fetch-package-docs`: `packageName` is inserted raw into the generated Markdown

**Repository:** `cdugo/package-documentation-mcp` · **Tool:** `fetch-package-docs` · **Tested commit:** `9f8ac08`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`fetch-package-docs` builds a registry URL from `packageName` and `language`, crawls the page and returns a Markdown document. `packageName` is not validated or URL-encoded. The name extracted back from the URL is written raw into the document heading, the overview, the `Source:` line and the prompt hint at the end. HTML, Markdown and template syntax in `packageName` therefore come back unescaped in output meant to be rendered as Markdown.

## Details
`src/index.ts:187-197` at `9f8ac08`:

```ts
  async ({ packageName, language = "javascript" }) => {
    ...
    try {
      const packageUrl = getPackageUrl(packageName, language);
      console.error(`Using package URL: ${packageUrl}`);

      const documentationContent =
        await scraperService.fetchLibraryDocumentation(packageUrl);
```

`getPackageUrl` (`src/utils/packageRepository.ts:32-101`) interpolates `packageName` into every registry URL without `encodeURIComponent`. `extractLibraryName` (`packageRepository.ts:152-179`) takes the path segment after the registry prefix. `src/services/ScraperService.ts` writes that value and the raw URL into the Markdown at lines 165, 168, 210, 214 and 231, for example:

```ts
    let result = `# ${libraryName} Documentation\n\n`;
    result += `Library Name: ${libraryName}\n`;
      result += `Source: ${page.url}\n\n`;
```

The error branch (`ScraperService.ts:176-193`) reflects the same values, so the fetch result does not matter.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and outbound HTTPS access. The tool fetches the npm package page. No API key is needed.
2. Install and start the server:
   ```
   git clone https://github.com/cdugo/package-documentation-mcp
   cd package-documentation-mcp && git checkout 9f8ac082cdf8a7d78b92b4df33b0bc6ddda6bd57
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments. The payload avoids `/`, because `extractLibraryName` cuts the name at the first `/`.
   ```json
   {"packageName": "<b>tofu-poc${7*7}{{7*7}}", "language": "javascript"}
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
               result = await session.call_tool(
                   "fetch-package-docs",
                   {"packageName": "<b>tofu-poc${7*7}{{7*7}}", "language": "javascript"},
               )
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the Markdown starts with `# <b>tofu-poc${7*7}{{7*7}} Documentation`, and the same string appears in `Library Name:`, in `Source: https://www.npmjs.com/package/...` and in `libraryName="..."` at the end.

## Expected behavior
`packageName` should be validated against the registry's naming rules, or URL-encoded when the URL is built. Values written into the Markdown should be escaped or wrapped in inline code.

## Actual behavior
The value is reflected verbatim. From the fuzzing run (trimmed):

```
# "packageName": "..\\..\\..\\..\\win${"packageNni", "language": "dotnet Documentation
...
Library Name: "packageName": "..\\..\\..\\..\\win${"packageNni", "language": "dotnet
...
Source: https://www.npmjs.com/package/"packageName": "..\\..\\..\\..\\win${"packageNni", "language": "dotnet
...
- libraryName: ""packageName": "..\\..\\..\\..\\win${"packageNni", "language": "dotnet"
```

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The output is a Markdown document, so clients that render Markdown, and possibly inline HTML, will render caller-chosen markup. A name with line breaks can also add headings or instructions to the document returned to the model. The attacker already influences the call, so the severity is low.

## Suggested fix
- Validate `packageName` per registry, for example the npm name pattern `^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$` for `javascript`.
- Build registry URLs with `encodeURIComponent(packageName)`, keeping `/` for scoped names.
- Escape `libraryName`, `page.url` and `page.title` before writing them into the Markdown, or wrap them in inline code.
- Declare `language` as a `z.enum` of the supported keys instead of a free string that silently falls back to npm.

## Status on the default branch
Still present at `9f8ac08` (2025-03-13). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. `check_resource_exhaustion` also triggered for this tool (not part of this draft).
- Campaigns and executions: repo24-b, 4 runs of 4,200 s: 57,344/57,340, 55,296/55,259, 41,984/41,979, 55,808/55,804 (exec/ok).
- Evidence (verbatim, trimmed): input `{'packageName': '"packageName": "..\\\\..\\\\..\\\\..\\\\win${"packageNni", "language": "dotnet', 'language': ''}` -> `# "packageName": "..\\..\\..\\..\\win${"packageNni", "language": "dotnet Documentation ...` (token `${`). Two more inputs reflected `{{`.
- Hand-check hints: weak. Same root cause as `fetch-library-docs` and `fetch-multilingual-docs` (shared `getPackageUrl` + `ScraperService` Markdown builder); consider one issue for all three. Reflection into Markdown output is real and logged, but only `${`/`{{` were flagged and the caller is the attacker. The `<b>` payload is derived from the code and was not run.
</details>
