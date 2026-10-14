# Missing output encoding in `fetch-library-docs`: the `library` name is inserted raw into the generated Markdown

**Repository:** `cdugo/package-documentation-mcp` · **Tool:** `fetch-library-docs` · **Tested commit:** `9f8ac08`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`fetch-library-docs` takes a package name or URL, crawls the documentation and returns a Markdown document. The package name is not validated or encoded. It is inserted raw into the npm URL, and the library name taken back out of that URL is written into the Markdown heading, the overview, the `Source:` line and the prompt hint at the end. HTML, Markdown and template syntax in `library` therefore come back unescaped in a result that is meant to be rendered as Markdown.

## Details
`src/index.ts:252-256` at `9f8ac08` builds the URL:

```ts
      const isLibraryUrl = isUrl(library);
      let url = isLibraryUrl ? library : getPackageUrl(library, language);

      const documentationContent =
        await scraperService.fetchLibraryDocumentation(url);
```

`getPackageUrl` (`src/utils/packageRepository.ts:47`) returns `` `https://www.npmjs.com/package/${packageName}` `` with no `encodeURIComponent`. `extractLibraryName` (`packageRepository.ts:154-155`) takes everything after `/package/` up to the next `/`. `src/services/ScraperService.ts` then writes that value and the raw URL into the output:

```ts
    let result = `# ${libraryName} Documentation\n\n`;          // line 210
    result += `Library Name: ${libraryName}\n`;                 // line 214
      result += `Source: ${page.url}\n\n`;                      // line 231
- libraryName: "${libraryName}"                                 // line 165
Example: @summarize-library-docs with libraryName="${libraryName}"  // line 168
```

The error path (`ScraperService.ts:176-193`) reflects the same value, so the reflection happens whether or not the fetch works.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and outbound HTTPS access. The tool fetches `https://www.npmjs.com/package/<name>`. No API key is needed.
2. Install and start the server:
   ```
   git clone https://github.com/cdugo/package-documentation-mcp
   cd package-documentation-mcp && git checkout 9f8ac082cdf8a7d78b92b4df33b0bc6ddda6bd57
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments. The payload has no `/`, because `extractLibraryName` cuts the name at the first `/`.
   ```json
   {"library": "<b>tofu-poc{{7*7}}", "language": "javascript"}
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
                   "fetch-library-docs",
                   {"library": "<b>tofu-poc{{7*7}}", "language": "javascript"},
               )
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the Markdown starts with `# <b>tofu-poc{{7*7}} Documentation`, contains `Library Name: <b>tofu-poc{{7*7}}` and `Source: https://www.npmjs.com/package/<b>tofu-poc{{7*7}}`, and ends with `libraryName="<b>tofu-poc{{7*7}}"`.

## Expected behavior
The package name should be checked against the naming rules of the target registry, or at least passed through `encodeURIComponent` when building the URL. Values written into the Markdown should be escaped, for example with HTML entities for `<`, `>` and `&` and a backslash before Markdown control characters, or placed in inline code.

## Actual behavior
The value is reflected verbatim in several places. From the fuzzing run (trimmed):

```
# a:r\x7f{{"li":r\x7f "\x7f Documentation
...
Library Name: a:r\x7f{{"li":r\x7f "\x7f
...
Source: https://www.npmjs.com/package/a:r\x7f{{"li":r\x7f "\x7f
...
Example: @summarize-library-docs with libraryName="a:r\x7f{{"li":r\x7f "\x7f"
```

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The tool's output is a Markdown document, so clients that render Markdown, and possibly inline HTML, will render caller-chosen markup. A name with line breaks can also add headings or instructions to the document handed back to the model. The attacker already influences the call, so this is low severity. It is still worth fixing because the output is designed to be rendered.

## Suggested fix
- Validate `library` when it is not a URL, for example with the npm name pattern `^(@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$`, or the equivalent rule for the selected registry.
- Build registry URLs with `encodeURIComponent(packageName)`, keeping `/` for scoped names.
- Escape `libraryName`, `page.url` and `page.title` before writing them into the Markdown, or wrap them in inline code.

## Status on the default branch
Still present at `9f8ac08` (2025-03-13). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`. Also triggered for this tool: `check_introspection_hardcoded_credentials` and `check_resource_exhaustion` (not part of this draft).
- Campaigns and executions: repo24-b, 7 runs of 4,200 s each: 56,832/56,624, 65,536/65,445, 58,368/58,297, 41,472/41,418, 48,128/48,009, 54,784/54,668, 59,904/59,778 (exec/ok).
- Evidence (verbatim, trimmed): input `{'library': 'a:r\x7f{{"li":r\x7f "\x7f', 'language': ''}` -> `# a:r\x7f{{"li":r\x7f "\x7f Documentation ... Library Name: a:r\x7f{{"li":r\x7f "\x7f ... Source: https://www.npmjs.com/package/a:r\x7f{{"li":r\x7f "\x7f`. npm served a Cloudflare "Just a moment..." page. Two more inputs of the same shape.
- Hand-check hints: weak. Real reflection into output that is explicitly Markdown, but the only flagged token was `{{` and the caller is the attacker. The `<b>` payload is derived from the code; it was not run. `extractLibraryName` truncates at `/`, so `</b>` style payloads lose their closing tag in the heading but not in the `Source:` line. Out of scope here but noticed: `library` may be any URL (`isUrl` branch) and `fetch-url-docs` fetches any URL, and the crawler follows links from fetched pages, which is an SSRF surface; `page.title` from the remote page is also written raw into the Markdown.
</details>
