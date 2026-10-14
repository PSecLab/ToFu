# Missing output encoding in `fetch-multilingual-docs`: `packageName` and `languages` are inserted raw into the Markdown summary

**Repository:** `cdugo/package-documentation-mcp` · **Tool:** `fetch-multilingual-docs` · **Tested commit:** `9f8ac08`
**Weakness:** CWE-79 Cross-site Scripting / unescaped output

## Summary
`fetch-multilingual-docs` looks a package up in several registries and returns a Markdown summary followed by the documentation it found. `packageName` and every entry of `languages` are free strings. They are written into the Markdown heading, into bold labels and into the registry URLs without validation or escaping. Caller-supplied HTML, Markdown and template syntax therefore come back unescaped in a result meant for Markdown rendering.

## Details
`src/index.ts:309-374` at `9f8ac08`:

```ts
    for (const language of languages) {
      try {
        const packageUrl = getPackageUrl(packageName, language);
        ...
    const summaryLines = [
      `## Documentation Search Results for '${packageName}'`,
    ];
    ...
        summaryLines.push(
          `✅ **${language}**: Successfully fetched documentation from ${result.url}`
        );
    ...
      `# Documentation Content (from ${bestLanguage} repository)`
```

An unknown `language` falls through to the npm default in `getPackageUrl` (`src/utils/packageRepository.ts:99-100`), which interpolates `packageName` into the URL without `encodeURIComponent`. The appended documentation comes from `ScraperService.fetchLibraryDocumentation`, which writes the extracted library name and raw URL into its own Markdown (`src/services/ScraperService.ts:165`, `:168`, `:210`, `:214`, `:231`). The failure message at `index.ts:338` reflects both values as well.

## Steps to reproduce
1. Prerequisites: Node.js 18 or later and outbound HTTPS access. The tool fetches the npm package page. No API key is needed.
2. Install and start the server:
   ```
   git clone https://github.com/cdugo/package-documentation-mcp
   cd package-documentation-mcp && git checkout 9f8ac082cdf8a7d78b92b4df33b0bc6ddda6bd57
   npm install && npm run build
   node build/index.js
   ```
3. Call the tool with these arguments:
   ```json
   {"packageName": "<b>tofu-poc{{7*7}}", "languages": ["javascript", "<i>tofu-lang</i>"]}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   ARGS = {"packageName": "<b>tofu-poc{{7*7}}", "languages": ["javascript", "<i>tofu-lang</i>"]}

   async def main():
       server = StdioServerParameters(command="node", args=["build/index.js"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("fetch-multilingual-docs", ARGS)
               print(result)

   asyncio.run(main())
   ```
4. What to observe: the result starts with `## Documentation Search Results for '<b>tofu-poc{{7*7}}'` and contains `✅ **<i>tofu-lang</i>**: Successfully fetched documentation from https://www.npmjs.com/package/<b>tofu-poc{{7*7}}`. The appended document repeats the name in its heading and `Library Name:` line.

## Expected behavior
`languages` should be limited to the supported registry keys, for example with `z.enum([...])`, and `packageName` should be validated or URL-encoded. Values written into the Markdown should be escaped or put in inline code.

## Actual behavior
Both values are reflected verbatim. From the fuzzing run (trimmed):

```
## Documentation Search Results for '{{"p\x1f...\x1fme": "oetc/pa[swd\\u0000", "langua'

✅ **es": ["buby\x1c...m"pack", "aphp"]**: Successfully fetched documentation from https://www.npmjs.com/package/{{"p\x1f...", "langua
✅ ****: Successfully fetched documentation from https://www.npmjs.com/package/{{"p\x1f...", "langua
...
# Documentation Content (from es": ["buby\x1c...m"pack", "aphp"] repository)
```

The run passed a free-text "language" and four empty strings. All were accepted and treated as npm.

## Impact
The LLM picks the tool arguments, and prompt injection in untrusted content can steer them. The output is Markdown, so clients that render Markdown, and possibly inline HTML, will render caller-chosen markup in the summary. Line breaks in either argument can also add headings or instructions to the text handed back to the model. The attacker already influences the call, so the severity is low.

## Suggested fix
- Declare `languages` as `z.array(z.enum([...supported keys])).max(10)` and drop duplicates. The cap also limits how many crawls one call can start.
- Validate `packageName` against registry naming rules, or encode it with `encodeURIComponent` when building URLs.
- Escape `packageName`, `language` and URLs before writing them into the Markdown, or wrap them in inline code.

## Status on the default branch
Still present at `9f8ac08` (2025-03-13). The tested commit is the head of the default branch.

## Prior reports
None found. Searched all 0 issues and 2 pull requests (fetched 2026-10-01) and the README / docs on the default branch.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: reflected-xss via `check_reflected_output`; `check_invalid_json` fired on the same inputs. `check_resource_exhaustion` also triggered for this tool (not part of this draft; plausible cause is the unbounded `languages` array, each entry starting a crawl of up to 5 pages).
- Campaigns and executions: repo24-b, 3 runs of 4,200 s: 80,896/21,702, 86,528/21,380, 78,336/17,922 (exec/ok).
- Evidence (verbatim, trimmed): input `{'packageName': '{{"p\x1f\x1c\x14\x1e\x18\x1a1\x16"p\x1fme": "oetc/pa[swd\\u0000", "langua', 'languages': ['es": ["buby\x1c\x14\x1e\x18\x1a1\x16m"pack", "aphp"]', '', '', '', '']}` -> `## Documentation Search Results for '{{"p...` then `✅ **es": ["buby...m"pack", "aphp"]**: Successfully fetched documentation from https://www.npmjs.com/package/{{"p...`. Two more inputs differ by one character.
- Hand-check hints: weak. Reflection into Markdown output is real and visible in the log, but only `{{` was flagged and the attacker is the caller. The `<b>`/`<i>` reproduction follows from the code and was not run. The second language in the repro hits the same npm URL, so `CacheService` serves it from cache; the reflection does not depend on that.
</details>
