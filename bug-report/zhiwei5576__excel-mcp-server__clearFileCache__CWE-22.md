# `clearFileCache` accepts traversal-style paths but performs no file access (CWE-22 not confirmed)

**Repository:** `zhiwei5576/excel-mcp-server` · **Tool:** `clearFileCache` · **Tested commit:** `cf0e7c9`
**Weakness:** CWE-22 Path Traversal

## Summary
A fuzzer flagged `clearFileCache` because it accepts values such as `../../../../etc/passwd` and returns success. Reading the code, the tool only removes a key from an in-memory `Map`; it never opens, reads, writes or deletes a file. A traversal path can at most clear the cache entry stored under that exact string. I do not consider this a vulnerability; at most, the tool could reject paths that are not absolute, as its parameter description asks.

## Details
The handler normalizes the string and deletes a cache key (`src/tools/cacheTools.ts:9-36`):

```ts
        async (params: { fileAbsolutePath: string }) => {
            try {
                const normalizedPath = await normalizePath(params.fileAbsolutePath);
                ...
                const deleted = workbookCache.delete(normalizedPath);

                return {
                    content: [{
                        type: "text",
                        text: JSON.stringify({
                            success: true,
                            message: deleted
                                ? `Cache cleared successfully for file: ${normalizedPath}`
                                : `No cache found for file: ${normalizedPath}`
```

`normalizePath` only round-trips the string through `encodeURIComponent`/`decodeURIComponent` and trims it (`src/utils/utils.ts:34-50`). `workbookCache.delete` is `Map.delete` (`src/utils/workbookCache.ts:66-69`). No filesystem API is called on this path.

## Steps to reproduce
1. Prerequisites: Node.js.
2. Start the server as the README describes: `npx --yes @zhiweixu/excel-mcp-server`
3. Call the tool with `{"fileAbsolutePath": "../../../../etc/hostname"}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["--yes", "@zhiweixu/excel-mcp-server"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("clearFileCache", {"fileAbsolutePath": "../../../../etc/hostname"})
               print(result)

   asyncio.run(main())
   ```
4. The tool returns `{"success":true,"message":"No cache found for file: ../../../../etc/hostname"}`. No file is touched.

## Expected behavior
Optionally, reject relative or non-Excel paths with a clear error, since the parameter is documented as an absolute Excel file path.

## Actual behavior
The tool reports success for any string. From the fuzzing run:

```
{"success":true,"message":"No cache found for file: ../../../../etc/passwd"}
```

## Impact
None found. The argument is LLM-chosen, but it only selects which in-memory cache entry to drop. The caller's string is echoed back in the result, which has no security effect here.

## Suggested fix
No security fix needed. For consistency, validate that `fileAbsolutePath` is absolute (`path.isAbsolute`) and ends in `.xlsx`/`.xls` before using it as a cache key.

## Status on the default branch
Unchanged at `cf0e7c9` (2025-04-10). The default branch has no commits after the tested commit.

## Prior reports
- Documentation: README.md, "Cache Tools": `clearFileCache` will "Clear cached data for the specified Excel file", with `fileAbsolutePath`: "Absolute path of the Excel file to clear from cache". This matches the code: the argument is a cache key, not a file to open. Nothing documents rejection of relative paths.
- No issue or PR reports this. Searched all 4 issues and the 1 pull request (fetched 2026-10-01); #5 (file not found in Cherry Studio) and #3 ("Unknown tool" on Windows) are unrelated usage bugs.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal` (input pattern check on `../`, `/etc/passwd`, `windows\win.ini`; "Silent Bug Alert").
- Campaigns and executions: `corpus-sbx` 2,560 execs / 2,556 success (60 s); `e2-0922` 512 / 508.
- Evidence (verbatim, trimmed): input `{'fileAbsolutePath': '../../../../etc/passwd'}`, output `{'content': [{'type': 'text', 'text': '{"success":true,"message":"No cache found for file: ../../../../etc/passwd"}'}]}`. Same for `/etc/passwd\x00` and `..\\..\\..\\..\\windows\\win.ini`.
- Hand-check hints: weak, a false positive. The tool's only sink is `Map.delete`. Recommend not filing. Other tools in this server (read/write tools) take absolute paths by design and were not part of this item; if a path-traversal issue is filed for this repo, it belongs on those tools, after checking them.
</details>
