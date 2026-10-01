# Path traversal in `markdown_to_mindmap`: `inputPath` reads any file the server can access

**Repository:** `jinzcdev/markmap-mcp-server` · **Tool:** `markdown_to_mindmap` · **Tested commit:** `13d8751`
**Weakness:** CWE-22 Path Traversal

## Summary
When `markdown` is omitted, `markdown_to_mindmap` reads `inputPath` with `fs.readFile` and no check on location or extension. The file's text is embedded in the generated HTML, which is saved in the output directory and can be read back with `get_mindmap`, or is returned inline with `--return-mode content|both`. So any file readable by the server process, not only `.md` files, can be pulled into the agent's context. `get_mindmap` already confines paths to the output directory; `inputPath` has no equivalent check.

## Details
The handler reads the caller's path directly (`src/mcp/tools/markmap-tools.ts:237-253`):

```ts
                    if (!markdown && !inputPath) {
                        // ... returns an isError result
                    }

                    const content =
                        markdown ??
                        (await fs.readFile(inputPath as string, "utf8"));
```

The content is converted and written into the HTML file, including a verbatim copy in a hidden `<textarea>` (`src/markmap/createMarkmap.ts:283` and `:358`). `get_mindmap` returns that HTML as text when it is under 200 KB (`markmap-tools.ts:400-410`). Compare the containment check that `get_mindmap` does have (`src/markmap/lifecycle.ts:97-107`):

```ts
    const resolvedOutput = resolve(outputDir);
    const resolvedPath = resolve(filePath);

    if (
        !resolvedPath.startsWith(resolvedOutput + "/") &&
        resolvedPath !== resolvedOutput
    ) {
        throw new Error(
            `Access denied: ${filePath} is outside the output directory`
        );
```

## Steps to reproduce
1. Prerequisites: Node.js. Linux for `/etc/hostname`; on macOS use any small text file you create.
2. Start the server as the README describes, with a throwaway output directory: `npx -y @jinzcdev/markmap-mcp-server --output /tmp/tofu-markmap`
3. Call `markdown_to_mindmap` with `{"inputPath": "/etc/hostname", "format": "html", "filename": "tofu-poc"}` (no `markdown` key), then read the result with `get_mindmap`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "@jinzcdev/markmap-mcp-server", "--output", "/tmp/tofu-markmap"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("markdown_to_mindmap", {"inputPath": "/etc/hostname", "format": "html", "filename": "tofu-poc"})
               print(result)
               result = await session.call_tool("get_mindmap", {"filePath": "/tmp/tofu-markmap/markmap-tofu-poc.html"})
               print(result)

   asyncio.run(main())
   ```
4. The first result lists `/tmp/tofu-markmap/markmap-tofu-poc.html`. The second result contains the HTML, and the machine's hostname appears inside `<textarea id="original-markdown">` and in the mind map data. A relative path such as `../../../../etc/hostname` works the same way, resolved against the server's working directory.

## Expected behavior
`inputPath` is resolved and rejected unless it is inside an allowed directory (and, per the tool description, is a `.md` file).

## Actual behavior
Any readable file is accepted. In the fuzzing run the tool accepted `inputPath: '../../../../etc/passwd'` and wrote an output file:

```
{"htmlFilePath":"/home/<user>/.markmap-mcp/markmap-passwd-leak.html","filePath":"/home/<user>/.markmap-mcp/markmap-passwd-leak.html"}
```

In that run `markdown` was `""`, so `??` kept the empty string and the file was not actually read. The read happens when `markdown` is absent, as in the steps above.

## Impact
`inputPath` is chosen by the LLM and can be steered by prompt injection from content the agent processes. An attacker can have the agent read files such as `~/.ssh/config`, `~/.aws/credentials` or project `.env` files into a mind map and then into the conversation, where other tools can send them elsewhere. The copy also stays in the output directory (default `~/.markmap-mcp`) until cleanup. The tool is meant to read local Markdown, so the problem is the missing root and type restriction, not file reading itself. Moderate.

## Suggested fix
Resolve `inputPath` with `fs.realpath` and reject it unless it is under a configured input root (for example a new `--input-dir`/env option, defaulting to the working directory), using the same check as `getMindmap`. Also require a `.md`/`.markdown` extension. Optionally treat `markdown: ""` as absent, so the `!markdown` check and the `??` fallback agree.

## Status on the default branch
Still present at `13d8751` (2026-08-04). The default branch has no commits after the tested commit.

## Prior reports
- No issue or PR reports this. Searched the 1 issue and 6 pull requests (fetched 2026-10-01); the others are badge, deployment and HTTPS-support items.
- #9 "feat: upgrade MCP tools with ACI design, lifecycle APIs, and tri-state open mode" (PR, closed 2026-08-04): added `get_mindmap` and the lifecycle APIs, where the output-directory check lives. The body does not mention `inputPath`, and `inputPath` is still read unchecked on the default branch.
- Documentation: README.md documents `inputPath` as "Absolute path to a local `.md` file" (README_zh-CN.md says the same). So absolute paths are intended input, but the `.md` restriction is only stated, not enforced.
- Documentation: README.md says of `get_mindmap`: "Path must stay inside the configured output directory (path traversal denied)." AGENTS.md also says `get_mindmap` has "path traversal protection". Nothing documents an equivalent limit for `inputPath`.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal via `check_path_traversal` (input pattern check, "Silent Bug Alert").
- Campaigns and executions: `e2-0922`, 1 exec, 0 success, 60 s budget.
- Evidence (verbatim, trimmed): input `{'markdown': '', 'inputPath': '../../../../etc/passwd', 'format': 'html', 'filename': 'passwd-leak'}`, output `{'content': [{'type': 'text', 'text': '{"htmlFilePath":"/home/mza6485/.markmap-mcp/markmap-passwd-leak.html", ...}'}]}`. Third sample had non-empty `markdown`, so `inputPath` was ignored.
- Hand-check hints: real by code reading: `inputPath` reaches `fs.readFile` unchecked whenever `markdown` is undefined. But ToFu's evidence does not show a read: all samples passed `markdown` (`''` or text), and `''` short-circuits `??`. The output path in the public draft has the username replaced with `<user>`. Default `--return-mode` is `path` (`src/index.ts:112`), hence the two-step reproduction via `get_mindmap`. Not run.
</details>
