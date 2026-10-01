# Path traversal in `set_memory_bank_path`: `path` can re-point the session to a memory bank outside the project

**Repository:** `movibe/memory-bank-mcp` · **Tool:** `set_memory_bank_path` · **Tested commit:** `7851e06`
**Weakness:** CWE-22 Path Traversal

## Summary
`set_memory_bank_path` switches the active memory bank to `<path>/memory-bank` when that directory exists and holds at least one core file. The `path` argument accepts absolute paths and `../` segments and is not limited to the project directory the server was started with (`--path` or the working directory). After the call, every read and write tool works on the other directory. A second, smaller problem: when no memory bank is found at the new path, the tool still reports `Memory Bank path set to <previous directory>`, which reads as success.

## Details
`src/server/tools/CoreTools.ts:141-157`:

```ts
const basePath = customPath || memoryBankManager.getProjectPath();
const absolutePath = path.isAbsolute(basePath) ? basePath : path.resolve(process.cwd(), basePath);
await memoryBankManager.setCustomPath(absolutePath);
const memoryBankDir = memoryBankManager.getMemoryBankDir();
if (memoryBankDir) {
  return { content: [{ type: 'text', text: `Memory Bank path set to ${memoryBankDir}` }] };
}
```

`setCustomPath` (`src/core/MemoryBankManager.ts:421-441`) joins the folder name onto `basePath` and, if `isMemoryBank` finds any core file there (`MemoryBankManager.ts:137-176`), calls `setMemoryBankDir`. There is no check that `absolutePath` is under the project path. If no memory bank is found, `memoryBankDir` is left unchanged, so the handler's `if (memoryBankDir)` branch returns the old directory as if the switch worked.

## Steps to reproduce
1. Prerequisites: Node.js 18+ and Python with the `mcp` package. Create a project directory and, next to it, a memory bank with a marker file:
   ```bash
   mkdir -p /tmp/tofu-poc/project /tmp/tofu-poc/memory-bank
   echo marker > /tmp/tofu-poc/memory-bank/progress.md
   ```
2. Start the server as the README describes (`npx @movibe/memory-bank-mcp`; the tested commit is the 0.4.1 release commit), with `/tmp/tofu-poc/project` as the working directory. From a source checkout: `bun install && bun run build`, then `node build/index.js`.
3. Re-point the session with `{"path": ".."}` and read the marker:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="npx",
           args=["-y", "@movibe/memory-bank-mcp@0.4.1", "--path", "/tmp/tofu-poc/project"],
           cwd="/tmp/tofu-poc/project",
       )
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               print(await session.call_tool("set_memory_bank_path", {"path": ".."}))
               print(await session.call_tool("read_memory_bank_file", {"filename": "progress.md"}))

   asyncio.run(main())
   ```
4. Observe: the first result is `Memory Bank path set to /tmp/tofu-poc/memory-bank` and the second returns `marker`. All later file tools now act on `/tmp/tofu-poc/memory-bank`, outside the project.

## Expected behavior
The tool only accepts a `path` inside the configured project directory, and it reports an error when no memory bank exists at the requested path.

## Actual behavior
Any directory on disk that contains a `memory-bank/` folder with a core file is accepted, including through `../`. When the requested path has no memory bank, the reply is `Memory Bank path set to <old directory>`. During fuzzing, a `../../../../` path with no memory bank behind it returned:

```
Memory Bank path set to <working directory>/memory-bank
```

which is the previous directory, not the requested one (working directory redacted).

## Impact
In MCP the model chooses tool arguments and can be steered by prompt injection. A steered call can move the session onto another project's memory bank, after which `read_memory_bank_file` returns its notes and `write_memory_bank_file` / `track_progress` change them. The target must already contain a `memory-bank/` folder with a core file, which limits the reach. The misleading success message can hide that the switch did not happen.

## Suggested fix
- Resolve `path` against the configured project path and reject it when `path.relative(projectRoot, resolved)` starts with `..` or is absolute. If switching to arbitrary directories is an intended feature, gate it behind a startup flag rather than a tool argument.
- Return an error (with `isError: true`) when `setCustomPath` did not find a memory bank, instead of echoing the previous `memoryBankDir`.

## Status on the default branch
Still present at `7851e06` (2025-03-17). The default branch has no commits after the tested one.

## Prior reports
- No issue or PR reports this. Searched all 1 issue and 9 pull requests (fetched 2026-10-01); none mentions `set_memory_bank_path`, path validation, traversal or the misleading success message.
- Documentation: docs/memory-bank-path-changes.md: "Absolute paths are used as-is." with the example `set_memory_bank_path path=/path/to/custom/memory-bank` (switching to an arbitrary directory is documented as intended, so the out-of-project part is by design; the false success reply is not documented).
- Documentation: docs/mcp-protocol-specification.md: "Sets a custom path for the Memory Bank" (same: documented purpose).

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: path-traversal; `check_path_traversal`.
- Campaigns and executions: corpus-sbx 1024 exec / 989 success; e2-0922 512 / 503.
- Evidence (verbatim, trimmed):
  - `{'path': '../../../../etc/passwd'}` -> `Memory Bank path set to /home/mza6485/toolfuzzer/eval/targets/movibe__memory-bank-mcp/memory-bank` (unchanged previous dir).
  - `{'path': '/etc/passwd\x00'}` -> same unchanged previous dir.
  - `{'path': '..\\..\\..\\..\\windows\\win.ini'}` -> `Memory Bank path set to /home/mza6485/toolfuzzer/eval/targets/movibe__memory-bank-mcp/..\\..\\..\\..\\windows\\win.ini/memory-bank`. On Linux the backslashes are literal characters; this directory was created inside the target dir by an earlier fuzzed `initialize_memory_bank` call. Not a real escape.
- Hand-check hints: weak. None of the three logged calls escaped anything: two left the old directory in place and one matched a directory the fuzzer itself created. The out-of-project switch is shown from code only. Choosing a custom path is the tool's stated purpose ("Set a custom path for the Memory Bank"), so the maintainer may see this as by design; the misleading success message is the clearer bug. Not run.
</details>
