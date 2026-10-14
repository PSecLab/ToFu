# Possible log injection in `vim_grep`: `pattern` with CR/LF can reach stderr error logs

**Repository:** `bigcodegen/mcp-neovim-server` · **Tool:** `vim_grep` · **Tested commit:** `9076bbb`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`vim_grep` runs a project-wide `vimgrep` using a caller-supplied `pattern`. On a Neovim error the pattern is included in an error that is written to stderr via `console.error`, unneutralized. Caller-controlled CR/LF could therefore split or spoof log lines. The captured evidence does not actually reach the logging path (the fuzzer sent an empty-after-trim pattern, which is rejected before any logging), so this is a low-confidence, by-inspection finding.

## Details
The tool passes `pattern` to `grepInProject` (`src/index.ts:437-446`). There (`src/neovim.ts:706-734`):

```ts
public async grepInProject(pattern: string, filePattern = '**/*'): Promise<string> {
  if (!pattern || pattern.trim().length === 0) {
    throw new NeovimValidationError('Grep pattern cannot be empty');
  }
  const command = `vimgrep /${pattern}/ ${filePattern}`;
  await nvim.command(command);
  ...
  } catch (error) {
    console.error('Error in grep:', error);               // error carries `grep ${pattern}`
    throw new NeovimCommandError(`grep ${pattern}`, ...);
  }
}
```

When `nvim.command` fails, `error` (and the thrown `NeovimCommandError`, whose message embeds the raw `pattern`) is written to stderr by `console.error` with no CR/LF stripping.

## Steps to reproduce
1. Prerequisites: Neovim running with a listening socket (`nvim --listen /tmp/nvim`), server started:
   ```json
   { "command": "npx", "args": ["-y", "mcp-neovim-server"], "env": { "NVIM_SOCKET_PATH": "/tmp/nvim" } }
   ```
2. Call the tool with a non-empty pattern that both forces a `vimgrep` error and carries CR/LF. Arguments as JSON:
   ```json
   {"pattern": "a\r\nFAKE-LOG-ENTRY", "filePattern": "**/*"}
   ```
   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="npx", args=["-y", "mcp-neovim-server"],
                                      env={"NVIM_SOCKET_PATH": "/tmp/nvim"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("vim_grep", {"pattern": "a\r\nFAKE-LOG-ENTRY", "filePattern": "**/*"})
               print(result)

   asyncio.run(main())
   ```
3. Inspect the server's stderr. If the `vimgrep` call errors, the `console.error('Error in grep:', ...)` line contains the injected `\r\nFAKE-LOG-ENTRY`, appearing as a separate log line.

## Expected behavior
Caller input written to logs should have CR/LF stripped or escaped so it cannot forge log entries.

## Actual behavior
In the fuzz evidence the pattern was a bare newline, which trims to empty and is rejected before any logging:

```
Grep pattern cannot be empty
```

So the captured run did not demonstrate injection; the logging path is reached only when a non-empty pattern causes a `vimgrep` error.

## Impact
MCP tool arguments are LLM-controlled and steerable by prompt injection. If an attacker's pattern reaches the error log, injected CR/LF can forge or corrupt log lines on stderr. Severity is low: it requires the grep to error, and the sink is process stderr rather than a structured audit log.

## Suggested fix
Strip or escape CR/LF (and other control characters) from `pattern` before including it in any logged message or thrown error.

## Status on the default branch
Still present at `9076bbb` (2025-09-13). The tested commit is the current `refs/remotes/origin/latest` head.

## Prior reports
None found. Searched all 9 issues and 15 pull requests (fetched 2026-10-01) and the README / docs on the default branch. 11 of the 15 pull requests have an empty description.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection (CWE-117); triggered `check_log_injection`. Campaigns: corpus-sbx (1/1), e2-0922 (512/361). Single evidence item.
- Evidence (verbatim, trimmed): input `{'pattern': '\n', 'filePattern': ''}` → `Grep pattern cannot be empty`. The `\n` trims to empty and never reaches logging — this fired alert is effectively a false positive for the captured input.
- Hand-check hints: WEAK / low confidence. The actual log-injection path (console.error / NeovimCommandError embedding raw `pattern` on a vimgrep failure) is real by inspection but was NOT exercised by the evidence, and the sink is stderr, not a log file. Could not verify an injected line. Report as low severity, by-inspection.
</details>
