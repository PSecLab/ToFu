# Log injection in `sequentialthinking`: CR/LF in `thought` forges lines in `sequential_thinking.log`

**Repository:** `FradSer/mcp-server-mas-sequential-thinking` · **Tool:** `sequentialthinking` · **Tested commit:** `f1a20b3`
**Weakness:** CWE-117 Improper Output Neutralization for Logs

## Summary
`sequentialthinking` logs the caller's `thought` text verbatim at INFO level before it calls any model. The log goes to stderr and to the rotating file `~/.sequential_thinking/logs/sequential_thinking.log`. A thought containing CR/LF ends the current record and starts a new line that looks like a real log entry, with the attacker's chosen timestamp, level and message. The tool path does not apply `sanitize_and_validate_input`, which the prompt handler uses.

## Details
`process_thought` logs context before running the workflow (`src/mcp_server_mas_sequential_thinking/services/server_core.py:416-423`), and `log_context_building` writes the raw thought (`src/mcp_server_mas_sequential_thinking/services/context_builder.py:107-110`):

```python
        logger.info("  Session thoughts: %d total", len(self._session.thought_history))
        logger.info("  Input thought: %s", thought_data.thought)
        logger.info("  Built prompt length: %d chars", len(input_prompt))
        logger.info("  Built prompt:\n%s", input_prompt)
```

The built prompt also embeds the thought unchanged (`context_builder.py:40`). The logger has a stderr handler and a file handler (`src/mcp_server_mas_sequential_thinking/infrastructure/logging_config.py:47-69`):

```python
    file_formatter = logging.Formatter(
        "%(asctime)s - %(name)s - %(levelname)s - %(funcName)s:%(lineno)d - %(message)s"
    )
```

Before this point, the tool only checks the size of `thought` (`main.py:574`, `security/rate_limiter.py:286-310`) and builds a pydantic model (`services/server_core.py:497-520`); neither changes control characters. Other places log the first 100 characters of the thought the same way (`processors/multi_thinking_processor.py:172`, `routing/multi_thinking_router.py:85`, `routing/ai_complexity_analyzer.py:138`).

## Steps to reproduce
1. Prerequisites: Python 3.10+, `uv`. Set `LLM_PROVIDER=ollama`, which needs no API key. By code reading, the log line is written before any model call, so Ollama does not have to answer.
2. Install as the README describes: `git clone https://github.com/FradSer/mcp-server-mas-sequential-thinking.git && cd mcp-server-mas-sequential-thinking && git checkout f1a20b3 && uv pip install .` The entry point is `mcp-server-mas-sequential-thinking`.
3. Call the tool with `{"thought": "tofu-poc step\r\n00:00:00 - sequential_thinking - ERROR - main:1 - FAKE-LOG-ENTRY", "thoughtNumber": 1, "totalThoughts": 1, "nextThoughtNeeded": false, "isRevision": false, "branchFromThought": null, "branchId": null, "needsMoreThoughts": false}`:

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(command="mcp-server-mas-sequential-thinking", args=[], env={"LLM_PROVIDER": "ollama"})
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("sequentialthinking", {
                   "thought": "tofu-poc step\r\n00:00:00 - sequential_thinking - ERROR - main:1 - FAKE-LOG-ENTRY",
                   "thoughtNumber": 1, "totalThoughts": 1, "nextThoughtNeeded": False, "isRevision": False,
                   "branchFromThought": None, "branchId": None, "needsMoreThoughts": False})
               print(result)

   asyncio.run(main())
   ```
4. Open `~/.sequential_thinking/logs/sequential_thinking.log`. After the record ending in `  Input thought: tofu-poc step`, there is a separate line `00:00:00 - sequential_thinking - ERROR - main:1 - FAKE-LOG-ENTRY` that the server never logged. The same appears in stderr.

## Expected behavior
Caller text is escaped (for example with `%r`) or has CR/LF replaced before logging, so each record stays on one line.

## Actual behavior
The forged line lands in the log file as its own entry. The fuzzing run recorded a related, weaker case: pydantic validation errors are logged as multi-line records, for example:

```
Input validation failed for thought #3: Invalid thought data: 1 validation error for ThoughtData\n  Value error, branchFromThought must be less than current thoughtNumber [type=value_error, input_value={'thought': '/etc/passwd\...edsMoreThoughts': False}, input_type=dict]\n    For further information visit https://errors.pydantic.dev/2.13/v/value_error
```

Those newlines come from pydantic's formatting (the caller value is `repr()`'d), so on their own they are not injection.

## Impact
`thought` is written by the LLM and is the main free-text field of this tool, so prompt injection from any content the agent reads can place CR/LF in it. An attacker can add fake entries to the persistent log file, for example a forged error or success line, which misleads anyone reviewing the log or any tool that parses it. No code execution or data access follows from this alone. Low to moderate.

## Suggested fix
Log the thought with `%r`, or strip `\r` and `\n` before logging (`thought_data.thought.replace("\r", "\\r").replace("\n", "\\n")`). A `logging.Formatter` subclass that escapes control characters in `record.getMessage()` would cover all call sites at once. Logging full thoughts and prompts at INFO also puts user content into a persistent file, so consider moving those lines to DEBUG.

## Status on the default branch
Still present at `f1a20b3` (2026-08-05). The default branch has no commits after the tested commit.

## Prior reports
- #31 "feat: implement multi-thinking architecture with enhanced security" (PR, merged/closed 2025-09-24): the hardening PR that added "Prompt Injection Protection: Comprehensive input sanitization" and "Unified Logging ... with sensitive data filtering". It does not mention CR/LF in log records, and the tool path still logs the raw thought at the tested commit, so it does not fix this.
- #15 "API Key Exposure in Error Logs" (issue, closed 2026-03-13): a different logging problem (API keys in exception logs), not log injection.
- No other related issue or PR among the 26 issues and 45 pull requests (fetched 2026-10-01); the rest are feature work and dependency bumps.
- Documentation: `CLAUDE.md` (in the repository) lists "Comprehensive input sanitization with HTML escaping" under "Security & Rate Limiting" and points to `~/.sequential_thinking/logs/sequential_thinking.log` for live logs. That sanitizing is not applied on the `sequentialthinking` tool path, as described above. The README says nothing about log contents.

<details>
<summary>Internal notes (remove before filing)</summary>

- ToFu class / sanitizers: log-injection via `check_introspection_log_injection` (fires on any `\n`/`\r` in a captured log record). Also triggered: `check_introspection_weak_hash` (not part of this claim).
- Campaigns and executions: `corpus-sbx` 3,072 execs / 5 success (60 s); `e2-0922` 1,024 / 13.
- Evidence (verbatim, trimmed): input `{'thought': '/etc/passwd\x00', 'thoughtNumber': 3, 'totalThoughts': 3, 'nextThoughtNeeded': False, 'isRevision': False, 'branchFromThought': '3', 'branchId': 'B', 'needsMoreThoughts': False}`, output `None`, logged `'Input validation failed for thought #3: Invalid thought data: 1 validation error for ThoughtData\n  Value error, branchFromThought must be less than current thoughtNumber [...]'` (from `main.py:653-654`).
- Hand-check hints: real by code reading, but not what ToFu observed. ToFu's three samples are all validation failures where the newline is pydantic's own formatting and the input is repr-truncated (weak on its own). The raw sink `context_builder.py:108` is reached only after validation passes, which no evidence sample did. Not run. Assumes `ENVIRONMENT` is not `production` for the stderr copy; the file handler is always on. Whether `LLM_PROVIDER=ollama` with no local Ollama lets the server start is from code reading of `server_core.py:138-172` (no network check found).
</details>
