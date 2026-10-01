# Path traversal check for `output_dir` in `generate_uml_batch` (fuzzer report; containment appears to work)

**Repository:** `antoinebou12/uml-mcp` · **Tool:** `generate_uml_batch` · **Tested commit:** `e3c007d`
**Weakness:** CWE-22 Path Traversal

## Summary
`generate_uml_batch` renders several diagrams and can save them under a shared `output_dir`. Our fuzzer flagged calls whose `output_dir` was a `../` sequence, because the tool returned normally instead of raising. Reading the code, the value is resolved and checked against the configured output root before any write, and every flagged call reported its items as failed. We found no file written outside the root. This draft records the check. It is probably not a bug.

## Details
`mcp_core/tools/diagram_tools.py:145-185` (tested commit) validates each item together with the shared `output_dir`:

```python
validated = GenerateUMLInput.model_validate({**raw, "output_dir": output_dir})
```

`GenerateUMLInput.validate_output_location` (`mcp_core/tools/schemas.py:126-166`) resolves the path and rejects it unless it stays under `MCP_OUTPUT_ROOT` (default: `MCP_SETTINGS.output_dir`, which is `./output`):

```python
root = Path(root_raw).expanduser().resolve()
requested = Path(self.output_dir).expanduser()
if not requested.is_absolute():
    requested = (Path.cwd() / requested).resolve()
else:
    requested = requested.resolve()
try:
    requested.relative_to(root)
except ValueError as exc:
    raise ValueError(f"output_dir must stay under configured output root '{root}'. ...")
```

`generate_from_request` repeats the same validation (`mcp_core/core/diagram_service.py:118-133`), and `generate_diagram` applies a second sandbox in `_sanitize_output_dir` (`mcp_core/core/utils.py:111-154`). The check is skipped only when `MCP_ALLOW_ARBITRARY_OUTPUT_DIR` is true, or when that is unset and a generic `TESTING` variable is truthy (`schemas.py:143-146`).

## Steps to reproduce
1. Prerequisites: Python 3.12+, `uv`. Do not set `MCP_ALLOW_ARBITRARY_OUTPUT_DIR` or `TESTING`.
2. Install and start the server as the README describes:
   `git clone https://github.com/antoinebou12/uml-mcp.git && cd uml-mcp && git checkout e3c007d && uv sync`
3. Call the tool with:

   ```json
   {"items": [{"diagram_type": "mermaid", "code": "graph TD; A-->B;"}], "output_dir": "../../../../tmp/tofu-poc"}
   ```

   ```python
   import asyncio
   from mcp import ClientSession, StdioServerParameters
   from mcp.client.stdio import stdio_client

   async def main():
       server = StdioServerParameters(
           command="uv", args=["run", "--directory", "/path/to/uml-mcp", "python", "server.py"])
       async with stdio_client(server) as (read, write):
           async with ClientSession(read, write) as session:
               await session.initialize()
               result = await session.call_tool("generate_uml_batch", {
                   "items": [{"diagram_type": "mermaid", "code": "graph TD; A-->B;"}],
                   "output_dir": "../../../../tmp/tofu-poc",
               })
               print(result)

   asyncio.run(main())
   ```
4. Check whether `/tmp/tofu-poc` was created and whether the item result carries `output_dir must stay under configured output root ...`.

## Expected behavior
The item fails with the output-root error and nothing is written outside `./output`.

## Actual behavior
In our runs every flagged call returned a per-item failure, which matches the check above:

```
Processed 1 diagrams; 1 failed.
```

We did not observe a write outside the output root. Our harness did not keep the per-item error text, so we cannot confirm from the log which check rejected the call.

## Impact
None shown. `output_dir` is chosen by the LLM and can be steered by prompt injection, but the code rejects paths outside the root before writing. The only residual point is that the sandbox turns off when a generic `TESTING` environment variable is truthy, which a host could set for unrelated reasons.

## Suggested fix
No fix needed for the reported behavior. Optional hardening: drop the `TESTING` fallback in `validate_output_location` and require the explicit `MCP_ALLOW_ARBITRARY_OUTPUT_DIR=true` opt-out.

## Status on the default branch
Unchanged at `c598429` (2026-09-29). `mcp_core/tools/schemas.py` has no diff against the tested commit, and the same containment check is at `schemas.py:127-166`.

## Prior reports
- #316 "feat(mcp): harden result contracts, rendering, validation, and HTTP security" (PR, closed 2026-08-24): added "local output-path sandboxing via `MCP_OUTPUT_ROOT` with explicit trusted-development opt-out". This is the containment check this draft found working.
- #39 "feat: add MCP_READ_ONLY mode to disable file-writing tools" (PR, closed 2026-04-01): calls `output_dir` "a path traversal risk" and adds `MCP_READ_ONLY`, which drops `output_dir` entirely. Earlier mitigation of the same concern.
- #323 "test: repair three stale assertions against current runtime behavior" (PR, closed 2026-08-31): notes that `_sanitize_output_dir` now rejects an absolute path unless `MCP_ALLOW_ARBITRARY_OUTPUT_DIR` is set, which confirms the second sandbox.
- Documentation: ARCHITECTURE_AUDIT.md: "Output path sandbox added with MCP_OUTPUT_ROOT and MCP_ALLOW_ARBITRARY_OUTPUT_DIR"; docs/configuration.md: `MCP_READ_ONLY` "Reject `output_dir` and never write diagram files to disk"; docs/integrations/claude_desktop_mcpb.md: "the folder becomes the write sandbox" (all document the containment as intended behaviour).

<details>
<summary>Internal notes (remove before filing)</summary>

- DUPLICATE/FIXED CHECK: already guarded. PR #316 (2026-08-24) added the `MCP_OUTPUT_ROOT` sandbox that blocks this traversal, and #39 earlier added `MCP_READ_ONLY` for the same risk. Nothing to file.
- ToFu class / sanitizers: path-traversal (CWE-22), `check_path_traversal` via the "Silent Bug" rule: the input-side sanitizer flagged the argument and the tool did not raise. That rule only looks at the input. Also fired for this tool: `check_introspection_log_injection` (the `Called generate_uml_batch: count=%s, output_dir=%s` line at `diagram_tools.py:210-214` logs `output_dir` raw, same CWE-117 pattern as the other uml-mcp drafts) and `check_resource_exhaustion`.
- Campaigns and executions: corpus-sbx 2048 exec / 2017 ok (60 s); repo24-b 92672 / 90482 and 40448 / 39608 (4200 s each); e2-0922 1024 / 1004 (60 s).
- Evidence (verbatim, trimmed):
  - `{'items': [{'diagram_type': 'sequence', 'code': 'A -> B: Test'}], 'output_dir': '../../../../../../'}` -> `'Processed 1 diagrams; 1 failed.'`
  - `{'items': [{'diagram_type': 'component', 'code': '/etc/passwd\x00'}], 'output_dir': '../../../../../var/log'}` -> `'Processed 1 diagrams; 1 failed.'`
  - `{'items': [{}, {}, {}, {}, {}], 'output_dir': '"items": [{" "../../../../etc/pass'}` -> `'Processed 5 diagrams; 5 failed.'`
- Hand-check hints: weak, likely false positive. Recommend not filing. Every flagged call failed, and the code resolves and contains `output_dir` twice before writing. Not verified: whether the fuzz host had `TESTING` set (that would disable the check, but also would be a host config issue), and whether the failures came from the root check or from the render (the sandbox may have had no network). If anything, fold the `output_dir` log line into the combined uml-mcp log-injection issue.
</details>
