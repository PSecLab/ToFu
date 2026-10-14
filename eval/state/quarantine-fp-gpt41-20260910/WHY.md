# Why this is here

The six alert-bearing runs of the gpt-4.1 arm (2026-09-10 16:14-16:48).
761 raw alerts, 4 distinct signatures. ALL false positives or known noise.
Kept because they are the evidence.

## check_path_traversal -- 426 alerts, bhouston/mcp-server-text-editor

The tool REFUSED every one of them, in a normal MCP result:

    {"success":false,"message":"File not found: /etc/passwd..."}
    {"success":false,"message":"Path must be absolute"}
    {"success":false,"message":"new_str parameter is required for insert command"}
    {"success":false,"message":"ENOENT: no such file or directory, mkdir '/repo'"}

No isError, no top-level error -- a structured refusal buried inside
content[].text, which the oracle could not read, so it recorded a validation
bypass on a tool that was validating correctly. FIXED (bug 18): _inband_error
now parses a content block's JSON and treats an explicit `"success": false`
(or its own `error`) as a failed execution. Prose is still not guessed at.

## check_invalid_json -- 313 alerts, sequential-thinking

NOT a tool defect: a SELECTION error, and a usable RQ2 datum. gpt-4.1 chose
check_invalid_json for `thought`, a FREE-TEXT field. The sanitizer fires
whenever the mutated text contains "{" and does not parse, which for free text
is meaningless. The tool accepted the input and returned a normal result.
Record this as sanitizer-selection precision, not as a finding.

## check_process_and_fd_leaks -- 4 tools (nazmul.todo item 40)

"Process leak/leftover detected: PID 38747 (node)" while TWO workers were
running. Almost certainly the other worker's MCP server. The ancestor filter in
_execute_and_time is not excluding it. UNFIXED.

## check_resource_exhaustion -- 4 tools (nazmul.todo item 39)

"Execution took 5.01 seconds (Limit: 2.0s)" on tools that make outbound HTTPS
calls to the National Park Service API. A 5s network fetch is normal. The 2.0s
default is noise on any tool that talks to the network. UNFIXED -- the
threshold is a judgement call and belongs to Ananto.

## What the arm DID establish

9/9 tools executable, 9/9 llm_selection ok, 9/9 llm_seeds ok, zero harness
errors -- the first arm where every single run reached the target and the LLM
stage worked on every config. gpt-4.1's LLM tax is ~8s vs gemma4's ~270s.
