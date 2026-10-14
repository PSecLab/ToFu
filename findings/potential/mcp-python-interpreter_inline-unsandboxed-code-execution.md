# V7 (potential) — yzfly/mcp-python-interpreter: `run_python_code` (inline, default) executes attacker-supplied Python in-process, unsandboxed (CWE-94 / RCE-equivalent)

**Status: POTENTIAL** — "dangerous by design," but a textbook accident-waiting:
an MCP tool that runs arbitrary Python with no isolation is RCE for any agent
that can be steered by untrusted content. Filing so MCP clients and the
maintainer treat it as such.

| | |
|---|---|
| repo | yzfly/mcp-python-interpreter |
| commit | pinned (see eval/state) |
| tools | `run_python_code` (default `execution_mode="inline"`), `run_python_file`, `install_package` |
| weakness | CWE-94 code injection / arbitrary code execution; in-process, no sandbox |
| run | VM (Linux, py3.13), gpt-4.1, `eval/runs/gpt41-vm/yzfly__mcp-python-interpreter__run_python_code.log` |

## Evidence (traceable)
```
Faulty Input: {'code': "with open('../../../../etc/passwd','r') as f: print(f.read())", 'execution_mode':'inline', ...}
Tool Output : "Execution in session 'default' (inline mode):\n--- Output ---\nroot:x:0:0:root:/root:/bin/bash\n..."
```
The tool ran the submitted code and returned `/etc/passwd`. A write attempt
(`open('/etc/passwd','w')…`) failed only because the OS denied it, not the tool.

## Source (local: eval/sandbox/targets)
`mcp_python_interpreter/server.py`: `execution_mode` defaults to `"inline"`;
inline runs `exec(code, self.locals)` **in the MCP server process** (subprocess
mode exists but is not the default). No seccomp/namespace/allowlist. So a caller
who controls `code` gets: arbitrary file read/write within process permissions,
the server's environment (and thus any API keys it holds — cf. bug 23 / V4's
`/proc/self/environ`), network, and code execution.

## Why potential (not "confirmed bug")
Executing Python is the tool's advertised function; the maintainer may consider
this working as intended. The reportable, non-obvious risk is that **inline (the
default) is in-process and unsandboxed**, so the blast radius is the whole MCP
host, and an LLM agent processing untrusted input is a realistic trigger. This
is the V3-class framing (a capability that is safe only until it isn't).

## Disclosure
Recommend: default to `subprocess` mode; drop privileges / use a sandbox
(seccomp, nsjail, or a container) for both modes; scrub server credentials from
the child env. For MCP clients: gate this tool behind explicit human approval
and never expose it to an agent handling untrusted content.

## Contrast (same arm)
The same server's `read_file`/`write_file` ARE jailed to `WORKING_DIR` — the
maintainer knows how to sandbox file access but does not sandbox code execution.
