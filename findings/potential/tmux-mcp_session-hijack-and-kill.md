# tmux-mcp — arbitrary tmux session/window/pane control incl. kill (CWE-284 / CWE-732, host takeover)

- **Project**: nickgnd/tmux-mcp
- **Tools**: `kill-session`, `kill-window`, `kill-pane`, `create-session`, `split-pane`, `execute-command`, `capture-pane`, `list-sessions`, …
- **Class**: unrestricted control of the host's tmux server — no scoping to an owned session
- **Status**: POTENTIAL, **DEMONSTRATED LIVE**
- **Severity**: High — an MCP client (or adversarial content steering one) can kill, read, or inject commands into ANY of the operator's terminal sessions

## Summary
tmux-mcp drives the tmux server reachable via the process's `$TMUX` / default
socket, with no restriction to a session it created. `kill-session`/`kill-server`
tear down the operator's terminals; `execute-command` + `capture-pane` run
commands in and exfiltrate output from other panes; `send-keys`-style tools can
inject into a shell the user is actively using.

## How we know it's real (not a static guess)
On 2026-09-18 this tool **killed the ToFu campaign's own tmux session** during
fuzzing. ToFu ran the target with the harness's `$TMUX` inherited, so the
target's tmux operations (`kill-session`/`execute-command`) hit the *same* tmux
server the multi-hour `run_set_e2` campaign was running in — the session
vanished "out of nowhere" and the run died. Runtime proof of unscoped control:
the tool did exactly what the class predicts, against the operator's own
sessions, from fuzz input alone.

## Why this matters for MCP
A terminal-manager MCP with no session scoping is a host-takeover primitive for
any agent that can be steered by untrusted content: read other terminals
(secrets on screen), inject commands, or kill the user's work. Same shape as
UltimateCoderMCP (arbitrary FS delete) and mcp-python-interpreter (unsandboxed
exec) — a powerful local capability exposed as an unauthenticated tool.

## Suggested fix (maintainer)
Scope every operation to sessions the server itself created (namespaced prefix);
refuse `kill-server` and operations on foreign sessions; require explicit opt-in
for `execute-command`/`capture-pane` against existing panes.

## Note for ToFu (item 91, env isolation)
run_eval now scrubs `$TMUX`/`TMUX_PANE` and sets `TMUX_TMPDIR` to the per-config
scratch, so a fuzzed tmux target lands on an isolated socket, never the
operator's. cwd isolation (files) + env isolation (tmux) both needed; a full
sandbox is the general fix.
