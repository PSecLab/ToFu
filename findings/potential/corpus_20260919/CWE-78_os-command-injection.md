# CWE-78 — OS Command Injection (7 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-19.** Each row is a ToFu oracle hit: an adversarial input tripped `os-command-injection` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| PhialsBasement/CMD-MCP-Server | `execute_command` | node | 1.000 | 08a3492dd9 | check_blocked_command_bypass,check_process_and_fd_leaks | PhialsBasement__CMD-MCP-Server__execute_command.log |
| bigcodegen/mcp-neovim-server | `vim_command` | node | 1.000 | 9076bbb34a | check_blocked_command_bypass,check_command_injection | bigcodegen__mcp-neovim-server__vim_command.log |
| joshrutkowski/applescript-mcp | `iterm_run` | node | 1.000 | e6f4c2ee7d | check_blocked_command_bypass | joshrutkowski__applescript-mcp__iterm_run.log |
| apvlv/davinci-resolve-mcp | `execute_lua` | python | 0.963 | d025e4ecaf | check_blocked_command_bypass | apvlv__davinci-resolve-mcp__execute_lua.log |
| nickgnd/tmux-mcp | `execute-command` | node | 0.062 | ec68b1061c | check_blocked_command_bypass | nickgnd__tmux-mcp__execute-command.log |
| g0t4/mcp-server-commands | `run_process` | node | 0.009 | bc62283f43 | check_blocked_command_bypass | g0t4__mcp-server-commands__run_process.log |
| weidwonder/terminal-mcp-server | `execute_command` | node | 0.000 | c09db33e0c | check_blocked_command_bypass | weidwonder__terminal-mcp-server__execute_command.log |
