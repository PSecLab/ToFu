# CWE-404 — Improper Resource / FD Release (13 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-19.** Each row is a ToFu oracle hit: an adversarial input tripped `resource-fd-leak` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| Tisik79/MCP-Facebook | `connect_facebook_account` | node | 1.000 | 2ebfbc931b | check_process_and_fd_leaks | Tisik79__MCP-Facebook__connect_facebook_account.log |
| joshrutkowski/applescript-mcp | `mail_list_emails` | node | 1.000 | e6f4c2ee7d | check_process_and_fd_leaks | joshrutkowski__applescript-mcp__mail_list_emails.log |
| joshrutkowski/applescript-mcp | `pages_create_document` | node | 1.000 | e6f4c2ee7d | check_process_and_fd_leaks | joshrutkowski__applescript-mcp__pages_create_document.log |
| joshrutkowski/applescript-mcp | `shortcuts_run_shortcut` | node | 1.000 | e6f4c2ee7d | check_process_and_fd_leaks | joshrutkowski__applescript-mcp__shortcuts_run_shortcut.log |
| qpd-v/mcp-DEEPwebresearch | `parallel_search` | node | 1.000 | bdbbec656c | check_process_and_fd_leaks | qpd-v__mcp-DEEPwebresearch__parallel_search.log |
| PhialsBasement/CMD-MCP-Server | `execute_ssh_command` | node | 0.000 | 08a3492dd9 | check_process_and_fd_leaks,check_resource_exhaustion | PhialsBasement__CMD-MCP-Server__execute_ssh_command.log |
| ananddtyagi/webpage-screenshot-mcp | `screenshot-element` | node | 0.000 | cad4a14af1 | check_process_and_fd_leaks | ananddtyagi__webpage-screenshot-mcp__screenshot-element.log |
| crazyrabbitLTC/mcp-code-review-server | `analyze_repo` | node | 0.000 | ac4f281724 | check_process_and_fd_leaks | crazyrabbitLTC__mcp-code-review-server__analyze_repo.log |
| crazyrabbitLTC/mcp-code-review-server | `code_review` | node | 0.000 | ac4f281724 | check_process_and_fd_leaks | crazyrabbitLTC__mcp-code-review-server__code_review.log |
| hustcc/mcp-mermaid | `generate_mermaid_diagram` | node | 0.000 | 13497062a9 | check_process_and_fd_leaks | hustcc__mcp-mermaid__generate_mermaid_diagram.log |
| jatinsandilya/mcp-server-auto-commit | `git-changes-commit-message` | node | 0.000 | 36b2651d5e | check_process_and_fd_leaks | jatinsandilya__mcp-server-auto-commit__git-changes-commit-message.log |
| peng-shawn/mermaid-mcp-server | `generate` | node | 0.000 | 81dc507991 | check_process_and_fd_leaks,check_resource_exhaustion | peng-shawn__mermaid-mcp-server__generate.log |
| seanivore/mcp-file-preview | `preview_file` | node | 0.000 | ad300e12e8 | check_process_and_fd_leaks | seanivore__mcp-file-preview__preview_file.log |
