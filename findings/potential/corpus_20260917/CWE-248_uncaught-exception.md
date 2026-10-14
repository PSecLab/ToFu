# CWE-248 — Uncaught Exception / crash (5 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `uncaught-exception` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| alioshr/memory-bank-mcp | `list_project_files` | node | 0.000 | 559e422741 | check_unexpected_crash | alioshr__memory-bank-mcp__list_project_files.log |
| alioshr/memory-bank-mcp | `list_projects` | node | 0.000 | 559e422741 | check_unexpected_crash | alioshr__memory-bank-mcp__list_projects.log |
| alioshr/memory-bank-mcp | `memory_bank_read` | node | 0.000 | 559e422741 | check_unexpected_crash | alioshr__memory-bank-mcp__memory_bank_read.log |
| alioshr/memory-bank-mcp | `memory_bank_write` | node | 0.000 | 559e422741 | check_unexpected_crash | alioshr__memory-bank-mcp__memory_bank_write.log |
| isaacphi/mcp-gdrive | `gsheets_update_cell` | node | 0.000 | 5a94bdcb75 | check_unexpected_crash | isaacphi__mcp-gdrive__gsheets_update_cell.log |
