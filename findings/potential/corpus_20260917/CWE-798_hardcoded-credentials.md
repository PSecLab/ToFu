# CWE-798 — Use of Hard-coded Credentials (1 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-17.** Each row is a ToFu oracle hit: an adversarial input tripped `hardcoded-credentials` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| T1nker-1220/memories-with-lessons-mcp-server | `create_lesson` | node | 0.013 | 7c6a33e635 | check_introspection_hardcoded_credentials | T1nker-1220__memories-with-lessons-mcp-server__create_lesson.log |
