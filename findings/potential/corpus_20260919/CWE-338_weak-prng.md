# CWE-338 — Weak PRNG (1 candidates)

**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the set_e2 corpus run, 2026-09-19.** Each row is a ToFu oracle hit: an adversarial input tripped `weak-prng` sanitizer(s) AND the tool still returned success (silent bug). Success rate = strength (1.0 = the tool swallowed the adversarial input on every exec). NOT hand-verified — a human must reproduce before it is a confirmed finding. The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.

| repo | tool | lang | succ | commit | sanitizers | log |
|---|---|---|---|---|---|---|
| nkapila6/mcp-local-rag | `rag_search_google` | python | 0.000 | aabb55d64c | check_introspection_type_confusion,check_introspection_weak_prng | nkapila6__mcp-local-rag__rag_search_google.log |
