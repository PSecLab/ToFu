# Why this is here

The 2026-09-10 07:48 smoke run of `api7/apisix-mcp::delete_resource`, moved
aside so the SAME config re-runs after Fix 2 was reverted and the coverage
comparison is like-for-like.

It is NOT junk. Its LLM stage is the first fully healthy one on record:

    LLM_SELECTION_OK  tool=delete_resource attempt=1 n_selected=6 n_dropped=0
    LLM_SEEDGEN_OK    tool=delete_resource attempt=1 n_seeds=12 n_rejected=0 validated=1
    seeds schema-shaped, e.g. {"id": "'; DROP TABLE users; --", "type": "upstreams"}
    sanitizers plausible for the tool: command_injection, sql_injection,
    path_traversal, sensitive_file_access, argument_injection, resource_exhaustion

It is the BEFORE half of the coverage A/B:

    #13   INITED cov: 1388 ft: 1388 corp: 1/32b exec/s: 0
    #8192 pulse  cov: 1388 ft: 1388 corp: 1/32b exec/s: 107

exec/s rose to 107-128 (acceptance test (c) PASSES, was 0-33), but cov: never
moved and corp: never grew past 1 across 8192 executions on 12 distinct seeds.

Cause, measured afterwards: takePreciseCoverage RESETS V8's execution counters,
so Fix 2's prevCounts delta suppressed almost every range after the first call.
Fix 2 is reverted; re-run this config to get the AFTER half.
