# Rejected designs — do not wire these in

net_tracer.js.REJECTED was written into src/runners/ by a workflow subagent on
2026-09-10. It was never referenced by any code and its own adversarial review
returned verdict=REJECT, contract_matches=false, will_break_target=TRUE:

  * the dns.lookup hook rebuilds the function without copying
    Symbol(customPromisifyArgs), so promisify(dns.lookup) changes semantics
  * extractAddress defaults an absent host to 'localhost', which is in
    check_introspection_ssrf's internal_host_patterns -- a benign target doing
    net.connect({port:6379}) to a local Redis would emit a GUARANTEED SSRF
    ALERT ON EVERY EXECUTION. It manufactures the finding we most want.

Moved out of src/ so it cannot be mistaken for working instrumentation.
Full design + verdict: workflows/wf_a107e419-5ce/journal.jsonl.
