# Why this is here

Middle rung of the JS-coverage A/B/C on `api7/apisix-mcp::delete_resource`.
Moved aside, not deleted, so the same config re-runs against the block-coverage
fix and all three traces are comparable.

    A  eval/state/preRevertFix2/          Fix 2 active (prevCounts delta)
       #13    INITED cov: 1388 ft: 1388 corp: 1/32b
       #8192  pulse  cov: 1388 ft: 1388 corp: 1/32b

    B  THIS DIRECTORY                     Fix 2 reverted, count>0 filter
       #13    INITED cov: 1390 ft: 2181 corp: 3/103b
       #355   REDUCE cov: 1390 ft: 2557 corp: 4/46b
       #4096  pulse  cov: 1390 ft: 2557 corp: 4/38b
       ft: and corp: now move -- the revert was right. cov: still pinned.

    C  (to be produced)                   executedIntervals() block coverage

Why cov: was still pinned at B, measured on a live inspector.Session:
V8 emits one range per function carrying its execution count and carves the
branches that did NOT run out of it as nested count:0 sub-ranges. The count>0
set is therefore identical whichever branch an input takes:
    [routes  ] ranges= 157-265:1  207-263:0
    [services] ranges= 157-265:1  194-207:0  244-263:0
    [zzz     ] ranges= 157-265:1  194-207:0  231-244:0
processCoverage now subtracts nested count:0 ranges and reports the disjoint
executed intervals by byte offset. Against those three measured range sets it
yields 3 distinct coverage sets instead of 1 (tests/test_audit_regressions.py).

The LLM stage in this run is healthy and is NOT what is being re-tested:
    LLM_SELECTION_OK n_selected=6 n_dropped=0
    LLM_SEEDGEN_OK   n_seeds=12 n_rejected=0 validated=1
