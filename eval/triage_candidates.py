#!/usr/bin/env python3
"""List the findings CANDIDATE pool from a run index, the way every triage in
this project has been done by hand:

  * only runs whose tool actually EXECUTED (executable == "yes") -- a run with
    zero successful executions says nothing about the target;
  * grouped by the distinct sanitizer signature, with raw hit counts shown but
    never used for ranking (hit count is anti-correlated with real bugs here:
    the two confirmed findings came from 7 and ~1800 hits, the 10,040-hit repo
    was pure noise);
  * known false-positive families flagged inline so the reader goes straight
    to the sink.

This prints candidates. It does NOT decide. Every candidate still needs the
sink read and, for any file/exec/persistence effect, a directed test.

    python3 eval/triage_candidates.py eval/sandbox/state/runs.gpt41-sandbox.jsonl
    python3 eval/triage_candidates.py <index> --since-config <config-name>   # only newer runs
"""
import argparse, collections, json, os, sys

# Sanitizers whose alerts have, so far, ALWAYS traced to a harness defect or a
# tool behaving as documented. Listed so a reader is not re-fooled; not an
# exclusion -- a genuine finding can still hide in a mixed signature.
KNOWN_FP = {
    "check_invalid_json": "free-text arg containing braces; fires on any string (bug-22 family)",
    "check_strict_har_security_contract": "written for extract_har.py; None-guard added 2026-09-12",
    "check_strict_markitdown_security_contract": "written for MarkItDown; None-guard added 2026-09-12",
    "check_url_structure_and_parsing": "url check on non-url arg (context-guarded 2026-09-12)",
    "check_url_hostname_canonicalization": "url check on non-url arg (context-guarded 2026-09-12)",
    "check_url_ssrf_ip_ranges": "url check on non-url arg (context-guarded 2026-09-12)",
    "check_url_alternative_ip_representations": "url check on non-url arg (context-guarded 2026-09-12)",
    "check_blocked_command_bypass": "fires on any string with 'su'/'dd' substrings (context-guarded 2026-09-12)",
    "check_unhandled_promise_rejection": "substring grep on successful output (gated on res.success 2026-09-12)",
    "check_resource_exhaustion": "was: transport timeout scored as DoS (bug 20). Post-fix hits are real slow calls -- usually external API latency",
    "check_process_and_fd_leaks": "terminal/command tools spawn children by design",
}

def host_log_path(log, index_path):
    """The index stores the CONTAINER path (eval/runs/<arm>/x.log). On the host
    the sandbox overlay lives under eval/sandbox/. Return whichever exists."""
    if not log:
        return ""
    if os.path.exists(log):
        return log
    cand = os.path.join(os.path.dirname(os.path.dirname(index_path)), log.split("eval/", 1)[-1]) \
        if "eval/" in log else log
    if os.path.exists(cand):
        return cand
    alt = os.path.join("eval", "sandbox", log.split("eval/", 1)[-1]) if "eval/" in log else log
    return alt if os.path.exists(alt) else log


def load(path):
    rows = []
    for l in open(path):
        try: rows.append(json.loads(l))
        except Exception: pass
    return rows

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("index")
    ap.add_argument("--since-config", default=None,
                    help="only consider runs recorded AFTER this config name appears in the index")
    ap.add_argument("--repo", default=None, help="substring filter on repo")
    a = ap.parse_args()

    rows = load(a.index)
    if a.since_config:
        idx = next((i for i, r in enumerate(rows) if r.get("config") == a.since_config), None)
        if idx is None:
            print(f"--since-config {a.since_config!r} not found in index", file=sys.stderr); sys.exit(2)
        rows = rows[idx + 1:]
    if a.repo:
        rows = [r for r in rows if a.repo.lower() in r.get("repo", "").lower()]

    execd = [r for r in rows if r.get("executable") == "yes"]
    zero = [r for r in rows if r.get("executable") == "no"]
    cand = [r for r in execd if r.get("finding_hits") or r.get("triggered_sanitizers")]

    print(f"runs={len(rows)}  executable={len(execd)}  zero-success={len(zero)}  "
          f"CANDIDATES (executable+alerted)={len(cand)}")
    print("zero-success runs are NOT evidence about the target; they are excluded below.\n")

    sig = collections.defaultdict(list)
    for r in cand:
        ts = r.get("triggered_sanitizers") or []
        sig[tuple(sorted(ts))].append(r)

    for key, runs in sorted(sig.items(), key=lambda kv: -len(kv[1])):
        fp_notes = [f"{s}: {KNOWN_FP[s]}" for s in key if s in KNOWN_FP]
        novel = [s for s in key if s not in KNOWN_FP]
        tag = "  <-- NOVEL sanitizer(s), read the sink FIRST" if novel else ""
        print(f"[{len(runs):3d} run(s)]  {key}{tag}")
        for r in runs[:6]:
            print(f"      {r['repo']}::{r['tool']}  raw_hits={r.get('finding_hits')}  "
                  f"exec_ok={r.get('n_exec_success')}/{r.get('n_exec')}  log={host_log_path(r.get('log',''), a.index)}")
        if len(runs) > 6: print(f"      ... +{len(runs)-6} more")
        for n in fp_notes: print(f"      note: {n}")
        print()

    if not cand:
        print("no candidates: nothing executed AND alerted. (Absence of evidence, not evidence of absence.)")

if __name__ == "__main__":
    main()
