#!/usr/bin/env python3
"""Auto-triage ToFu oracle hits into real-vulnerability candidates.

INPUT is the run index (eval/state/runs.<arm>.jsonl), not prose. Every row with
finding_hits>0 is a silent-bug oracle hit (an adversarial input tripped a
sanitizer AND the tool still returned success). This classifier turns that raw
set into a ranked, de-duplicated list of *reportable* candidates by:

  1. CLASS MAP -- map each triggered sanitizer to a security class, or drop it as
     robustness/noise. Dropped classes are quality/DoS signals or the always-on
     BASE_MANDATORY_SANITIZERS (CLAUDE.md 2), which fire regardless of LLM
     selection and so are not evidence of a targeted vulnerability.
  2. SEVERITY PICK -- a hit is labelled by its highest-severity real class.
  3. DEDUP -- count distinct (repo, tool, class); one tool = one vuln.
  4. REACHABILITY (descriptive only) -- exec_success_rate is the fraction of ALL
     of the tool's executions that returned a non-error response. It is reported
     per candidate but never tiers or filters: the oracle already requires the
     tool to accept the flagged input, so how often it rejects other fuzz inputs
     says nothing about a given alert. (A former ">=0.5 = high-confidence" tier was
     withdrawn 2026-09-26.)

These are CANDIDATES, not hand-verified. The mandatory layer is NOT subtracted
(do that before any LLM-selection/RQ2-RQ3 claim). A human sample-triage is still
owed for a published false-positive rate. This is a noise filter + ranking.

  python3 eval/triage_findings.py --arm gpt41-corpus
  python3 eval/triage_findings.py --arm gpt41-corpus --write findings/potential/REAL_vulns.md
"""
import argparse, collections, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# security-exploitable sanitizer -> class. Order = severity (first match wins).
REAL = [
    ("check_command_injection",              ("os-command-injection", "CWE-78")),
    ("check_blocked_command_bypass",         ("os-command-injection", "CWE-78")),
    ("check_introspection_exfil",            ("data-exfiltration",     "CWE-201")),
    ("check_path_traversal",                 ("path-traversal",        "CWE-22")),
    ("check_reflected_output",               ("reflected-xss",         "CWE-79")),
    ("check_introspection_ssrf",             ("ssrf",                  "CWE-918")),
    ("check_url_ssrf_ip_ranges",             ("ssrf",                  "CWE-918")),
    ("check_url_hostname_canonicalization",  ("ssrf",                  "CWE-918")),
    ("check_url_alternative_ip_representations", ("ssrf",              "CWE-918")),
    ("check_strict_url_security_contract",   ("ssrf",                  "CWE-918")),
    ("check_log_injection",                  ("log-injection",         "CWE-117")),
    ("check_introspection_log_injection",    ("log-injection",         "CWE-117")),
    ("check_introspection_hardcoded_credentials", ("hardcoded-creds",  "CWE-798")),
    ("check_introspection_temp_file_leak",   ("insecure-temp-file",    "CWE-377")),
]
# Explicitly dropped as robustness / mandatory-layer noise (documented, not silent):
NOISE = {
    "check_introspection_type_confusion", "check_unexpected_crash", "check_invalid_json",
    "check_resource_exhaustion", "check_introspection_incomplete_cleanup",
    "check_process_and_fd_leaks", "check_introspection_weak_prng",
    "check_url_structure_and_parsing",
}


def classify(sanitizers):
    s = set(sanitizers or [])
    for name, cls in REAL:
        if name in s:
            return cls
    return None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="gpt41-corpus")
    ap.add_argument("--index", default=None, help="override index path")
    ap.add_argument("--write", default=None, help="also write the enumerated list to this markdown path")
    a = ap.parse_args()

    idx = a.index or os.path.join(ROOT, "eval", "state", f"runs.{a.arm}.jsonl")
    rows = []
    for l in open(idx):
        if l.strip():
            try: rows.append(json.loads(l))
            except Exception: pass
    fnd = [r for r in rows if r.get("ok") and r.get("finding_hits")]

    # dedup by (repo, tool, class); keep the max success seen
    best = {}
    for r in fnd:
        cls = classify(r.get("triggered_sanitizers"))
        if not cls:
            continue
        key = (r.get("repo"), r.get("tool"), cls[0])
        sr = r.get("exec_success_rate") or 0
        if key not in best or sr > best[key][0]:
            best[key] = (sr, cls[1], (r.get("commit") or "")[:10])

    by_class_all = collections.Counter()
    for (repo, tool, cls), (sr, cwe, commit) in best.items():
        by_class_all[cls] += 1

    total_all = sum(by_class_all.values())
    repos = len({k[0] for k in best})
    print(f"index: {os.path.relpath(idx, ROOT)}  oracle-hits: {len(fnd)}")
    print(f"{'class':22} {'CWE':8} {'candidates':>10}")
    order = []
    seen = set()
    for _, (cls, cwe) in REAL:
        if cls not in seen:
            seen.add(cls); order.append((cls, cwe))
    for cls, cwe in order:
        if by_class_all.get(cls):
            print(f"{cls:22} {cwe:8} {by_class_all.get(cls,0):>10}")
    print(f"{'-'*47}")
    print(f"{'TOTAL REAL':22} {'':8} {total_all:>10}   across {repos} repos")

    if a.write:
        cwe_of = {cls: cwe for _, (cls, cwe) in REAL}
        rows_out = sorted(best.items(), key=lambda kv: (kv[0][2], -kv[1][0]))
        with open(a.write, "w") as f:
            f.write(f"# ToFu real-vulnerability candidates ({a.arm})\n\n")
            f.write(f"**{total_all} distinct repo::tool::class across {repos} repos** "
                    f"(succ column = tool exec-success rate, reachability only). Auto-triaged by "
                    f"eval/triage_findings.py; robustness/mandatory-layer classes excluded. "
                    f"POTENTIAL/unconfirmed -- hand-verify before any published figure.\n\n")
            cur = None
            for (repo, tool, cls), (sr, cwe, commit) in rows_out:
                if cls != cur:
                    cur = cls
                    n = by_class_all.get(cls, 0)
                    f.write(f"\n## {cls} ({cwe_of.get(cls,'')}) -- {n}\n\n"
                            f"| repo | tool | succ | commit |\n|---|---|---|---|\n")
                f.write(f"| {repo} | `{tool}` | {sr:.3f} | {commit} |\n")
        print(f"wrote {a.write}")


if __name__ == "__main__":
    main()
