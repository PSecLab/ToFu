#!/usr/bin/env python3
"""Harvest every ToFu oracle candidate from a run's index into findings/potential/.

Each row with finding_hits>0 is a SILENT-BUG candidate by ToFu's oracle (an
adversarial input tripped a sanitizer AND the tool still returned success). This
script groups them by CWE class (from the triggered sanitizers) and writes one
markdown per class listing every repo::tool instance with its evidence, so the
whole harvest lands in findings/potential/ in one traceable, dated batch.

  python3 eval/gen_potential_findings.py --arm gpt41-corpus --out findings/potential/corpus_20260917

These are UNCONFIRMED (auto-triaged), NOT hand-verified. Success rate is the
strength signal (succ~1.0 = the tool swallowed the adversarial input every time).
Nothing here is a confirmed finding until a human reproduces it.
"""
import argparse, collections, json, os, re, datetime

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# sanitizer -> (CWE, short class). Ordered by security value; the first HIGH
# match on a row decides its file, so a path-traversal+crash row files as
# path-traversal, not crash.
SAN_CWE = [
    ("check_command_injection",              ("CWE-78",  "os-command-injection")),
    ("check_blocked_command_bypass",         ("CWE-78",  "os-command-injection")),
    ("check_path_traversal",                 ("CWE-22",  "path-traversal")),
    ("check_introspection_ssrf",             ("CWE-918", "ssrf")),
    ("check_url_ssrf_ip_ranges",             ("CWE-918", "ssrf")),
    ("check_url_hostname_canonicalization",  ("CWE-918", "ssrf")),
    ("check_url_alternative_ip_representations", ("CWE-918", "ssrf")),
    ("check_url_structure_and_parsing",      ("CWE-918", "ssrf")),
    ("check_strict_url_security_contract",   ("CWE-918", "ssrf")),
    ("check_log_injection",                  ("CWE-117", "log-injection")),
    ("check_introspection_log_injection",    ("CWE-117", "log-injection")),
    ("check_introspection_hardcoded_credentials", ("CWE-798", "hardcoded-credentials")),
    ("check_introspection_temp_file_leak",   ("CWE-377", "insecure-temp-file")),
    ("check_introspection_incomplete_cleanup", ("CWE-459", "incomplete-cleanup")),
    ("check_process_and_fd_leaks",           ("CWE-404", "resource-fd-leak")),
    ("check_resource_exhaustion",            ("CWE-400", "resource-exhaustion")),
    ("check_introspection_weak_prng",        ("CWE-338", "weak-prng")),
    ("check_introspection_type_confusion",   ("CWE-843", "type-confusion")),
    ("check_unexpected_crash",               ("CWE-248", "uncaught-exception")),
    ("check_invalid_json",                   ("CWE-20",  "improper-input-validation")),
    ("check_strict_markitdown_security_contract", ("CWE-20", "markitdown-contract")),
]
CWE_TITLE = {
    "CWE-78": "OS Command Injection", "CWE-22": "Path Traversal / arbitrary file access",
    "CWE-918": "Server-Side Request Forgery (SSRF)", "CWE-117": "Log Injection",
    "CWE-798": "Use of Hard-coded Credentials", "CWE-377": "Insecure Temporary File",
    "CWE-459": "Incomplete Cleanup", "CWE-404": "Improper Resource / FD Release",
    "CWE-400": "Uncontrolled Resource Consumption (DoS)", "CWE-338": "Weak PRNG",
    "CWE-843": "Type Confusion", "CWE-248": "Uncaught Exception / crash",
    "CWE-20": "Improper Input Validation",
}


def scrub(s):
    s = str(s)
    s = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-<REDACTED>", s)
    s = re.sub(r"(?i)(api[_-]?key|token|secret|password|bearer)([\"'`:=\s]+)[A-Za-z0-9_\-\.]{6,}",
               r"\1\2<REDACTED>", s)
    return s


def classify(sanitizers):
    for san, cwe in SAN_CWE:
        if san in sanitizers:
            return cwe
    return ("CWE-noclass", "unclassified")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="gpt41-corpus")
    ap.add_argument("--out", default=os.path.join(ROOT, "findings", "potential",
                    "corpus_" + datetime.date.today().strftime("%Y%m%d")))
    ap.add_argument("--min-success", type=float, default=0.0,
                    help="skip candidates whose exec_success_rate is below this")
    a = ap.parse_args()

    idx = os.path.join(ROOT, "eval", "state", f"runs.{a.arm}.jsonl")
    rows = [json.loads(l) for l in open(idx) if l.strip()]
    cand = [r for r in rows if r.get("finding_hits") and r.get("ok")
            and (r.get("exec_success_rate") or 0) >= a.min_success]

    groups = collections.defaultdict(list)
    for r in cand:
        cwe, cls = classify(set(r.get("triggered_sanitizers") or []))
        groups[(cwe, cls)].append(r)

    os.makedirs(a.out, exist_ok=True)
    rel = os.path.relpath(a.out, ROOT)
    today = datetime.date.today().isoformat()

    order = [c for _, c in SAN_CWE]  # keep security-value order, dedup
    seen = set(); ordered_cls = []
    for c in order:
        if c not in seen:
            seen.add(c); ordered_cls.append(c)

    written = []
    for (cwe, cls), items in sorted(groups.items(),
            key=lambda kv: ordered_cls.index(kv[0][1]) if kv[0][1] in ordered_cls else 999):
        items.sort(key=lambda r: -(r.get("exec_success_rate") or 0))
        fn = os.path.join(a.out, f"{cwe}_{cls}.md")
        with open(fn, "w") as f:
            f.write(f"# {cwe} — {CWE_TITLE.get(cwe, cls)} ({len(items)} candidates)\n\n")
            f.write(f"**Status: POTENTIAL / UNCONFIRMED — auto-triaged from the "
                    f"set_e2 corpus run, {today}.** Each row is a ToFu oracle hit: an "
                    f"adversarial input tripped `{cls}` sanitizer(s) AND the tool still "
                    f"returned success (silent bug). Success rate = strength (1.0 = the "
                    f"tool swallowed the adversarial input on every exec). NOT hand-"
                    f"verified — a human must reproduce before it is a confirmed finding. "
                    f"The mandatory-sanitizer layer (CLAUDE.md §2) is NOT subtracted.\n\n")
            f.write("| repo | tool | lang | succ | commit | sanitizers | log |\n")
            f.write("|---|---|---|---|---|---|---|\n")
            for r in items:
                sans = ",".join(s for s in (r.get("triggered_sanitizers") or []))
                f.write("| %s | `%s` | %s | %.3f | %s | %s | %s |\n" % (
                    scrub(r.get("repo")), scrub(r.get("tool")), r.get("lang"),
                    r.get("exec_success_rate") or 0, (r.get("commit") or "")[:10],
                    scrub(sans), os.path.basename(r.get("log") or "")))
        written.append((cwe, cls, len(items), os.path.relpath(fn, ROOT)))

    # master index
    idxf = os.path.join(a.out, "INDEX.md")
    with open(idxf, "w") as f:
        f.write(f"# set_e2 corpus — potential findings harvest ({today})\n\n")
        f.write(f"{len(cand)} oracle candidates across {len(set(r['repo'] for r in cand))} "
                f"repos, from `eval/state/runs.{a.arm}.jsonl`. All POTENTIAL / unconfirmed.\n\n")
        f.write("| CWE | class | candidates | file |\n|---|---|---|---|\n")
        for cwe, cls, n, path in written:
            f.write(f"| {cwe} | {cls} | {n} | [{os.path.basename(path)}]({os.path.basename(path)}) |\n")
    print(f"wrote {len(written)} class files + INDEX.md to {rel}  ({len(cand)} candidates)")
    for cwe, cls, n, _ in written:
        print(f"  {cwe:12} {cls:26} {n}")


if __name__ == "__main__":
    main()
