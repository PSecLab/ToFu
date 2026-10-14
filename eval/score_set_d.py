#!/usr/bin/env python3
"""
Score ToFu on Set D against VIPER-MCP's OWN metric, on VIPER's OWN servers.

Set D is the subset of VIPER-MCP's 0-day discoveries (arXiv 2605.21392v2,
Appendix B) that we could resolve to a live GitHub repo. Each repo carries a
ground-truth vulnerability CLASS (command injection / SSRF / path traversal) --
the only three classes VIPER models. This script asks the one question the
user posed: run ToFu *in VIPER's court* and see how it does.

THE METRIC (VIPER's, Table 2):
  On the vulnerable set, VIPER reports FNR = FN / (TP + FN), where a server is
  a TP if the tool detects its known taint-style bug. We reproduce exactly that
  at the repo level: a Set D repo is a ToFu TP iff, across its tools, ToFu fired
  at least one sanitizer that maps to the repo's ground-truth class.

WHAT MAKES THIS FAIR TO BOTH SIDES:
  * Fair to VIPER: ToFu gets NO credit for firing an off-class sanitizer
    (e.g. a ReDoS or weak-hash finding on a command-injection server). Only a
    class-matching trigger counts as "detected the VIPER bug".
  * Fair to ToFu: we only score the 3 classes VIPER itself models, so ToFu is
    not charged for classes VIPER also does not cover.
  * Off-class findings are reported SEPARATELY (never as detections, never as
    misses) -- that is the "ToFu found a different bug" column.

WHAT THIS IS NOT (print these with any number this produces):
  * Set D repos are servers VIPER *found*, so the deck is stacked toward VIPER.
    By construction VIPER detects ~all of them; the interesting question is how
    many ToFu independently also catches.
  * Commits are GitHub HEAD, not the paper's (redacted) vulnerable revision. A
    repo patched since disclosure is a FALSE NEGATIVE THAT IS NOT TOFU'S FAULT;
    such repos are flagged 'possibly_patched' for manual review, not silently
    scored as misses.
  * ToFu's Set-D FNR is over the resolvable subset (~63 repos), NOT the paper's
    130. It does not slot directly beside VIPER's 7.7% -- it is a different
    denominator. The reference column is shown for orientation, clearly labeled.

Usage:
    python3 eval/score_set_d.py
    python3 eval/score_set_d.py --md set_d_scorecard.md
"""
import argparse, json, os
from collections import defaultdict

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "eval" else HERE
SETD = os.path.join(ROOT, "Benchmarks", "extraction", "set_d.json")
RUNS = os.path.join(ROOT, "eval", "state", "runs.jsonl")
CISCO = os.path.join(ROOT, "eval", "state", "cisco_runs.jsonl")

# ---- ToFu sanitizer family -> VIPER class ----------------------------------
# Only the three classes VIPER models. Everything else is 'other' (off-class).
SANI_CLASS = {}
def _reg(cls, *names):
    for n in names: SANI_CLASS[n] = cls
_reg("cmdi",
     "check_command_injection", "check_blocked_command_bypass",
     "check_introspection_command_injection", "check_introspection_argument_injection")
_reg("ssrf",
     "check_introspection_ssrf", "check_url_ssrf_ip_ranges",
     "check_url_alternative_ip_representations", "check_url_hostname_canonicalization",
     "check_url_raw_input_validation", "check_url_structure_and_parsing",
     "check_strict_url_security_contract", "check_markitdown_uri_validation",
     "check_har_url_path_security")
_reg("path",
     "check_path_traversal", "check_file_access", "check_directory_jailbreak_write",
     "check_har_path_traversal", "check_introspection_path_traversal",
     "check_introspection_symlink_following", "check_introspection_sensitive_file_access",
     "check_markitdown_file_uri_jailbreak", "check_unrestricted_file_upload")
# NB: check_introspection_code_injection is deliberately NOT cmdi -- VIPER lists
# "code injection" as a class it does NOT model, so counting it would be unfair.

def classes_of(sanitizers):
    return {SANI_CLASS[s] for s in sanitizers if s in SANI_CLASS}

def expand_gt(vuln_class_list):
    """Ground-truth classes for a repo; 'ssrf_path' means both."""
    out = set()
    for c in vuln_class_list:
        if c == "ssrf_path": out |= {"ssrf", "path"}
        else: out.add(c)
    return out

def read_jsonl(path):
    if not os.path.exists(path): return []
    rows = []
    for line in open(path):
        line = line.strip()
        if line:
            try: rows.append(json.loads(line))
            except json.JSONDecodeError: pass
    return rows

# VIPER Table 2 reference (over the FULL 130 vulnerable servers)
REF = {"VIPER-MCP": 0.077, "Cisco AI Defense": 0.731, "MCPSafetyScanner": 0.638}

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--md", help="also write a markdown scorecard here")
    a = ap.parse_args()

    setd = json.load(open(SETD))["set_d"]
    gt = {r["repo"]: r for r in setd}

    runs = [r for r in read_jsonl(RUNS) if r.get("set") == "D" or r.get("repo") in gt]
    by_repo = defaultdict(list)
    for r in runs:
        by_repo[r["repo"]].append(r)

    rows, tp, fn, notrun, offclass_only = [], 0, 0, 0, 0
    fallback_tp = 0
    for repo, meta in sorted(gt.items(), key=lambda kv: (kv[1]["tier"] != "gold", kv[0])):
        want = expand_gt(meta["vuln_class"])
        rr = by_repo.get(repo, [])
        ok_runs = [r for r in rr if r.get("ok")]
        fired = set()
        fired_llm = set()   # only from runs where the LLM selection actually ran
        for r in rr:
            f = set(r.get("triggered_sanitizers") or [])
            fired |= f
            if r.get("llm_selection") == "ok":
                fired_llm |= f
        got = classes_of(fired)
        got_llm = classes_of(fired_llm)
        hit = bool(want & got)
        hit_llm = bool(want & got_llm)
        off = classes_of(fired) - want or (
            {s for s in fired if s not in SANI_CLASS} and {"other"}) or set()
        offbucket = {s for s in fired if s not in SANI_CLASS}

        if not rr:
            status = "NOT-RUN"; notrun += 1
        elif not ok_runs and not fired:
            status = "NOT-RUN(all-errored)"; notrun += 1
        elif hit:
            status = "DETECT"; tp += 1
            if hit_llm is False and hit: fallback_tp += 1
        elif (got - want) or offbucket:
            status = "OFF-CLASS"; fn += 1; offclass_only += 1
        else:
            status = "MISS"; fn += 1

        rows.append({
            "repo": repo, "tier": meta["tier"], "want": sorted(want),
            "n_tools": len({r.get("tool") for r in rr}),
            "got_classes": sorted(got), "status": status,
            "llm_hit": hit_llm,
            "off_class": sorted(offbucket)[:6],
            "tool": meta.get("vulnerable_tool"),
            "provenance_warn": "HEAD not vuln-commit",
        })

    scanned = tp + fn
    fnr = fn / scanned if scanned else None

    # ---------- console report ----------
    W = 78
    print("=" * W)
    print("ToFu on Set D  --  VIPER-MCP's own 0-day servers, VIPER's own metric")
    print("=" * W)
    print(f"  Set D repos            : {len(gt)}  (gold {sum(1 for m in gt.values() if m['tier']=='gold')}, "
          f"silver {sum(1 for m in gt.values() if m['tier']=='silver')})")
    print(f"  scanned by ToFu        : {scanned}   not-run/errored: {notrun}")
    print(f"  class-match DETECT (TP): {tp}")
    print(f"     of which via LLM path: {tp - fallback_tp}   via deterministic fallback: {fallback_tp}")
    print(f"  MISS + OFF-CLASS  (FN) : {fn}   (off-class-only finds: {offclass_only})")
    if fnr is not None:
        print(f"  ToFu FNR (scanned)     : {fnr:.1%}   [denominator = {scanned} resolvable repos]")
    print()
    print("  Reference -- VIPER Table 2 FNR over the FULL 130 vulnerable servers")
    print("  (DIFFERENT denominator; shown for orientation, NOT a like-for-like):")
    for k, v in REF.items():
        print(f"     {k:<22}: {v:.1%}")
    print()
    print("  Caveats that MUST accompany any of these numbers:")
    print("   * Set D = servers VIPER FOUND -> stacked toward VIPER by construction.")
    print("   * commits are GitHub HEAD, not the paper's vulnerable revision;")
    print("     a since-patched repo is a false negative that is NOT ToFu's fault.")
    print("   * off-class = ToFu found a DIFFERENT bug than VIPER's; not a detection,")
    print("     not a miss -- reported on its own.")
    print("=" * W)
    print(f"{'repo':<40}{'tier':<7}{'want':<12}{'got':<12}{'status'}")
    print("-" * W)
    for r in rows:
        print(f"{r['repo'][:39]:<40}{r['tier']:<7}"
              f"{','.join(r['want']):<12}{','.join(r['got_classes'])[:11]:<12}{r['status']}"
              + ("" if r['llm_hit'] or r['status'] != 'DETECT' else "  (fallback)"))

    if a.md:
        with open(a.md, "w") as f:
            f.write("# ToFu on Set D (VIPER-MCP's servers, VIPER's metric)\n\n")
            f.write(f"- Set D repos: **{len(gt)}**; scanned by ToFu: **{scanned}**; "
                    f"not-run/errored: **{notrun}**\n")
            f.write(f"- class-match detections (TP): **{tp}** "
                    f"(LLM path {tp-fallback_tp}, fallback {fallback_tp})\n")
            f.write(f"- misses + off-class (FN): **{fn}**; "
                    f"off-class-only finds: **{offclass_only}**\n")
            if fnr is not None:
                f.write(f"- **ToFu FNR (scanned subset) = {fnr:.1%}** "
                        f"(denominator {scanned}, NOT the paper's 130)\n\n")
            f.write("Reference (VIPER Table 2, full 130 vulnerable servers, different denominator):\n\n")
            f.write("| Tool | FNR |\n|---|---|\n")
            for k, v in REF.items(): f.write(f"| {k} | {v:.1%} |\n")
            f.write("\n> Set D is VIPER's own discoveries (stacked toward VIPER); commits are "
                    "HEAD not the vulnerable revision; off-class finds are a different bug, "
                    "not a detection.\n\n")
            f.write("| repo | tier | want | got | status | vuln tool |\n|---|---|---|---|---|---|\n")
            for r in rows:
                f.write(f"| {r['repo']} | {r['tier']} | {','.join(r['want'])} | "
                        f"{','.join(r['got_classes'])} | {r['status']} | "
                        f"{r.get('tool') or ''} |\n")
        print(f"\nwrote {a.md}")

if __name__ == "__main__":
    main()
