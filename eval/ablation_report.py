#!/usr/bin/env python3
"""Ablation report for eval/run_ablation.sh. Counts bugs per arm exactly as the
headline does (findings/union_20260926/analyze_union.py: ok row with finding_hits,
triage_findings.classify -> one (repo, tool, class) per config), restricted to the
ablation config list, and derives the oracle ablations from the `full` arm:

  tracers-only     classify(only check_introspection_* names)     -- runtime-observed op
  outcome-only     classify(non-introspection names)              -- tracer off
  sanitizers-only  classify(non-introspection names, incl. those that WOULD fire on
                   failed executions: ORACLE_SHADOW_UNGATED)      -- no success gate

Usage: python3 eval/ablation_report.py [--state eval/state] [--prefix abl] [--out FILE]
"""
import argparse, collections, json, os, sys
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "eval"))
from triage_findings import classify

ARMS = ["full", "nollmseeds", "mandatory", "nollm", "noseeds", "allsan"]
DESC = {
    "full": "full ToFu", "nollmseeds": "fallback seeds (no LLM seeds)",
    "mandatory": "mandatory sanitizers only (no LLM selection)",
    "nollm": "no LLM at all (fallback seeds + mandatory)",
    "noseeds": "empty corpus (no seeds at all)", "allsan": "all sanitizers (no LLM selection)",
}
is_tracer = lambda n: n.startswith("check_introspection_")


def load(p, want):
    rows = {}
    if os.path.exists(p):
        for l in open(p):
            if l.strip():
                r = json.loads(l)
                k = os.path.splitext(r.get("config", ""))[0]
                if k in want:
                    rows[k] = r          # last row per config wins (resume)
    return rows


def bugs(rows, pick=lambda r: r.get("triggered_sanitizers"), need_hit=True):
    out = set()
    for r in rows.values():
        if not r.get("ok") or (need_hit and not r.get("finding_hits")):
            continue
        c = classify(pick(r))
        if c:
            out.add((r.get("repo"), r.get("tool"), c[0], r.get("lang")))
    return out


def stats(rows):
    ex = [r for r in rows.values() if (r.get("n_exec_success") or 0) >= 1]
    rate = [r["n_exec"] / r["seconds"] for r in rows.values()
            if r.get("n_exec") and r.get("seconds")]
    rate.sort()
    return len(rows), len(ex), (rate[len(rate) // 2] if rate else 0.0)


def line(name, desc, n, ex, eps, B, base, by_tool=False):
    langs = collections.Counter(b[3] for b in B)
    repos = len({b[0] for b in B})
    if by_tool and base is not None:
        # oracle subsets: a config keeps "its" bug if it still yields ANY class --
        # classify() re-picks the most severe remaining class, so a (repo, tool,
        # class) diff would count the re-pick as a new bug.
        B, base = {b[:2] for b in B}, {b[:2] for b in base}
    d = "" if base is None else f"{len(B & base)} / {len(B - base)} / {len(base - B)}"
    return (f"| {name} | {desc} | {n} | {ex} | {eps:.1f} | **{len(B)}** | {repos} | "
            f"{langs.get('python', 0)} | {langs.get('node', 0) + langs.get('js', 0)} | {d} |")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--state", default=os.path.join(ROOT, "eval", "state"))
    ap.add_argument("--prefix", default="abl")
    ap.add_argument("--configs", default=os.path.join(ROOT, "Benchmarks", "extraction", "ablation_251_configs.txt"))
    ap.add_argument("--out", default=None)
    a = ap.parse_args()
    want = {os.path.splitext(l.strip())[0] for l in open(a.configs) if l.strip() and not l.startswith("#")}
    R = {arm: load(os.path.join(a.state, f"runs.{a.prefix}-{arm}.jsonl"), want) for arm in ARMS}
    hdr = ("| arm | what is removed | configs run | executed | median exec/s | bugs | repos | py | js "
           "| shared / only-here / lost vs full |\n|---|---|---|---|---|---|---|---|---|---|")
    L = [f"# ToFu ablation ({len(want)} configs)\n", "## Stage ablations (each arm = its own run)\n", hdr]
    base = bugs(R["full"]) if R["full"] else None
    for arm in ARMS:
        if not R[arm]:
            L.append(f"| {arm} | {DESC[arm]} | 0 | - | - | - | - | - | - | not run |"); continue
        n, ex, eps = stats(R[arm]); B = bugs(R[arm])
        L.append(line(arm, DESC[arm], n, ex, eps, B, None if arm == "full" else base))
        if n < len(want):
            L[-1] += f" (INCOMPLETE {n}/{len(want)})"
    if R["full"]:
        f = R["full"]; n, ex, eps = stats(f)
        shadow_rows = sum(1 for r in f.values() if r.get("shadow_ungated_signatures"))
        L += ["", "## Oracle ablations (derived from the `full` arm's logs; no extra run)\n",
              "shared/only-here/lost compared per (repo, tool).\n", hdr]
        L.append(line("full", "sanitizer AND (success OR tracer)", n, ex, eps, base, None))
        L.append(line("tracers-only", "only runtime-observed ops count", n, ex, eps,
                      bugs(f, lambda r: [x for x in r.get("triggered_sanitizers") or [] if is_tracer(x)]), base, True))
        L.append(line("outcome-only", "tracer off: sanitizer AND success", n, ex, eps,
                      bugs(f, lambda r: [x for x in r.get("triggered_sanitizers") or [] if not is_tracer(x)]), base, True))
        L.append(line("sanitizers-only", "every sanitizer fire, success or not", n, ex, eps,
                      bugs(f, lambda r: [x for x in (r.get("triggered_sanitizers") or [])
                                         + (r.get("shadow_ungated_sanitizers") or []) if not is_tracer(x)],
                           need_hit=False), base, True))
        L.append(f"\nshadow-oracle lines present in {shadow_rows} of {n} full-arm configs"
                 + ("  <-- 0 means TOFU_ORACLE_SHADOW was off; sanitizers-only row is INVALID" if not shadow_rows else ""))
    L.append("\nBugs = distinct (repo, tool, class) via triage_findings.classify, same rule as the headline. "
             "Extra bugs in `allsan` are raw candidates: precision must be labelled before they count.")
    txt = "\n".join(L) + "\n"
    if a.out:
        open(a.out, "w").write(txt)
    print(txt)


if __name__ == "__main__":
    main()
