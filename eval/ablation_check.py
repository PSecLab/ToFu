#!/usr/bin/env python3
"""Health check for the ablation arms (eval/run_ablation.sh). Verifies, from the index
AND the per-config logs, that each arm removed exactly the stage it claims to and
nothing silently degraded (CLAUDE.md failure mode: a healthy-looking 0).

  python3 eval/ablation_check.py [--prefix abl] [arm ...]

Per arm: rows done, ok, executed vs the headline rows for the same configs, the
ablation switches recorded in the rows, and log markers:
  full        cache hits, no live LLM call, ORACLE_SHADOW_UNGATED present somewhere
  nollmseeds  seeds = fallback, selection = cache hit
  mandatory   'NO_LLM selection (mandatory only)', n_selected <= 10, seeds = cache hit
  nollm       fallback seeds + mandatory selection
  noseeds     'NO_SEEDS empty initial corpus', selection = cache hit, still executes
  allsan      'NO_LLM selection (all sanitizers)', n_selected = len(AVAILABLE_SANITIZERS)
Every non-full arm: zero live LLM calls (LLM_SELECTION_OK / LLM_SEEDGEN_OK), cache unchanged.
"""
import argparse, collections, glob, json, os, re, sys
ROOT = os.environ.get("TOFU_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ARMS = ["full", "nollmseeds", "mandatory", "nollm", "noseeds", "allsan"]
WANT_ENV = {
    "full": {"TOFU_ORACLE_SHADOW": "1"},
    "nollmseeds": {"TOFU_NO_LLM_SEEDS": "1", "TOFU_LLM_CACHE_READONLY": "1"},
    "mandatory": {"TOFU_NO_LLM_SANITIZERS": "mandatory", "TOFU_LLM_CACHE_READONLY": "1"},
    "nollm": {"TOFU_NO_LLM": "1", "TOFU_LLM_CACHE_READONLY": "1"},
    "noseeds": {"TOFU_NO_SEEDS": "1", "TOFU_LLM_CACHE_READONLY": "1"},
    "allsan": {"TOFU_NO_LLM_SANITIZERS": "all", "TOFU_LLM_CACHE_READONLY": "1"},
}
RE_NSEL = re.compile(r"NO_LLM selection \((mandatory only|all sanitizers)\) tool=\S+ n_selected=(\d+)")


def rows_of(p):
    out = {}
    if os.path.exists(p):
        for l in open(p):
            if l.strip():
                r = json.loads(l); out[os.path.splitext(r.get("config", ""))[0]] = r
    return out


def n_available():
    sys.path.insert(0, ROOT)
    try:
        from src.sanitizers import AVAILABLE_SANITIZERS
        return len(AVAILABLE_SANITIZERS)
    except Exception:
        return None


def check(prefix, arm, head, n_avail):
    R = rows_of(os.path.join(ROOT, "eval", "state", f"runs.{prefix}-{arm}.jsonl"))
    if not R:
        return [f"{prefix}-{arm}: not started"]
    bad, c = [], collections.Counter()
    for k, r in R.items():
        c["rows"] += 1; c["ok"] += bool(r.get("ok"))
        ex = (r.get("n_exec_success") or 0) >= 1; c["exec"] += ex
        h = head.get(k)
        if h is not None:
            c["head_n"] += 1; c["head_exec"] += (h.get("n_exec_success") or 0) >= 1
            c["both_exec"] += ex and (h.get("n_exec_success") or 0) >= 1
        if r.get("sandbox") != "bwrap": bad.append(f"{k}: sandbox={r.get('sandbox')}")
        if (r.get("ablation") or {}) != WANT_ENV[arm]: bad.append(f"{k}: ablation={r.get('ablation')}")
        c["shadow"] += bool(r.get("shadow_ungated_signatures"))
        log = r.get("log") or os.path.join(ROOT, "eval", "runs", f"{prefix}-{arm}", k + ".log")
        try:
            t = open(log, errors="replace").read()
        except OSError:
            c["nolog"] += 1; continue
        live = ("LLM_SELECTION_OK" in t) + ("LLM_SEEDGEN_OK" in t)
        c["live_llm"] += bool(live)
        c["sel_hit"] += "LLM_SELECTION_CACHE_HIT" in t
        c["seed_hit"] += "LLM_SEEDGEN_CACHE_HIT" in t
        c["fallback"] += "LLM_SEEDGEN_FALLBACK" in t
        c["noseeds"] += "NO_SEEDS empty initial corpus" in t
        for mode, n in RE_NSEL.findall(t):
            n = int(n)
            if mode == "mandatory only" and n > 10: bad.append(f"{k}: mandatory n_selected={n}")
            if mode == "all sanitizers" and n_avail and n != n_avail: bad.append(f"{k}: all n_selected={n}!={n_avail}")
            c["nsel_" + mode.split()[0]] += 1
    n = c["rows"]
    exp = {  # (counter, must equal n) per arm
        "full": ["sel_hit", "seed_hit"], "nollmseeds": ["sel_hit", "fallback"],
        "mandatory": ["nsel_mandatory", "seed_hit"], "nollm": ["nsel_mandatory", "fallback"],
        "noseeds": ["sel_hit", "noseeds"], "allsan": ["nsel_all", "seed_hit"],
    }[arm]
    for e in exp:
        if c[e] != n - c["nolog"]: bad.append(f"marker {e}: {c[e]}/{n - c['nolog']} logs")
    if c["ok"] < n: bad.append(f"{n - c['ok']} of {n} rows ok=False (runner error/crash) -- read their logs")
    crash = [k for k, r in R.items() if (r.get("n_exec") or 0) and r.get("n_exec") < 50 and not r.get("stopped_early")]
    if crash: bad.append(f"{len(crash)} rows ended after <50 execs (target died?): {crash[:3]}")
    if arm != "full" and c["live_llm"]: bad.append(f"LIVE LLM CALL in {c['live_llm']} logs of a read-only arm")
    if arm == "full" and c["live_llm"]: bad.append(f"note: {c['live_llm']} live LLM calls (cache miss)")
    if arm == "full" and n >= 50 and not c["shadow"]: bad.append("no shadow lines in >=50 rows: TOFU_ORACLE_SHADOW not effective")
    hr = f"{c['head_exec']}/{c['head_n']}" if c["head_n"] else "-"
    L = [f"{prefix}-{arm}: rows={n} ok={c['ok']} executed={c['exec']} (headline same configs: {hr}, "
         f"both={c['both_exec']}) shadow-rows={c['shadow']} live-llm={c['live_llm']} "
         f"sel-hit={c['sel_hit']} seed-hit={c['seed_hit']} fallback={c['fallback']} "
         f"noseeds={c['noseeds']} nolog={c['nolog']}"]
    L += ["   !! " + b for b in bad[:12]] + ([f"   !! ... {len(bad) - 12} more"] if len(bad) > 12 else [])
    if not bad: L.append("   OK")
    return L


def main():
    ap = argparse.ArgumentParser(); ap.add_argument("--prefix", default="abl"); ap.add_argument("arms", nargs="*")
    a = ap.parse_args()
    head = {}
    for f in ("findings/corpus_sbx_20260926/runs.gpt41-corpus-sbx.jsonl",
              "findings/recover_pc_20260926/runs.gpt41-recover-pc.jsonl"):
        head.update(rows_of(os.path.join(ROOT, f)))
    n_avail = n_available()
    cdir = os.environ.get("TOFU_LLM_CACHE_DIR", os.path.join(ROOT, "eval", "state", "llm_cache_ablation"))
    if os.path.isdir(cdir):
        fs = glob.glob(os.path.join(cdir, "*.json"))
        newest = max((os.path.getmtime(f) for f in fs), default=0)
        import time
        print(f"cache {cdir}: {len(fs)} entries, newest write {time.strftime('%Y-%m-%d %H:%M', time.localtime(newest))}")
    for arm in a.arms or ARMS:
        print("\n".join(check(a.prefix, arm, head, n_avail)))


if __name__ == "__main__":
    main()
