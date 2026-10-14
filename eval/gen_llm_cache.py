#!/usr/bin/env python3
"""Retro-build the ToFu LLM replay cache from a completed run's artifacts.

The two LLM calls per config are recorded on disk after a run:
  - sanitizer SELECTION -> the run log (eval/runs/<arm>/<config>.log lines
    "Sanitizers selected: [...]" and "Sanitizer rules: {...}")
  - SEEDS -> the corpus dir (eval/corpora_<arm>/<config>/seed_*.json, each the
    verbatim dict generate_seeds returned; fuzzer.py writes them there)

This writes one cache file per config to eval/state/llm_cache/<config>.json with
{"selected_sanitizers", "rules", "seeds"}. src/llm.py reads it (keyed by
TOFU_LLM_CACHE_KEY) and returns the recorded response instead of calling the
model, so re-running an already-fuzzed tool costs ZERO LLM calls.

  python3 eval/gen_llm_cache.py --arm gpt41-corpus
"""
import argparse, ast, glob, json, os, re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SEL_RE = re.compile(r"Sanitizers selected:\s*(\[.*\])\s*$")
PROV_HIT_RE = re.compile(r"LLM_SEEDGEN_CACHE_HIT\b.*?\bprovenance=(\w+)")
RULES_RE = re.compile(r"Sanitizer rules:\s*(\{.*\})\s*$")


def safe_key(k):
    return re.sub(r"[^A-Za-z0-9_.-]", "_", k)


def parse_selection(logpath):
    """Last 'Sanitizers selected:' / 'Sanitizer rules:' in the log (the accepted
    result). Returns (selected_list, rules_dict) or (None, None)."""
    sel = rules = None
    try:
        with open(logpath, errors="ignore") as f:
            for line in f:
                m = SEL_RE.search(line)
                if m:
                    try: sel = ast.literal_eval(m.group(1))
                    except Exception: pass
                m = RULES_RE.search(line)
                if m:
                    try: rules = ast.literal_eval(m.group(1))
                    except Exception: pass
    except OSError:
        return None, None
    return sel, rules


def seeds_provenance(logpath):
    """Who produced the corpus seed_*.json of this run, from its log.

    The fuzzer writes seed_*.json for WHATEVER seeds it got -- including the
    deterministic fallback -- so a corpus seed is not by itself an LLM seed.
    Measured 2026-09-23: >=12 of the 5022 VM cache entries replay fallback
    seeds; before this, a cache hit on them was indistinguishable from real
    LLM seed generation. Returns "llm", "fallback" or "unknown".
    """
    try:
        with open(logpath, errors="ignore") as f:
            txt = f.read()
    except OSError:
        return "unknown"
    if "LLM_SEEDGEN_OK" in txt:
        return "llm"
    if "LLM_SEEDGEN_FALLBACK" in txt:
        return "fallback"
    m = PROV_HIT_RE.search(txt)   # the run itself replayed a tagged entry
    if m and m.group(1) in ("llm", "fallback"):
        return m.group(1)
    return "unknown"


def backfill_provenance(cache_dir, logs_dir, write):
    """Add seeds_provenance to existing entries that lack it (never overwrites
    one that has it). Dry run unless write=True. Atomic per file."""
    import collections
    counts = collections.Counter()
    for p in sorted(glob.glob(os.path.join(cache_dir, "*.json"))):
        try:
            with open(p) as f:
                entry = json.load(f)
        except Exception:
            counts["unreadable"] += 1
            continue
        if "seeds" not in entry or entry.get("seeds_provenance"):
            counts["skip (no seeds / already tagged)"] += 1
            continue
        key = os.path.basename(p)[:-5]
        prov = seeds_provenance(os.path.join(logs_dir, key + ".log"))
        counts[prov] += 1
        if write and prov != "unknown":
            entry["seeds_provenance"] = prov
            tmp = p + ".tmp"
            with open(tmp, "w") as f:
                json.dump(entry, f)
            os.replace(tmp, p)
    return counts


def load_seeds(corpus_dir):
    files = sorted(glob.glob(os.path.join(corpus_dir, "seed_*.json")),
                   key=lambda p: int(re.search(r"seed_(\d+)", p).group(1)))
    seeds = []
    for p in files:
        try:
            with open(p) as f:
                seeds.append(json.load(f))
        except Exception:
            pass
    return seeds if files else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="gpt41-corpus")
    ap.add_argument("--out", default=os.path.join(ROOT, "eval", "state", "llm_cache"))
    ap.add_argument("--backfill-provenance", action="store_true",
                    help="tag EXISTING cache entries with seeds_provenance from "
                         "--arm's logs instead of rebuilding; dry run unless --write")
    ap.add_argument("--write", action="store_true")
    a = ap.parse_args()

    logs_dir = os.path.join(ROOT, "eval", "runs", a.arm)
    if a.backfill_provenance:
        counts = backfill_provenance(a.out, logs_dir, a.write)
        print(f"seeds_provenance from {os.path.relpath(logs_dir, ROOT)} "
              f"({'WRITTEN' if a.write else 'dry run, pass --write'}): "
              + ", ".join(f"{k}={v}" for k, v in sorted(counts.items())))
        return
    corpora_dir = os.path.join(ROOT, "eval", f"corpora_{a.arm}")
    os.makedirs(a.out, exist_ok=True)

    logs = glob.glob(os.path.join(logs_dir, "*.log"))
    n_sel = n_seeds = n_written = 0
    for lp in logs:
        key = os.path.basename(lp)[:-4]  # strip .log
        sel, rules = parse_selection(lp)
        seeds = load_seeds(os.path.join(corpora_dir, key))
        entry = {}
        if sel is not None:
            entry["selected_sanitizers"] = sel
            entry["rules"] = rules or {}
            n_sel += 1
        if seeds is not None:
            entry["seeds"] = seeds
            entry["seeds_provenance"] = seeds_provenance(lp)
            n_seeds += 1
        if not entry:
            continue
        with open(os.path.join(a.out, safe_key(key) + ".json"), "w") as f:
            json.dump(entry, f)
        n_written += 1

    print(f"logs scanned: {len(logs)}")
    print(f"cache files written: {n_written}  (with selection: {n_sel}, with seeds: {n_seeds})")
    print(f"-> {os.path.relpath(a.out, ROOT)}")


if __name__ == "__main__":
    main()
