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
    a = ap.parse_args()

    logs_dir = os.path.join(ROOT, "eval", "runs", a.arm)
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
