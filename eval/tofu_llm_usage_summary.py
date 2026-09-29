#!/usr/bin/env python3
"""Exact LLM usage from an llm_cache_proxy ledger (ToFu, Viper, Cisco all go through it).

Every ledger line is one LLM call. For a miss the ledger carries the upstream token usage; for a
replay (hit) the usage is read back from the recorded response, so replayed calls are counted
with the tokens they would have cost. Optional --since/--until (epoch seconds) restrict to a
campaign window; --index (a run_eval index) gives the number of tools for per-tool means.

  python3 eval/tofu_llm_usage_summary.py --ledger eval/state/tofu_usage_proxy/_ledger.jsonl \
      --index eval/state/runs.usage-full.jsonl
"""
import argparse, json, os, statistics


def usage_of(raw, stream):
    try:
        if not stream:
            u = json.loads(raw).get("usage") or {}
            return u.get("prompt_tokens") or 0, u.get("completion_tokens") or 0
        for line in reversed(raw.splitlines()):
            if line.startswith("data:") and '"usage"' in line:
                u = json.loads(line[5:].strip()).get("usage") or {}
                return u.get("prompt_tokens") or 0, u.get("completion_tokens") or 0
    except Exception:
        pass
    return 0, 0


ap = argparse.ArgumentParser()
ap.add_argument("--ledger", required=True)
ap.add_argument("--index", default=None)
ap.add_argument("--since", type=float, default=None)
ap.add_argument("--until", type=float, default=None)
ap.add_argument("--json", default=None, help="write the summary here")
a = ap.parse_args()
cache_dir = os.path.dirname(os.path.abspath(a.ledger))

calls = hits = misses = errors = 0
pt = ct = 0
models = {}
for line in open(a.ledger):
    if not line.strip():
        continue
    r = json.loads(line)
    ts = r.get("ts", 0)
    if (a.since and ts < a.since) or (a.until and ts > a.until) or r.get("refused"):
        continue
    calls += 1
    models[r.get("model")] = models.get(r.get("model"), 0) + 1
    if r.get("hit"):
        hits += 1
        k = r["key"]
        try:
            rec = json.load(open(os.path.join(cache_dir, k[:2], k + ".json")))
            p, c = usage_of(rec["raw"], r.get("stream"))
        except Exception:
            p = c = 0
    else:
        misses += 1
        if r.get("status") not in (None, 200):
            errors += 1
        p, c = r.get("prompt_tokens") or 0, r.get("completion_tokens") or 0
    pt += p; ct += c

out = dict(calls=calls, replayed=hits, upstream=misses, upstream_errors=errors,
           prompt_tokens=pt, completion_tokens=ct, models=models)
if a.index and os.path.exists(a.index):
    rows = [json.loads(l) for l in open(a.index) if l.strip()]
    ran = [r for r in rows if r.get("ok")]
    n = len(ran)
    out.update(tools=n, per_tool=dict(calls=round(calls / n, 2), prompt_tokens=round(pt / n),
                                      completion_tokens=round(ct / n)) if n else None)
print(json.dumps(out, indent=1))
if a.json:
    json.dump(out, open(a.json, "w"), indent=1)
