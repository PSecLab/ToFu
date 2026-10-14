#!/usr/bin/env python3
"""Emit set_full.json: EVERY tool-exposing repo in the scanned corpus (1404),
so ToFu can be run over the whole thing (not just the sampled sets).

Source of truth is results.jsonl (the scan output): each row already carries a
pinned `commit`, `lang`, `stars`, `n_tools` and a `sinks` map. No re-scan.

Rows are ordered by a PRIORITY TIER so a streaming campaign fuzzes the repos
most likely to yield findings first (our confirmed/potential bugs are all in
file-write / file-read / exec / code sinks), and API/log-only repos last:

  python3 Benchmarks/extraction/build_set_full.py            # -> set_full.json
  python3 Benchmarks/extraction/build_set_full.py --tier 1   # only tier-1 repos
"""
import argparse, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
RESULTS = os.path.join(HERE, "results.jsonl")
OUT = os.path.join(HERE, "set_full.json")

# sink families where V1/V4/V6/V7 (and the classic MCP bugs) live -> tier 1
PRIORITY_SINKS = {
    "FileWrite", "FileAccess", "CommandExecution", "CodeExecution",
    "SQLExecution", "Deserialization", "UnverifiedCodeDownload",
    "UnrestrictedFileUpload", "ArchiveExtraction",
}


def tier(row):
    sinks = row.get("sinks") or {}
    keys = set(sinks.keys()) if isinstance(sinks, dict) else set()
    return 1 if (keys & PRIORITY_SINKS) else 2


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tier", type=int, choices=[1, 2], default=None,
                    help="emit only this tier (1 = high-value sinks first)")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(RESULTS) if l.strip()]
    tool_rows = [r for r in rows if (r.get("n_tools") or 0) > 0 and r.get("commit")]
    out = []
    for r in tool_rows:
        t = tier(r)
        if a.tier and t != a.tier:
            continue
        out.append({
            "repo": r["repo"],
            "commit": r["commit"],
            "last_commit": r.get("last_commit"),
            "lang": r["lang"],
            "stars": r.get("stars"),
            "set": "FULL",
            "n_tools": r.get("n_tools"),
            "_tier": t,
            "_sinks": sorted((r.get("sinks") or {}).keys()) if isinstance(r.get("sinks"), dict) else [],
        })
    # tier 1 first, then by tool count desc within tier (cheap wins early)
    out.sort(key=lambda x: (x["_tier"], -(x["n_tools"] or 0)))
    json.dump({"set_full": out}, open(a.out, "w"), indent=1)

    import collections
    byl = collections.Counter(x["lang"] for x in out)
    byt = collections.Counter(x["_tier"] for x in out)
    print(f"wrote {a.out}: {len(out)} repos  lang={dict(byl)}  tier={dict(byt)}  "
          f"tools={sum(x['n_tools'] or 0 for x in out)}")


if __name__ == "__main__":
    main()
