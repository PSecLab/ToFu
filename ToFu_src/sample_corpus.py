#!/usr/bin/env python3
"""
Deterministic, reproducible sampling of MCP servers for ToFu's evaluation
corpus, drawn from MCPCorpus (Lin, Ruan, Liu, Zhao; ASE 2025 Tool
Demonstrations; arXiv:2506.23474).

Replaces the "top of https://github.com/mcp" + "first GitHub search result for
AI tool" selection in sec6_eval.tex with a procedure any reader can re-run and
get the identical target list.

DATA SOURCE (verified reachable, no HuggingFace / no API token needed):
  https://raw.githubusercontent.com/Snakinya/MCPCorpus/main/Website/mcpso_servers_cleaned.json
  ~13 MB, 13,875 server records, downloads in <10s.

VERIFIED SCHEMA (as of the snapshot committed 2025-09-01):
  top level : id, name, url, title, description, author_name, tags, category,
              type, tools, sse_url, server_command, server_config, github
  github{}  : full_name, stargazers_count, forks_count, contributors_count,
              open_issues_count, language, languages, license, archived,
              last_commit, has_docker, has_readme, has_requirements

Usage:
    python3 sample_corpus.py --n 25 --seed 20260908 --out targets.csv
    python3 sample_corpus.py --local servers.json --n 25      # offline

WHY EACH FILTER IS HERE (state these in the paper's setup subsection):
  type != "client"        the servers file is already servers-only; the
                          "type" field is None on 12,976 of 13,875 records, so
                          filtering FOR "server" would discard 93% of the
                          corpus. Only the 3 explicitly-tagged clients go.
  github.full_name        we must be able to clone it to fuzz it.
  stars >= 10             drops toy repos. Same threshold Hasan et al. use in
                          "MCP at First Glance" (TOSEM 2026), so our filtered
                          population stays comparable to theirs.
  not archived            archived == dead, won't accept a disclosure.
  language in {Python, TypeScript, JavaScript}
                          ToFu has exactly two runners (PythonRunner,
                          JSRunner). Everything else is COUNTED AND REPORTED
                          but excluded from the draw -- state the exclusion,
                          don't hide it.

  *** DEDUP BY REPO -- do not remove this step. ***
  MCPCorpus lists each server from a monorepo as a SEPARATE record, all
  pointing at the same GitHub repo. modelcontextprotocol/servers alone appears
  35 times; 20% of the filtered pool belongs to a multi-entry repo. Sampling
  without dedup would draw the same repository several times and reproduce
  exactly the flaw Pierre flagged in the current draft (412 of 569 tools coming
  from a single repository). After dedup the pool is 1,848 unique repos
  (808 Python, 1,040 Node/TS).
"""

import argparse
import csv
import hashlib
import json
import random
import sys
import urllib.request
from datetime import datetime, timezone

CORPUS_URL = ("https://raw.githubusercontent.com/Snakinya/MCPCorpus/"
              "main/Website/mcpso_servers_cleaned.json")
STAR_THRESHOLD = 10
PY = {"Python"}
NODE = {"TypeScript", "JavaScript"}


def load(local=None):
    if local:
        with open(local, "r", encoding="utf-8") as f:
            return json.load(f)
    print(f"[i] downloading {CORPUS_URL}", file=sys.stderr)
    with urllib.request.urlopen(CORPUS_URL, timeout=120) as r:
        return json.loads(r.read().decode("utf-8"))


def gh(rec, key, default=None):
    g = rec.get("github")
    return g.get(key, default) if isinstance(g, dict) else default


def bucket(rec):
    lang = gh(rec, "language")
    if lang in PY:
        return "python"
    if lang in NODE:
        return "node"
    return "other"


def filter_population(rows):
    kept, dropped = [], {}

    def drop(reason):
        dropped[reason] = dropped.get(reason, 0) + 1

    for r in rows:
        # NB: do NOT filter on r["type"] == "server". That field is sparsely
        # populated -- it is None for 12,976 of the 13,875 records. This file
        # (mcpso_servers_cleaned.json) is the servers file by construction;
        # clients live in mcpso_clients_cleaned.json. Only exclude the handful
        # explicitly tagged as clients.
        if r.get("type") == "client":
            drop("explicitly_tagged_client"); continue
        if not gh(r, "full_name"):
            drop("no_github_repo"); continue
        if (gh(r, "stargazers_count") or 0) < STAR_THRESHOLD:
            drop("under_star_threshold"); continue
        if gh(r, "archived"):
            drop("archived"); continue
        kept.append(r)
    return kept, dropped


def dedup_by_repo(rows):
    """One record per GitHub repo. Deterministic tie-break: prefer the record
    carrying a tools schema, then the one with a server_command, then the
    lexicographically smallest server name -- never random, so the choice is
    reproducible."""
    best = {}
    for r in rows:
        key = gh(r, "full_name")
        rank = (bool(r.get("tools")), bool(r.get("server_command")))
        prev = best.get(key)
        if prev is None:
            best[key] = r
            continue
        prev_rank = (bool(prev.get("tools")), bool(prev.get("server_command")))
        if rank > prev_rank or (rank == prev_rank and
                                str(r.get("name", "")) < str(prev.get("name", ""))):
            best[key] = r
    return list(best.values())


def stratified_sample(pool, n, seed):
    rng = random.Random(seed)
    buckets = {"python": [], "node": [], "other": []}
    for r in pool:
        buckets[bucket(r)].append(r)

    drawable = {k: v for k, v in buckets.items() if k != "other" and v}
    total = sum(len(v) for v in drawable.values())
    if not total:
        raise RuntimeError("no Python or Node/JS repos survived filtering")

    alloc = {k: max((len(v) / total) * n, 0.20 * n) for k, v in drawable.items()}
    floors = {k: int(v) for k, v in alloc.items()}
    for k in sorted(alloc, key=lambda k: alloc[k] - floors[k], reverse=True)[:n - sum(floors.values())]:
        floors[k] += 1

    sample = []
    for k, count in floors.items():
        # sort first so rng.sample sees a deterministic ordering
        ordered = sorted(drawable[k], key=lambda r: gh(r, "full_name") or "")
        sample.extend(rng.sample(ordered, min(count, len(ordered))))
    sample.sort(key=lambda r: gh(r, "full_name") or "")
    return sample, floors, buckets


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=25)
    ap.add_argument("--seed", type=int, default=20260908)
    ap.add_argument("--local", default=None, help="local servers.json instead of downloading")
    ap.add_argument("--out", default="targets.csv")
    args = ap.parse_args()

    rows = load(args.local)
    print(f"[i] MCPCorpus records: {len(rows)}")

    filtered, dropped = filter_population(rows)
    print(f"[i] after filters (server, has repo, >={STAR_THRESHOLD} stars, not archived): {len(filtered)}")
    for reason, c in sorted(dropped.items()):
        print(f"      dropped {reason}: {c}")

    pool = dedup_by_repo(filtered)
    print(f"[i] after dedup by GitHub repo: {len(pool)} unique repos "
          f"({len(filtered) - len(pool)} duplicate entries collapsed)")

    sample, alloc, buckets = stratified_sample(pool, args.n, args.seed)
    print(f"[i] language buckets (unique repos): "
          f"python={len(buckets['python'])} node={len(buckets['node'])} "
          f"other={len(buckets['other'])} <- 'other' reported, not sampled (no ToFu runner)")
    print(f"[i] drew {len(sample)} repos, seed={args.seed}, allocation={alloc}")

    fp = hashlib.sha256(",".join(sorted(gh(r, "full_name") for r in sample)).encode()).hexdigest()[:12]

    with open(args.out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["# MCPCorpus-derived ToFu evaluation sample"])
        w.writerow(["# generated_utc", datetime.now(timezone.utc).isoformat()])
        w.writerow(["# source", CORPUS_URL])
        w.writerow(["# seed", args.seed])
        w.writerow(["# n", args.n])
        w.writerow(["# star_threshold", STAR_THRESHOLD])
        w.writerow(["# sample_fingerprint_sha256_12", fp])
        w.writerow([])
        w.writerow(["repo", "url", "language", "stars", "has_docker",
                    "has_requirements", "server_command", "n_tools", "last_commit"])
        for r in sample:
            tools = r.get("tools")
            n_tools = len(tools) if isinstance(tools, list) else (1 if tools else 0)
            w.writerow([gh(r, "full_name"), r.get("url", ""), gh(r, "language"),
                        gh(r, "stargazers_count"), gh(r, "has_docker"),
                        gh(r, "has_requirements"), r.get("server_command", ""),
                        n_tools, gh(r, "last_commit", "")])

    print(f"[i] wrote {args.out} (fingerprint {fp})")
    print("[i] NEXT, and record it: pin each repo to a commit hash, then do a")
    print("    documented post-hoc exclusion pass for local runnability (Docker")
    print("    required? real browser required? install fails?). Report every")
    print("    exclusion with its reason -- never silently redraw to get an")
    print("    easier target.")


if __name__ == "__main__":
    main()
