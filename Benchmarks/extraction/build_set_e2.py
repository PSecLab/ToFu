#!/usr/bin/env python3
"""Emit set_e2.json -- "Set E, recalculated": the subset of the whole-corpus
prep that ACTUALLY cloned + installed + exposed tools (status=ready in
eval/state/prepared.jsonl), ordered and reported for good coverage of both
languages and all sink families.

Why a v2 of Set E: the original Set E (300) was drawn before the whole-corpus
prep, so it is not the same pool. After the 2-tier prepare, the executable
universe is exactly the `ready` rows of prepared.jsonl -- these are the only
repos that have eval/configs/*.json generated, so they are the only ones the
fuzzer can run. This script joins that pool with the scan's per-repo `sinks`
map (results.jsonl) to (a) prove the pool spans both langs and all sink
families and (b) order it tier-1-first so a time-boxed run hits the
bug-bearing sinks (FileWrite/FileAccess/Command/Code/SQL/...) first.

  python3 Benchmarks/extraction/build_set_e2.py
    -> Benchmarks/extraction/set_e2.json         (manifest, tier-ordered)
    -> Benchmarks/extraction/set_e2_repos.txt    (comma-list for --only-repo)
    -> prints the lang x sink coverage matrix + config/time estimate

  --max-repos N   cap the manifest to N repos, chosen round-robin over sink
                  families x lang so a smaller run still covers everything.
"""
import argparse, collections, json, os

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
RESULTS = os.path.join(HERE, "results.jsonl")
PREPARED = os.path.join(ROOT, "eval", "state", "prepared.jsonl")
OUT = os.path.join(HERE, "set_e2.json")
REPOS_TXT = os.path.join(HERE, "set_e2_repos.txt")
TIER1_TXT = os.path.join(HERE, "set_e2_tier1_repos.txt")
UNSAFE_TXT = os.path.join(HERE, "set_e2_unsafe_repos.txt")

# Host-control targets that CRASH the harness when fuzzed without a sandbox:
# they spawn/kill processes or drive the host's session, which cwd (item 91) and
# $TMUX isolation do not contain. Confirmed crashers: UltimateCoderMCP (FS wipe),
# tmux-mcp (killed the campaign's tmux), ClaudeComputerCommander (start_process/
# kill_process -> load 26-30 -> Terminated). Any tool name containing one of
# these marks the repo unsafe-to-fuzz-without-sandbox; skipped via
# --skip-repos-file until a per-target sandbox lands.
DANGER_TOOL_SUBSTR = (
    "kill_process", "force_terminate", "start_process", "kill-session",
    "kill-server", "kill-window", "kill-pane", "execute_command",
    "execute-command", "run_command", "spawn", "terminate",
)

# Same high-value families as build_set_full.py -- every confirmed/potential
# ToFu finding (V1/V4/V6/V7) lives in one of these.
PRIORITY_SINKS = {
    "FileWrite", "FileAccess", "CommandExecution", "CodeExecution",
    "SQLExecution", "Deserialization", "UnverifiedCodeDownload",
    "UnrestrictedFileUpload", "ArchiveExtraction",
}


def norm(repo):
    return (repo or "").strip().lower()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-repos", type=int, default=None,
                    help="cap manifest size; round-robin over (family,lang) to keep coverage")
    ap.add_argument("--prepared", default=PREPARED)
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()

    # 1. sinks + lang from the scan
    sinks_by = {}
    for l in open(RESULTS):
        if not l.strip():
            continue
        r = json.loads(l)
        sk = r.get("sinks")
        sinks_by[norm(r.get("repo"))] = {
            "lang": r.get("lang"),
            "sinks": sorted(sk.keys()) if isinstance(sk, dict) else [],
        }

    # 2. the executable pool = ready rows of prepared.jsonl
    pool = []
    seen = set()
    for l in open(a.prepared):
        if not l.strip():
            continue
        d = json.loads(l)
        if d.get("status") != "ready":
            continue
        repo = d.get("repo")
        key = norm(repo)
        if key in seen:
            continue
        seen.add(key)
        info = sinks_by.get(key, {})
        lang = d.get("lang") or info.get("lang") or ("python" if d.get("python") else "node")
        sinks = info.get("sinks", [])
        tools = d.get("tools") or []
        unsafe = any(sub in t.lower() for t in tools for sub in DANGER_TOOL_SUBSTR)
        pool.append({
            "repo": repo,
            "lang": lang,
            "sinks": sinks,
            "n_tools": len(tools) if tools else (d.get("n_tools_probed") or 0),
            "n_configs": d.get("n_configs") or (len(tools) if tools else 0),
            "commit": d.get("commit"),
            "_tier": 1 if (set(sinks) & PRIORITY_SINKS) else 2,
            "_unsafe": unsafe,
        })

    # 3. coverage matrix (repos per lang x family)
    fam_lang = collections.defaultdict(lambda: collections.Counter())
    for p in pool:
        for s in p["sinks"]:
            fam_lang[s][p["lang"]] += 1
    langs = collections.Counter(p["lang"] for p in pool)

    # 4. order: tier-1 first, then most tools (cheap coverage early)
    pool.sort(key=lambda x: (x["_tier"], -(x["n_tools"] or 0)))

    # 5. optional balanced cap: round-robin over (family, lang) buckets
    chosen = pool
    if a.max_repos and a.max_repos < len(pool):
        buckets = collections.defaultdict(list)
        for p in pool:
            fam = next((s for s in p["sinks"] if s in PRIORITY_SINKS),
                       (p["sinks"][0] if p["sinks"] else "None"))
            buckets[(fam, p["lang"])].append(p)
        picked, picked_keys = [], set()
        order = sorted(buckets)
        i = 0
        while len(picked) < a.max_repos and any(buckets.values()):
            fam, lang = order[i % len(order)]
            if buckets[(fam, lang)]:
                p = buckets[(fam, lang)].pop(0)
                if norm(p["repo"]) not in picked_keys:
                    picked.append(p); picked_keys.add(norm(p["repo"]))
            i += 1
            if i > len(order) * (a.max_repos + 5):
                break
        picked.sort(key=lambda x: (x["_tier"], -(x["n_tools"] or 0)))
        chosen = picked

    json.dump({"set_e2": chosen}, open(a.out, "w"), indent=1)
    with open(REPOS_TXT, "w") as f:
        f.write(",".join(p["repo"] for p in chosen))
    with open(TIER1_TXT, "w") as f:
        f.write(",".join(p["repo"] for p in chosen if p["_tier"] == 1))
    with open(UNSAFE_TXT, "w") as f:
        f.write(",".join(p["repo"] for p in pool if p.get("_unsafe")))

    # 6. report
    byt = collections.Counter(p["_tier"] for p in chosen)
    ncfg = sum(p["n_configs"] or 0 for p in chosen)
    print(f"POOL (ready repos): {len(pool)}   lang={dict(langs)}")
    print(f"CHOSEN: {len(chosen)} repos  tier={dict(byt)}  configs={ncfg}")
    print(f"  est wall @60s/cfg, 5 workers: {ncfg*60/5/3600:.1f} h")
    print(f"wrote {a.out} + {REPOS_TXT} + {TIER1_TXT} "
          f"({sum(1 for p in chosen if p['_tier']==1)} tier-1 repos)")
    print("\nlang x sink-family coverage (repo counts), * = priority sink:")
    print(f"  {'family':28} {'node':>6} {'python':>7}")
    for fam in sorted(fam_lang, key=lambda k: (-sum(fam_lang[k].values()), k)):
        star = "*" if fam in PRIORITY_SINKS else " "
        print(f" {star}{fam:28} {fam_lang[fam].get('node',0):>6} {fam_lang[fam].get('python',0):>7}")


if __name__ == "__main__":
    main()
