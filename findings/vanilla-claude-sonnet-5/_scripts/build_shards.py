#!/usr/bin/env python3
"""Phase 0 of the vanilla-claude-sonnet-5 static-audit baseline.

READ-ONLY. Never executes, installs, or contacts any target. It only reads:
  - eval/state/prepared.jsonl   (repo, lang, commit, tools[])
  - eval/configs/*.json         (ground truth for the exact (repo, tool) set)
  - eval/cisco_runs/*.json      (tool_name -> tool_description, per repo)
  - eval/targets/<slug>/**      (source files, for LOC sizing + hint-grep)

Writes, under this script's parent dir (findings/vanilla-claude-sonnet-5/):
  - shards/shard_NNN.json  -- one review unit per reviewer subagent
  - shards/manifest.json   -- summary + sha256 of the shard set, for
                              reproducibility (METHODOLOGY.md links here)

Before writing anything, asserts:
  (a) the union of all shard (repo, tool) pairs equals exactly the set of
      configs in eval/configs/*.json (no config missing, none invented)
  (b) shards are pairwise disjoint

Run: python3 findings/vanilla-claude-sonnet-5/_scripts/build_shards.py
"""
import json
import os
import re
import hashlib
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TARGETS = os.path.join(ROOT, "eval", "targets")
CONFIGS = os.path.join(ROOT, "eval", "configs")
PREPARED = os.path.join(ROOT, "eval", "state", "prepared.jsonl")
CISCO_RUNS = os.path.join(ROOT, "eval", "cisco_runs")
OUT_DIR = os.path.join(os.path.dirname(__file__), "..", "shards")

EXCLUDE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "__pycache__", "dist", "build",
    ".pytest_cache", "coverage", ".next", ".nyc_output", "egg-info",
    "test", "tests", "__tests__", "spec", "specs", ".mypy_cache", "htmlcov",
}
SRC_EXT = {".py", ".js", ".ts", ".mjs", ".cjs", ".tsx", ".jsx"}
MAX_FILE_BYTES = 900_000  # matches extract_tools.py convention

# Shard budgets (Phase 0, plan §"build the review manifest")
MAX_CONFIGS_PER_SHARD = 150
MAX_LOC_PER_SHARD = 25_000
MAX_REPOS_PER_SHARD = 15
GIANT_SURFACE_LOC = 12_000  # repos at/above this size get their own shard


def load_jsonl(path):
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


def load_configs_ground_truth():
    """Return {(repo, tool): config_filename} from eval/configs/*.json."""
    gt = {}
    for fn in os.listdir(CONFIGS):
        if not fn.endswith(".json"):
            continue
        path = os.path.join(CONFIGS, fn)
        with open(path) as f:
            cfg = json.load(f)
        repo = cfg.get("_repo")
        tool = cfg.get("target_tool")
        if repo and tool:
            gt[(repo, tool)] = fn
    return gt


def load_cisco_descriptions():
    """Return {slug: {tool_name: description}}."""
    out = {}
    if not os.path.isdir(CISCO_RUNS):
        return out
    for fn in os.listdir(CISCO_RUNS):
        if not fn.endswith(".json"):
            continue
        slug = fn[:-5]
        try:
            with open(os.path.join(CISCO_RUNS, fn)) as f:
                data = json.load(f)
        except Exception:
            continue
        tool_map = {}
        for item in data.get("scan_results") or []:
            if isinstance(item, dict) and item.get("item_type") == "tool":
                name = item.get("tool_name")
                desc = item.get("tool_description") or ""
                if name:
                    tool_map[name] = desc
        if tool_map:
            out[slug] = tool_map
    return out


def iter_source_files(repo_dir):
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS and not d.startswith(".")]
        for fn in files:
            ext = os.path.splitext(fn)[1]
            if ext in SRC_EXT:
                full = os.path.join(root, fn)
                try:
                    if os.path.getsize(full) > MAX_FILE_BYTES:
                        continue
                except OSError:
                    continue
                yield full


def scan_repo(repo_dir, tool_names):
    """Return (surface_loc, {tool_name: [{"file":rel,"line":n,"text":str}]})."""
    surface_loc = 0
    hints = {t: [] for t in tool_names}
    # cheap literal patterns per tool: quoted string, or python def
    for path in iter_source_files(repo_dir):
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
        except OSError:
            continue
        surface_loc += len(lines)
        rel = os.path.relpath(path, repo_dir)
        for tool in tool_names:
            if len(hints[tool]) >= 5:
                continue
            # only bother scanning this file for this tool if the literal
            # substring appears at all (fast reject before per-line regex)
            joined = None
            for i, line in enumerate(lines, 1):
                if tool in line:
                    if joined is None:
                        joined = True
                    hints[tool].append({"file": rel, "line": i, "text": line.strip()[:200]})
                    if len(hints[tool]) >= 5:
                        break
    return surface_loc, hints


def main():
    prepared = load_jsonl(PREPARED)
    by_repo = {}
    for row in prepared:
        by_repo[row["repo"]] = row  # later rows (dedup) win; all are status ready

    gt = load_configs_ground_truth()
    gt_repos = sorted({r for (r, t) in gt})
    print(f"[build_shards] ground truth: {len(gt)} configs across {len(gt_repos)} repos", file=sys.stderr)

    cisco_desc = load_cisco_descriptions()

    repo_units = []
    total_configs_expected = 0
    for repo in gt_repos:
        row = by_repo.get(repo)
        if row is None:
            print(f"[build_shards] WARNING: {repo} in configs but not in prepared.jsonl -- skipping", file=sys.stderr)
            continue
        slug = repo.replace("/", "__")
        repo_dir = os.path.join(TARGETS, slug)
        if not os.path.isdir(repo_dir):
            print(f"[build_shards] WARNING: {repo} has no clone dir at {repo_dir} -- skipping", file=sys.stderr)
            continue
        tools = sorted({t for (r, t) in gt if r == repo})
        total_configs_expected += len(tools)
        surface_loc, hints = scan_repo(repo_dir, tools)
        desc_map = cisco_desc.get(slug, {})
        tool_entries = []
        for t in tools:
            tool_entries.append({
                "name": t,
                "description": desc_map.get(t, ""),
                "config": gt[(repo, t)],
                "hints": hints.get(t, []),
            })
        repo_units.append({
            "repo": repo,
            "slug": slug,
            "lang": row.get("lang"),
            "commit": row.get("commit"),
            "path": os.path.relpath(repo_dir, ROOT),
            "surface_loc": surface_loc,
            "tools": tool_entries,
        })

    print(f"[build_shards] scanned {len(repo_units)} repos, {sum(len(r['tools']) for r in repo_units)} tool entries", file=sys.stderr)

    # --- shard packing ---
    repo_units.sort(key=lambda r: -r["surface_loc"])
    shards = []
    giants = [r for r in repo_units if r["surface_loc"] >= GIANT_SURFACE_LOC]
    normal = [r for r in repo_units if r["surface_loc"] < GIANT_SURFACE_LOC]

    for g in giants:
        shards.append([g])

    cur = []
    cur_configs = 0
    cur_loc = 0
    for r in normal:
        n_tools = len(r["tools"])
        if cur and (
            cur_configs + n_tools > MAX_CONFIGS_PER_SHARD
            or cur_loc + r["surface_loc"] > MAX_LOC_PER_SHARD
            or len(cur) + 1 > MAX_REPOS_PER_SHARD
        ):
            shards.append(cur)
            cur, cur_configs, cur_loc = [], 0, 0
        cur.append(r)
        cur_configs += n_tools
        cur_loc += r["surface_loc"]
    if cur:
        shards.append(cur)

    # --- completeness + disjointness assertions ---
    seen_pairs = set()
    union_pairs = set()
    for shard in shards:
        for r in shard:
            for t in r["tools"]:
                pair = (r["repo"], t["name"])
                assert pair not in seen_pairs, f"duplicate pair across shards: {pair}"
                seen_pairs.add(pair)
                union_pairs.add(pair)

    expected_pairs = set(gt.keys())
    missing = expected_pairs - union_pairs
    extra = union_pairs - expected_pairs
    assert not missing, f"{len(missing)} configs missing from shards, e.g. {list(missing)[:5]}"
    assert not extra, f"{len(extra)} invented pairs not in eval/configs, e.g. {list(extra)[:5]}"
    assert len(union_pairs) == len(gt), "union size mismatch"

    print(f"[build_shards] OK: {len(shards)} shards, union == {len(union_pairs)} configs == ground truth, disjoint", file=sys.stderr)

    # --- write shard files ---
    os.makedirs(OUT_DIR, exist_ok=True)
    os.makedirs(os.path.join(OUT_DIR, "out"), exist_ok=True)
    manifest = {"shards": [], "total_configs": len(union_pairs), "total_repos": len(repo_units)}
    for i, shard in enumerate(shards):
        shard_id = f"{i:03d}"
        n_configs = sum(len(r["tools"]) for r in shard)
        n_loc = sum(r["surface_loc"] for r in shard)
        payload = {
            "shard_id": shard_id,
            "n_repos": len(shard),
            "n_configs": n_configs,
            "surface_loc": n_loc,
            "repos": shard,
        }
        out_path = os.path.join(OUT_DIR, f"shard_{shard_id}.json")
        with open(out_path, "w") as f:
            json.dump(payload, f, indent=1)
        digest = hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()[:16]
        manifest["shards"].append({
            "shard_id": shard_id,
            "file": os.path.basename(out_path),
            "n_repos": len(shard),
            "n_configs": n_configs,
            "surface_loc": n_loc,
            "repos": [r["repo"] for r in shard],
            "sha256_16": digest,
        })

    manifest_sha = hashlib.sha256(json.dumps(manifest, sort_keys=True).encode()).hexdigest()
    manifest["manifest_sha256"] = manifest_sha
    with open(os.path.join(OUT_DIR, "manifest.json"), "w") as f:
        json.dump(manifest, f, indent=1)

    print(f"[build_shards] wrote {len(shards)} shard files to {OUT_DIR}", file=sys.stderr)
    print(f"[build_shards] manifest sha256: {manifest_sha}", file=sys.stderr)
    print(f"[build_shards] shard sizes (configs): {sorted(s['n_configs'] for s in manifest['shards'])}", file=sys.stderr)


if __name__ == "__main__":
    main()
