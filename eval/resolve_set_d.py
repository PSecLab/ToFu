#!/usr/bin/env python3
"""
Resolve Benchmarks/extraction/set_d_manifest.json (ground truth transcribed
from the VIPER-MCP paper) into the harness-ready Benchmarks/extraction/set_d.json.

For every repo in the manifest we look up the CURRENT GitHub default-branch
HEAD via `git ls-remote` (no GitHub API token needed, so it runs anywhere with
plain HTTPS to github.com). We do NOT have the paper's vulnerable commit -- the
CVE numbers are redacted and no commit is published -- so HEAD is the best
resolvable pin, with the loud caveat that a patched HEAD is a documented
false-negative source, not a ToFu miss.

    python3 eval/resolve_set_d.py            # writes set_d.json + set_d_unresolved.json

Re-run any time to refresh HEADs; it is idempotent and prints a diff summary.
Repos that no longer resolve (deleted / renamed / private) are written to
set_d_unresolved.json with a reason and left OUT of set_d.json rather than
guessed at.
"""
import json, os, subprocess, sys, datetime
from collections import Counter

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE) if os.path.basename(HERE) == "eval" else HERE
EXTR = os.path.join(ROOT, "Benchmarks", "extraction")
MANIFEST = os.path.join(EXTR, "set_d_manifest.json")
OUT = os.path.join(EXTR, "set_d.json")
UNRES = os.path.join(EXTR, "set_d_unresolved.json")


def head_sha(repo):
    """Current default-branch HEAD, or None if the repo will not resolve."""
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0")
    for _ in range(2):  # one retry to ride out a transient hiccup
        try:
            out = subprocess.run(
                ["git", "ls-remote", f"https://github.com/{repo}", "HEAD"],
                capture_output=True, text=True, timeout=30, env=env).stdout
            if out.strip():
                return out.split()[0]
        except subprocess.TimeoutExpired:
            pass
    return None


def main():
    if not os.path.exists(MANIFEST):
        sys.exit(f"missing {MANIFEST} -- build it from the paper first")
    man = json.load(open(MANIFEST))

    # collapse manifest entries to one record per distinct repo (a repo can
    # appear under several classes, e.g. 54yyyu/code-mcp = path + cmdi)
    per_repo = {}
    ownerless = []
    for e in man["entries"]:
        repo = e.get("repo")
        if not repo:
            ownerless.append(e)          # e.g. lanhu-mcp, owner not in paper
            continue
        r = per_repo.setdefault(repo, {
            "repo": repo, "lang": e["lang"], "classes": set(),
            "tier": "silver", "vulnerable_tool": None, "poc_prompt": None})
        r["classes"].add(e["vuln_class"])
        if e["tier"] == "gold":
            r["tier"] = "gold"
            r["vulnerable_tool"] = e.get("vulnerable_tool") or r["vulnerable_tool"]
            r["poc_prompt"] = e.get("poc_prompt") or r["poc_prompt"]

    prev = {}
    if os.path.exists(OUT):
        for r in json.load(open(OUT)).get("set_d", []):
            prev[r["repo"]] = r.get("commit")

    records, unresolved = [], []
    for repo, r in sorted(per_repo.items()):
        sys.stderr.write(f"  resolving {repo} ... ")
        sha = head_sha(repo)
        if not sha:
            sys.stderr.write("UNRESOLVED\n")
            unresolved.append({"repo": repo, "reason":
                "git ls-remote could not read HEAD (deleted, renamed, or private)",
                "vuln_class": sorted(r["classes"]), "lang": r["lang"]})
            continue
        moved = prev.get(repo) and prev[repo] != sha
        sys.stderr.write(sha[:12] + (" (moved)\n" if moved else "\n"))
        rec = {"repo": repo, "lang": r["lang"], "commit": sha,
               "vuln_class": sorted(r["classes"]), "tier": r["tier"],
               "commit_provenance": "github HEAD @ resolve time (NOT the paper's "
                                    "vulnerable commit; may be patched)",
               "source": "VIPER-MCP arXiv 2605.21392v2 Appendix B"
                         + (" + Table 1/App.C" if r["tier"] == "gold" else "")}
        if r["vulnerable_tool"]:
            rec["vulnerable_tool"] = r["vulnerable_tool"]
        if r["poc_prompt"]:
            rec["poc_prompt"] = r["poc_prompt"]
        records.append(rec)

    for e in ownerless:
        unresolved.append({"repo": None, "repo_slug_hint": e.get("repo_slug_hint"),
            "reason": "repository owner is not given anywhere in the paper",
            "vuln_class": [e["vuln_class"]], "lang": e["lang"],
            "tier": e["tier"], "vulnerable_tool": e.get("vulnerable_tool"),
            "poc_prompt": e.get("poc_prompt")})

    records.sort(key=lambda x: (x["tier"] != "gold", x["repo"]))
    json.dump({
        "_about": "Harness-ready Set D: VIPER-MCP's own 0-day servers resolved to "
                  "real GitHub commits. Read by prepare_targets.py --only-set d.",
        "_generated": datetime.datetime.utcnow().isoformat() + "Z",
        "_manifest": "Benchmarks/extraction/set_d_manifest.json",
        "_resolved": len(records), "_unresolved": len(unresolved),
        "_warning": "commit = GitHub HEAD at resolve time, NOT the paper's vulnerable "
                    "revision. A patched HEAD is a documented false negative, not a miss.",
        "set_d": records}, open(OUT, "w"), indent=1)
    json.dump({"unresolved": unresolved,
               "note": "Excluded from set_d.json; resolve manually before including."},
              open(UNRES, "w"), indent=1)

    print(f"\nresolved={len(records)} unresolved={len(unresolved)}")
    print("tiers:", dict(Counter(r["tier"] for r in records)))
    print("classes:", dict(Counter(c for r in records for c in r["vuln_class"])))
    print(f"wrote {OUT}")
    print(f"wrote {UNRES}")


if __name__ == "__main__":
    main()
