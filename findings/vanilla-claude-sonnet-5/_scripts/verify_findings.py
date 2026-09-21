#!/usr/bin/env python3
"""Phase 2 of the vanilla-claude-sonnet-5 static-audit baseline.

READ-ONLY mechanical verification gate. Never executes, installs, or
contacts any target. For every `flag` row emitted by a shard reviewer, this
re-grounds the claim against the source tree instead of trusting the LLM's
self-report -- this is the check CLAUDE.md SS1 and HANDOFF SS9 exist for.

For every row with verdict == "flag":
  1. eval/targets/<slug>/<file> exists, and is not under .git/, node_modules/,
     .venv/, venv/, or __pycache__/ (dependency evidence lives in a separate
     dep_evidence field and is checked the same way, if present).
  2. `excerpt` appears verbatim (whitespace-normalised: collapse runs of
     whitespace to a single space, strip) somewhere in that file, and the
     matching line is within +/-10 lines of the row's `line`.
  3. `tool` is in that repo's tools[] in eval/state/prepared.jsonl, and
     eval/configs/<slug>__<tool>.json exists on disk.
  4. `cwe` is in the taxonomy this audit committed to; `tier` in {A, B}.

Rows that fail ANY check move to rejected.jsonl with the specific reason and
are NOT counted toward the headline numbers. clear rows are not re-verified
here (nothing to ground -- absence of a sink is not mechanically checkable);
Phase 3 (recall cross-check) is the counterpart for clear verdicts.

Run: python3 findings/vanilla-claude-sonnet-5/_scripts/verify_findings.py
"""
import json
import os
import re
import sys
import collections

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
TARGETS = os.path.join(ROOT, "eval", "targets")
CONFIGS = os.path.join(ROOT, "eval", "configs")
PREPARED = os.path.join(ROOT, "eval", "state", "prepared.jsonl")
SHARDS_OUT = os.path.join(os.path.dirname(__file__), "..", "shards", "out")
MANIFEST = os.path.join(os.path.dirname(__file__), "..", "shards", "manifest.json")
REJECTED_OUT = os.path.join(os.path.dirname(__file__), "..", "rejected.jsonl")

EXCLUDE_PATH_PARTS = {".git", "node_modules", ".venv", "venv", "__pycache__"}

# The taxonomy this audit committed to (plan, Phase 1 "CWE taxonomy").
# Per the plan: "Anything outside the list must be argued in `why`" -- so an
# off-list CWE is not a grounding failure by itself, it is a taxonomy
# EXTENSION that must carry a real justification. Rows are only rejected for
# a CWE reason if the field doesn't parse as CWE identifier(s) at all, or if
# it's off-list with no substantive `why`.
ALLOWED_CWE = {
    "CWE-78", "CWE-88", "CWE-94", "CWE-95", "CWE-22", "CWE-23", "CWE-73",
    "CWE-918", "CWE-117", "CWE-798", "CWE-377", "CWE-200", "CWE-532",
    "CWE-552", "CWE-89", "CWE-502", "CWE-611", "CWE-400", "CWE-1333",
    "CWE-306", "CWE-862", "CWE-829",
}
ALLOWED_TIER = {"A", "B"}
CWE_RE = re.compile(r"CWE-\d+")
MIN_JUSTIFICATION_LEN = 20  # chars in `why`, for an off-taxonomy CWE


def slug_of(repo):
    owner, name = repo.split("/", 1)
    return f"{owner}__{name}"


def norm_ws(s):
    return re.sub(r"\s+", " ", s).strip()


def norm_tight(s):
    """Strip ALL whitespace, not just collapse it. A multi-line function call
    like `runProcess(\n  x,\n  y\n)` reflowed by a reviewer into a compact
    one-line excerpt `runProcess(x, y)` differs from the source only in
    exactly where whitespace falls (a space that follows a newline in the
    original vanishes when the call is written on one line) -- not in the
    code itself. Matching is done on whitespace-free text so that reflow
    does not register as "excerpt not found"; the line-window check below is
    what still catches a genuinely wrong or invented citation."""
    return re.sub(r"\s+", "", s)


def load_prepared():
    by_repo = {}
    with open(PREPARED) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            row = json.loads(line)
            by_repo[row["repo"]] = row
    return by_repo


def path_is_excluded(rel_path):
    parts = set(rel_path.split(os.sep))
    return bool(parts & EXCLUDE_PATH_PARTS)


ELLIPSIS_RE = re.compile(r"\s*(?:\.\.\.|…)\s*")


def excerpt_fragments(excerpt):
    """Split an excerpt on literal '...'/'…' elision markers into the
    substrings a reviewer actually claims appear in the file. Most excerpts
    have none (a single fragment); some condense a multi-statement handler
    into "stmt1 ... stmt2 ... stmt3" -- each stmt must still be a verbatim,
    in-order substring, just not contiguous."""
    parts = [norm_ws(p) for p in ELLIPSIS_RE.split(excerpt)]
    return [p for p in parts if p]


def fragments_found_in_order(fragments, text):
    pos = 0
    for frag in fragments:
        idx = text.find(frag, pos)
        if idx == -1:
            return False
        pos = idx + len(frag)
    return True


def check_file_and_excerpt(slug, file_rel, excerpt, line_no):
    """Returns (ok: bool, reason: str|None)."""
    if path_is_excluded(file_rel):
        return False, f"file path under excluded dir: {file_rel}"
    abs_path = os.path.join(TARGETS, slug, file_rel)
    if not os.path.isfile(abs_path):
        return False, f"file does not exist: {file_rel}"
    try:
        with open(abs_path, "r", errors="replace") as f:
            lines = f.readlines()
    except OSError as e:
        return False, f"could not read file: {e}"

    fragments = [norm_tight(f) for f in excerpt_fragments(excerpt)]
    if not fragments:
        return False, "empty excerpt"

    lo = max(0, (line_no or 1) - 1 - 10)
    hi = min(len(lines), (line_no or 1) - 1 + 10 + 1)
    window_text = norm_tight("".join(lines[lo:hi]))
    if fragments_found_in_order(fragments, window_text):
        return True, None

    # fall back to whole-file search, but report as a line-window miss if found
    whole_text = norm_tight("".join(lines))
    if fragments_found_in_order(fragments, whole_text):
        return False, f"excerpt found but not within +/-10 lines of line={line_no}"
    if len(fragments) > 1:
        return False, ("excerpt fragments (ellipsis-joined) not all found "
                        "verbatim, in order, in file")
    return False, "excerpt not found verbatim (whitespace-normalised) in file"


def check_tool_and_config(repo, tool, prepared_row):
    if prepared_row is None:
        return False, "repo not in prepared.jsonl"
    if tool not in (prepared_row.get("tools") or []):
        return False, f"tool not in prepared.jsonl tools[] for {repo}"
    slug = slug_of(repo)
    cfg_path = os.path.join(CONFIGS, f"{slug}__{tool}.json")
    if not os.path.isfile(cfg_path):
        return False, f"missing config file: {os.path.basename(cfg_path)}"
    return True, None


def check_cwe(cwe, why):
    """Returns (ok, reason|None, is_extension: bool)."""
    if not cwe or not isinstance(cwe, str):
        return False, f"cwe field missing or not a string: {cwe!r}", False
    ids = CWE_RE.findall(cwe)
    if not ids:
        return False, f"cwe does not parse as CWE-<n>: {cwe!r}", False
    is_extension = any(i not in ALLOWED_CWE for i in ids)
    if is_extension and len(norm_ws(why or "")) < MIN_JUSTIFICATION_LEN:
        return False, (f"cwe off-taxonomy ({cwe}) with no substantive `why` "
                        f"justification"), True
    return True, None, is_extension


def verify_row(row, prepared_by_repo):
    reasons = []
    is_extension = False
    repo = row.get("repo")
    tool = row.get("tool")
    slug = slug_of(repo) if repo else None

    ok_tc, why_tc = check_tool_and_config(repo, tool, prepared_by_repo.get(repo))
    if not ok_tc:
        reasons.append(why_tc)

    ok_cwe, why_cwe, is_extension = check_cwe(row.get("cwe"), row.get("why"))
    if not ok_cwe:
        reasons.append(why_cwe)

    tier = row.get("tier")
    if tier not in ALLOWED_TIER:
        reasons.append(f"tier not in {{A,B}}: {tier}")

    file_rel = row.get("file")
    excerpt = row.get("excerpt")
    line_no = row.get("line")
    if not file_rel or not excerpt:
        reasons.append("missing file or excerpt field")
    else:
        ok_fe, why_fe = check_file_and_excerpt(slug, file_rel, excerpt, line_no)
        if not ok_fe:
            reasons.append(why_fe)

    # dep_evidence: same grounding, if the row claims dependency-level evidence
    dep = row.get("dep_evidence")
    if dep and isinstance(dep, dict) and dep.get("file"):
        ok_de, why_de = check_file_and_excerpt(
            slug, dep["file"], dep.get("excerpt", ""), dep.get("line"))
        if not ok_de:
            reasons.append(f"dep_evidence: {why_de}")

    return reasons, is_extension


def load_and_verify():
    """Reusable by aggregate.py (Phase 4). Returns a dict with all_rows,
    flagged, cleared, accepted, rejected, incomplete_shards, n_extensions,
    reason_counts -- the full result of one verification pass, without
    printing or writing rejected.jsonl (callers decide what to do with it)."""
    prepared_by_repo = load_prepared()

    if not os.path.isfile(MANIFEST):
        raise FileNotFoundError(f"manifest not found at {MANIFEST}")
    manifest = json.load(open(MANIFEST))

    incomplete_shards = []
    all_rows = []
    for s in manifest["shards"]:
        sid = s["shard_id"]
        expected = s["n_configs"]
        path = os.path.join(SHARDS_OUT, f"shard_{sid}.jsonl")
        if not os.path.isfile(path):
            incomplete_shards.append((sid, 0, expected))
            continue
        with open(path) as f:
            rows = [json.loads(l) for l in f if l.strip()]
        if len(rows) != expected:
            incomplete_shards.append((sid, len(rows), expected))
        for r in rows:
            r["_shard_id"] = sid
        all_rows.extend(rows)

    flagged = [r for r in all_rows if r.get("verdict") == "flag"]
    cleared = [r for r in all_rows if r.get("verdict") == "clear"]
    other_verdict = [r for r in all_rows
                      if r.get("verdict") not in ("flag", "clear")]

    accepted = []
    rejected = []
    reason_counts = collections.Counter()
    n_extensions = 0

    for row in flagged:
        reasons, is_extension = verify_row(row, prepared_by_repo)
        if is_extension and not reasons:
            n_extensions += 1
        if reasons:
            rej = dict(row)
            rej["_rejection_reasons"] = reasons
            rejected.append(rej)
            for r in reasons:
                # bucket by the stable prefix (drop file/line/cwe specifics)
                bucket = re.sub(r"[:=].*$", "", r).strip()
                reason_counts[bucket] += 1
        else:
            accepted.append(row)

    for row in other_verdict:
        rej = dict(row)
        rej["_rejection_reasons"] = [f"unrecognised verdict: {row.get('verdict')}"]
        rejected.append(rej)

    return {
        "all_rows": all_rows, "flagged": flagged, "cleared": cleared,
        "accepted": accepted, "rejected": rejected,
        "incomplete_shards": incomplete_shards,
        "n_extensions": n_extensions, "reason_counts": reason_counts,
    }


def main():
    result = load_and_verify()
    incomplete_shards = result["incomplete_shards"]
    all_rows, flagged, cleared = result["all_rows"], result["flagged"], result["cleared"]
    accepted, rejected = result["accepted"], result["rejected"]
    n_extensions, reason_counts = result["n_extensions"], result["reason_counts"]

    if incomplete_shards:
        print(f"WARNING: {len(incomplete_shards)} shard(s) incomplete or missing "
              f"-- verification will run on what exists, but the corpus is NOT "
              f"complete. Re-run once all shards match their manifest line count.")
        for sid, got, exp in incomplete_shards:
            print(f"  shard_{sid}: {got}/{exp} rows")

    with open(REJECTED_OUT, "w") as f:
        for r in rejected:
            f.write(json.dumps(r) + "\n")

    n_other = len(all_rows) - len(flagged) - len(cleared)
    total_flagged = len(flagged)
    n_rejected = len(rejected) - n_other  # flag-verdict rejects only
    rate = (n_rejected / total_flagged) if total_flagged else 0.0

    print()
    print(f"total rows read:        {len(all_rows)}")
    print(f"  clear:                 {len(cleared)}")
    print(f"  flag:                  {len(flagged)}")
    print(f"  other/malformed:       {n_other}")
    print()
    print(f"flag rows ACCEPTED (grounded):  {len(accepted)}")
    print(f"  of which taxonomy EXTENSIONS (off-list CWE, justified): {n_extensions}")
    print(f"flag rows REJECTED (ungrounded): {n_rejected}")
    print(f"grounding-failure rate: {rate:.1%}")
    print()
    if reason_counts:
        print("rejection reasons (bucketed):")
        for reason, n in reason_counts.most_common():
            print(f"  {n:4d}  {reason}")
    print()
    print(f"wrote {len(rejected)} rejected row(s) to "
          f"{os.path.relpath(REJECTED_OUT, ROOT)}")

    return {
        "total_rows": len(all_rows),
        "n_clear": len(cleared),
        "n_flag": len(flagged),
        "n_accepted": len(accepted),
        "n_extensions": n_extensions,
        "n_rejected": n_rejected,
        "grounding_failure_rate": rate,
        "incomplete_shards": incomplete_shards,
    }


if __name__ == "__main__":
    main()
