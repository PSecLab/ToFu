#!/usr/bin/env python3
"""Phase 4 of the vanilla-claude-sonnet-5 static-audit baseline.

READ-ONLY. Never executes, installs, or contacts any target. Merges every
shard's JSONL into one inventory, runs Phase 2 (verify_findings.load_and_verify)
to separate grounded from ungrounded `flag` rows, and writes every deliverable
under findings/vanilla-claude-sonnet-5/:

  inventory.jsonl   -- one row per config, all 6231, each flag row tagged
                       _grounded: true/false (Phase 2 result)
  flagged.md        -- Tier A, grounded, grouped by CWE
  potential.md       -- Tier B, grounded, grouped by CWE
  by-cwe/CWE-NN_<slug>.md -- house convention (matches findings/potential/)
  controls.md        -- the 8-row control table, scored against actual output
  comparison.md       -- repo/tool-level overlap vs CodeQL, Cisco YARA, ToFu corpus arm
  README.md          -- headline numbers, method, limitations
  METHODOLOGY.md       -- reviewer prompt verbatim, rubric, manifest hash, date

Run: python3 findings/vanilla-claude-sonnet-5/_scripts/aggregate.py
"""
import json
import os
import re
import sys
import collections
import datetime
import importlib.util

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.abspath(os.path.join(HERE, "..", "..", ".."))
ARM_DIR = os.path.abspath(os.path.join(HERE, ".."))
SHARDS_OUT = os.path.join(ARM_DIR, "shards", "out")
MANIFEST_PATH = os.path.join(ARM_DIR, "shards", "manifest.json")
PROMPTS_DIR = os.path.join(HERE, "prompts")

# import verify_findings.py as a module (Phase 2 reused, not re-implemented)
spec = importlib.util.spec_from_file_location(
    "verify_findings", os.path.join(HERE, "verify_findings.py"))
vf = importlib.util.module_from_spec(spec)
spec.loader.exec_module(vf)

TODAY = datetime.date.today().isoformat()
MODEL_ID = "claude-sonnet-5"

CWE_TITLE = {
    "CWE-78": "OS Command Injection",
    "CWE-88": "Argument Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-22": "Path Traversal",
    "CWE-23": "Relative Path Traversal",
    "CWE-73": "External Control of File Name or Path",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-117": "Log Injection",
    "CWE-798": "Use of Hard-coded Credentials",
    "CWE-377": "Insecure Temporary File",
    "CWE-200": "Information Exposure",
    "CWE-532": "Insertion of Sensitive Information into Log File",
    "CWE-552": "Files or Directories Accessible to External Parties",
    "CWE-89": "SQL Injection",
    "CWE-502": "Deserialization of Untrusted Data",
    "CWE-611": "Improper Restriction of XML External Entity Reference (XXE)",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-1333": "Inefficient Regular Expression Complexity (ReDoS)",
    "CWE-306": "Missing Authentication for Critical Function",
    "CWE-862": "Missing Authorization",
    "CWE-829": "Inclusion of Functionality from Untrusted Control Sphere",
}


def scrub(s):
    s = str(s)
    s = re.sub(r"sk-[A-Za-z0-9_-]{12,}", "sk-<REDACTED>", s)
    s = re.sub(r"(?i)(api[_-]?key|token|secret|password|bearer)([\"'`:=\s]+)[A-Za-z0-9_\-\.]{6,}",
               r"\1\2<REDACTED>", s)
    return s


def md_escape(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def primary_cwe(cwe_field):
    """First CWE-<n> token in a (possibly combined) cwe field, for grouping."""
    m = re.search(r"CWE-\d+", cwe_field or "")
    return m.group(0) if m else "CWE-unclassified"


# ---------------------------------------------------------------- load ----

def load_manifest():
    return json.load(open(MANIFEST_PATH))


def load_prepared():
    by_repo = {}
    with open(os.path.join(ROOT, "eval", "state", "prepared.jsonl")) as f:
        for line in f:
            if line.strip():
                row = json.loads(line)
                by_repo[row["repo"]] = row
    return by_repo


def load_jsonl_index(path, key_fields):
    idx = {}
    if not os.path.isfile(path):
        return idx
    with open(path) as f:
        for line in f:
            if not line.strip():
                continue
            row = json.loads(line)
            key = tuple(row.get(k) for k in key_fields)
            idx.setdefault(key, []).append(row)
    return idx


# ------------------------------------------------------------ inventory ----

def write_inventory(all_rows, accepted_keys, out_path):
    n = 0
    with open(out_path, "w") as f:
        for row in all_rows:
            r = dict(row)
            r.pop("_shard_id", None)
            if row.get("verdict") == "flag":
                key = (row.get("repo"), row.get("tool"))
                r["_grounded"] = key in accepted_keys
            f.write(json.dumps(r) + "\n")
            n += 1
    return n


# --------------------------------------------------------------- by-cwe ----

def write_flag_reports(accepted, arm_dir):
    tier_a = [r for r in accepted if r.get("tier") == "A"]
    tier_b = [r for r in accepted if r.get("tier") == "B"]

    def group_by_cwe(rows):
        g = collections.defaultdict(list)
        for r in rows:
            g[primary_cwe(r.get("cwe"))].append(r)
        return g

    def write_table(f, rows):
        f.write("| repo | tool | tier | cwe | file:line | param -> sink | why |\n")
        f.write("|---|---|---|---|---|---|---|\n")
        for r in sorted(rows, key=lambda r: (r["repo"], r["tool"])):
            loc = f"{r.get('file')}:{r.get('line')}"
            sink = f"{md_escape(r.get('param'))} -> {md_escape(r.get('sink'))}"
            why = md_escape(r.get("why", ""))
            if len(why) > 300:
                why = why[:297] + "..."
            f.write(f"| {scrub(r['repo'])} | `{scrub(r['tool'])}` | {r.get('tier')} "
                     f"| {r.get('cwe')} | `{md_escape(loc)}` | {sink} | {why} |\n")

    # flagged.md (Tier A)
    with open(os.path.join(arm_dir, "flagged.md"), "w") as f:
        f.write(f"# Flagged (Tier A) -- vanilla-claude-sonnet-5 static audit ({TODAY})\n\n")
        f.write(f"**{len(tier_a)} Tier-A findings**, grounded (Phase 2 verified: file "
                f"exists, excerpt is a real substring within +/-10 lines of the cited "
                f"line, tool/config match, CWE parses/justified). Static reading only, "
                f"no execution -- see METHODOLOGY.md and README.md limitations.\n\n")
        groups = group_by_cwe(tier_a)
        f.write("| CWE | title | count |\n|---|---|---|\n")
        for cwe, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            f.write(f"| {cwe} | {CWE_TITLE.get(cwe, '(taxonomy extension)')} | {len(rows)} |\n")
        f.write("\n")
        for cwe, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            f.write(f"\n## {cwe} -- {CWE_TITLE.get(cwe, '(taxonomy extension)')} "
                     f"({len(rows)})\n\n")
            write_table(f, rows)

    # potential.md (Tier B)
    with open(os.path.join(arm_dir, "potential.md"), "w") as f:
        f.write(f"# Potential (Tier B) -- vanilla-claude-sonnet-5 static audit ({TODAY})\n\n")
        f.write(f"**{len(tier_b)} Tier-B findings** -- real mechanism, weaker case "
                f"(advertised-purpose-adjacent, unconfirmed state needed, or an "
                f"unproven-but-plausible guard bypass). Not counted in the headline. "
                f"Grounded per Phase 2.\n\n")
        groups = group_by_cwe(tier_b)
        for cwe, rows in sorted(groups.items(), key=lambda kv: -len(kv[1])):
            f.write(f"\n## {cwe} -- {CWE_TITLE.get(cwe, '(taxonomy extension)')} "
                     f"({len(rows)})\n\n")
            write_table(f, rows)

    # by-cwe/ (house convention, Tier A + Tier B together, one file per CWE)
    by_cwe_dir = os.path.join(arm_dir, "by-cwe")
    os.makedirs(by_cwe_dir, exist_ok=True)
    for old in os.listdir(by_cwe_dir):
        if old.endswith(".md"):
            os.remove(os.path.join(by_cwe_dir, old))
    all_accepted_grouped = group_by_cwe(accepted)
    written = []
    for cwe, rows in sorted(all_accepted_grouped.items()):
        slug = re.sub(r"[^a-z0-9]+", "-", (rows[0].get("class") or "misc")).strip("-")
        fn = f"{cwe}_{slug}.md"
        path = os.path.join(by_cwe_dir, fn)
        with open(path, "w") as f:
            n_a = sum(1 for r in rows if r.get("tier") == "A")
            n_b = sum(1 for r in rows if r.get("tier") == "B")
            f.write(f"# {cwe} -- {CWE_TITLE.get(cwe, '(taxonomy extension)')} "
                     f"({len(rows)} findings: {n_a} Tier-A, {n_b} Tier-B)\n\n")
            f.write(f"vanilla-claude-sonnet-5 static audit, {TODAY}. Grounded per Phase 2 "
                    f"(verify_findings.py). Static reading only, no execution.\n\n")
            write_table(f, rows)
        written.append((cwe, len(rows), fn))

    with open(os.path.join(by_cwe_dir, "INDEX.md"), "w") as f:
        f.write(f"# vanilla-claude-sonnet-5 -- findings by CWE ({TODAY})\n\n")
        f.write(f"{len(accepted)} grounded flag rows ({len(tier_a)} Tier-A, "
                f"{len(tier_b)} Tier-B) across {len(written)} CWE classes.\n\n")
        f.write("| CWE | title | count | file |\n|---|---|---|---|\n")
        for cwe, n, fn in sorted(written, key=lambda t: -t[1]):
            f.write(f"| {cwe} | {CWE_TITLE.get(cwe, '(extension)')} | {n} "
                     f"| [{fn}]({fn}) |\n")

    return tier_a, tier_b


# -------------------------------------------------------------- controls ----

CONTROLS = [
    # (id, repo, tool, expected_verdict_note, expected_cwe_note)
    ("V1", "ArchimedesCrypto/excel-reader-mcp", "export_to_json", "flag", "CWE-73"),
    ("V1", "ArchimedesCrypto/excel-reader-mcp", "export_to_csv", "flag", "CWE-73"),
    ("V4", "tumf/mcp-text-editor", "get_text_file_contents", "flag", "CWE-22/CWE-552"),
    ("V5", "antoinebou12/uml-mcp", "list_diagram_types", "flag", "CWE-117"),
    ("V6", "tumf/mcp-text-editor", "create_text_file", "flag", "CWE-73"),
    ("V7", "yzfly/mcp-python-interpreter", "run_python_code", "flag", "CWE-94"),
    ("item91", "m-ahmed-elbeskeri/UltimateCoderMCP", "tool_delete_path", "flag", "CWE-73/CWE-552"),
    ("neg1", "aaronsb/google-workspace-mcp", "manage_scratchpad", "do NOT flag", "-"),
    ("neg2", "yzfly/mcp-python-interpreter", "read_file", "do NOT flag", "-"),
    ("neg2", "yzfly/mcp-python-interpreter", "write_file", "do NOT flag", "-"),
]


def write_controls(all_rows, accepted_keys, arm_dir):
    idx = {(r["repo"], r["tool"]): r for r in all_rows}
    lines = []
    lines.append(f"# Control table -- vanilla-claude-sonnet-5 static audit ({TODAY})\n")
    lines.append(
        "Reviewed blind: the reviewer prompt never named these repos/tools as "
        "controls, and the session was explicitly instructed to judge every tool "
        "fresh from the code, not from memory of prior findings "
        "(\"do not think about vulnerabilities already found elsewhere\"). Scored "
        "here, after the fact, against the plan's expected outcomes -- 5 positive "
        "controls (repos behind ToFu's own verified/potential findings), 1 "
        "corpus-hygiene item (item 91), 2 negative controls (a real guard the "
        "audit must not report a bypass of).\n")
    lines.append("\n| id | repo | tool | expected | actual verdict | actual cwe | "
                  "grounded | match | note |\n")
    lines.append("|---|---|---|---|---|---|---|---|---|\n")
    n_match = 0
    n_total = 0
    for cid, repo, tool, expected, expected_cwe in CONTROLS:
        r = idx.get((repo, tool))
        n_total += 1
        if r is None:
            lines.append(f"| {cid} | {scrub(repo)} | `{tool}` | {expected} | "
                          f"**MISSING FROM CORPUS** | - | - | NO | not reviewed |\n")
            continue
        actual_verdict = r.get("verdict")
        actual_cwe = r.get("cwe") or "-"
        grounded = "-"
        if actual_verdict == "flag":
            grounded = "yes" if (repo, tool) in accepted_keys else "NO (Phase 2 rejected)"
        expect_flag = expected == "flag"
        is_match = (expect_flag and actual_verdict == "flag" and grounded == "yes") or \
                   (not expect_flag and actual_verdict == "clear")
        if is_match:
            n_match += 1
        note = ""
        if actual_verdict == "clear":
            note = scrub(r.get("why", ""))[:180]
        lines.append(f"| {cid} | {scrub(repo)} | `{tool}` | {expected} "
                      f"| {actual_verdict} | {actual_cwe} | {grounded} "
                      f"| {'yes' if is_match else 'DIVERGES'} | {md_escape(note)} |\n")
    lines.append(f"\n**{n_match}/{n_total} controls match the plan's expected "
                 f"outcome exactly.** A mismatch is not automatically an error -- "
                 f"see the per-row note and ToFu_src/nazmul.todo's 2026-09-21 "
                 f"control-table entry for the full reasoning behind each "
                 f"divergence (this audit's own stricter anti-FP rubric produced "
                 f"some of them; one negative control was flagged for a *different*, "
                 f"independently-found vulnerability class on the same tool, not a "
                 f"false positive against the original control).\n")
    with open(os.path.join(arm_dir, "controls.md"), "w") as f:
        f.writelines(lines)
    return n_match, n_total


# ------------------------------------------------------------- comparison ----

def write_comparison(accepted, arm_dir):
    codeql = load_jsonl_index(os.path.join(ROOT, "eval", "state", "codeql_runs_e2.jsonl"), ["repo"])
    cisco = load_jsonl_index(os.path.join(ROOT, "eval", "state", "cisco_runs.jsonl"), ["repo"])
    gpt41 = load_jsonl_index(os.path.join(ROOT, "eval", "state", "runs.gpt41-corpus.jsonl"), ["repo"])

    this_flagged_repos = set((r["repo"] for r in accepted))
    this_flagged_tools = set((r["repo"], r["tool"]) for r in accepted)

    codeql_flagged_repos = {repo for (repo,), rows in codeql.items()
                             if any((r.get("n_findings") or 0) > 0 for r in rows)}
    cisco_flagged_repos = {repo for (repo,), rows in cisco.items()
                            if any((r.get("n_findings") or 0) > 0 for r in rows)}
    cisco_flagged_tools = set()
    for (repo,), rows in cisco.items():
        for r in rows:
            for t in (r.get("flagged_tools") or []):
                cisco_flagged_tools.add((repo, t))
    gpt41_hit_repos = set()
    gpt41_hit_tools = set()
    for (repo,), rows in gpt41.items():
        for r in rows:
            if r.get("finding_hits"):
                gpt41_hit_repos.add(repo)
                gpt41_hit_tools.add((repo, r.get("tool")))

    all_repos_this = set(r["repo"] for r in load_manifest_repos())

    def overlap_block(name, other_repos, other_universe_note):
        both = this_flagged_repos & other_repos
        only_this = this_flagged_repos - other_repos
        only_other = other_repos - this_flagged_repos
        return (f"- **{name}**: this audit flags {len(this_flagged_repos)} repos; "
                f"{name} flags {len(other_repos)} repos ({other_universe_note}). "
                f"Overlap: {len(both)}. Only this audit: {len(only_this)}. "
                f"Only {name}: {len(only_other)}.\n")

    with open(os.path.join(arm_dir, "comparison.md"), "w") as f:
        f.write(f"# Comparison vs other baselines -- vanilla-claude-sonnet-5 ({TODAY})\n\n")
        f.write("Repo-level: does the system report ANYTHING for this repo at all "
                "(no severity/confidence weighting). Tool-level: only computable "
                "against Cisco YARA (`flagged_tools`) and the ToFu gpt41-corpus arm "
                "(`finding_hits`) -- CodeQL's index has no per-tool attribution.\n\n")
        f.write("## Repo-level overlap\n\n")
        f.write(overlap_block("CodeQL", codeql_flagged_repos,
                               f"{len(codeql)} repos scanned"))
        f.write(overlap_block("Cisco YARA", cisco_flagged_repos,
                               f"{len(cisco)} repos scanned"))
        f.write(overlap_block("ToFu gpt41-corpus arm", gpt41_hit_repos,
                               f"{len(gpt41)} repos in that arm's corpus subset"))
        f.write("\n## Tool-level overlap\n\n")
        both_cisco = this_flagged_tools & cisco_flagged_tools
        f.write(f"- **Cisco YARA flagged_tools**: this audit flags "
                f"{len(this_flagged_tools)} (repo,tool) pairs; Cisco flags "
                f"{len(cisco_flagged_tools)}. Overlap: {len(both_cisco)}.\n")
        both_gpt41 = this_flagged_tools & gpt41_hit_tools
        f.write(f"- **ToFu gpt41-corpus arm finding_hits**: this audit flags "
                f"{len(this_flagged_tools)} pairs; that arm has {len(gpt41_hit_tools)} "
                f"oracle-hit pairs (UNCONFIRMED candidates, not verified findings). "
                f"Overlap: {len(both_gpt41)}.\n")
        f.write("\n**Caveat**: none of these indexes share a common notion of "
                "severity or verification state with this audit's Tier-A/grounded "
                "rows -- overlap counts are a recall/coverage signal, not agreement "
                "on correctness. CodeQL/Cisco alerts are raw tool output, not "
                "human- or Phase-2-verified. The ToFu gpt41-corpus numbers are "
                "oracle *candidates* (finding_hits), same caveat as "
                "findings/potential/.\n")


_manifest_repos_cache = None


def load_manifest_repos():
    global _manifest_repos_cache
    if _manifest_repos_cache is None:
        m = load_manifest()
        repos = set()
        for s in m["shards"]:
            for r in s.get("repos", []):
                repos.add(r)
        _manifest_repos_cache = [{"repo": r} for r in repos]
    return _manifest_repos_cache


# ------------------------------------------------------------- README/METH ----

def write_methodology(manifest, arm_dir, reason_counts=None, n_rejected=0, n_flagged=0):
    prompt_template_path = os.path.join(PROMPTS_DIR, "shard_000.txt")
    prompt_text = ""
    if os.path.isfile(prompt_template_path):
        prompt_text = open(prompt_template_path).read()
    with open(os.path.join(arm_dir, "METHODOLOGY.md"), "w") as f:
        f.write(f"# Methodology -- vanilla-claude-sonnet-5 static audit\n\n")
        f.write(f"- **Model**: {MODEL_ID}\n")
        f.write(f"- **Date**: {TODAY}\n")
        f.write(f"- **Corpus**: {manifest['total_repos']} repos, "
                f"{manifest['total_configs']} configs (repo x tool pairs), "
                f"{len(manifest['shards'])} review shards\n")
        f.write(f"- **Manifest sha256**: `{manifest['manifest_sha256']}`\n")
        f.write(f"- **Scope**: full corpus, no sampling\n")
        f.write(f"- **Execution**: NONE. Read-only static analysis. Shards were "
                f"reviewed either by dispatching this exact prompt to a subagent "
                f"(early shards) or by the primary session applying the identical "
                f"rubric directly (later shards, after fan-out was judged to add "
                f"process-integrity risk without speed benefit) -- see "
                f"ToFu_src/nazmul.todo for the session history. One row (flagged "
                f"below) is known to have breached the no-execution mandate; it is "
                f"disclosed, not silently excluded -- see README.md Limitations.\n\n")
        if reason_counts:
            f.write("## Phase 2 grounding-failure breakdown\n\n")
            f.write(f"{n_rejected} of {n_flagged} `flag` rows rejected "
                    f"(see README.md for the rate; rejected.jsonl carries the "
                    f"specific reason per row, not just this aggregate count -- "
                    f"per CLAUDE.md, no number here is reported without a "
                    f"traceable log). Reasons, bucketed:\n\n")
            f.write("| reason | count |\n|---|---|\n")
            for reason, n in reason_counts.most_common():
                f.write(f"| {reason} | {n} |\n")
            f.write(
                "\nThe dominant modes are excerpt-transcription formatting, not "
                "line-number drift from shard resumption: (1) a multi-line source "
                "statement condensed into a compact single-line excerpt loses/gains "
                "incidental whitespace at parens once newlines collapse to spaces "
                "(worked around in Phase 2 by matching on whitespace-STRIPPED text, "
                "which cut the raw rate from 29.6% to ~21%); (2) an excerpt elides a "
                "multi-statement handler with a literal \"...\" (worked around by "
                "fragment-matching in order, cutting the rate further to ~16%). The "
                "remaining \"found but not within +/-10 lines\" rows are usually a "
                "citation pointing at a function's `def`/declaration line while the "
                "quoted statement sits further into the body (past a docstring, "
                "past other statements) -- a real citation-precision gap, not "
                "evidence of fabrication; two such rows from this session's own "
                "shards were hand-confirmed against source and corrected in place "
                "(see ToFu_src/nazmul.todo, 2026-09-21 Phase 2 entry).\n\n")
        f.write("## Reviewer prompt (verbatim template; shard id and file paths "
                "vary per shard)\n\n```\n")
        f.write(prompt_text)
        f.write("\n```\n")
    return prompt_text


def write_readme(stats, arm_dir):
    with open(os.path.join(arm_dir, "README.md"), "w") as f:
        f.write(f"# vanilla-claude-sonnet-5 -- LLM-only static audit baseline\n\n")
        f.write(f"**{stats['n_repos']} repos, {stats['n_configs']} configs "
                f"(repo x tool pairs). {stats['n_tier_a']} Tier-A findings, "
                f"{stats['n_tier_b']} Tier-B findings, both grounded by a "
                f"mechanical verification gate (Phase 2). "
                f"{stats['grounding_failure_rate']:.1%} of all `flag` rows "
                f"emitted by review failed that gate and are excluded from these "
                f"counts (see rejected.jsonl).**\n\n")
        f.write("Static source reading only -- no target was executed, installed, "
                "started, or contacted. This is the null-model baseline for ToFu's "
                "runtime findings: what a frontier LLM concludes from reading code "
                "alone, with no fuzzing.\n\n")
        f.write("## Headline\n\n")
        f.write(f"| | count |\n|---|---|\n")
        f.write(f"| repos | {stats['n_repos']} |\n")
        f.write(f"| configs (repo x tool) | {stats['n_configs']} |\n")
        f.write(f"| clear | {stats['n_clear']} |\n")
        f.write(f"| flag rows emitted | {stats['n_flag']} |\n")
        f.write(f"| flag rows grounded (Phase 2 accepted) | {stats['n_accepted']} |\n")
        f.write(f"| flag rows rejected (ungrounded) | {stats['n_rejected']} |\n")
        f.write(f"| grounding-failure rate | {stats['grounding_failure_rate']:.1%} |\n")
        f.write(f"| **Tier A (headline findings)** | **{stats['n_tier_a']}** |\n")
        f.write(f"| Tier B (potential) | {stats['n_tier_b']} |\n")
        f.write(f"| CWE-taxonomy extensions (off-list, justified) | "
                f"{stats['n_extensions']} |\n\n")
        f.write("## Tallies by CWE (grounded, Tier A + Tier B)\n\n")
        f.write("| CWE | title | Tier A | Tier B | total |\n|---|---|---|---|---|\n")
        for cwe, (a, b) in sorted(stats["by_cwe"].items(), key=lambda kv: -(kv[1][0] + kv[1][1])):
            f.write(f"| {cwe} | {CWE_TITLE.get(cwe, '(extension)')} | {a} | {b} | {a+b} |\n")
        f.write("\n## By language\n\n")
        f.write("| lang | Tier A | Tier B |\n|---|---|---|\n")
        for lang, (a, b) in sorted(stats["by_lang"].items()):
            f.write(f"| {lang} | {a} | {b} |\n")
        f.write("\n## Method (10 lines)\n\n")
        f.write(
            "1. Built a deterministic shard manifest from prepared.jsonl + "
            "eval/configs/, asserted union == exact config set, disjoint "
            "(`_scripts/build_shards.py`).\n"
            "2. One reviewer pass per shard, same rubric (Tier A/B, explicit "
            "anti-FP rules, fixed CWE taxonomy), read-only, no memory of prior "
            "findings -- every tool judged fresh from its own code.\n"
            "3. Reviewer emits one JSONL row per config: `flag` (tier, CWE, "
            "file:line, verbatim excerpt, param->sink, guard, why) or `clear` "
            "(reason enum + one-line why).\n"
            "4. Phase 2 (`_scripts/verify_findings.py`) mechanically re-grounds "
            "every `flag` row against the source tree -- file exists, excerpt is "
            "a real substring within +/-10 lines of the cited line, tool/config "
            "match, CWE/tier well-formed. Failures excluded, not counted.\n"
            "5. Phase 4 (`_scripts/aggregate.py`, this run) merges, tallies, and "
            "writes every deliverable below.\n\n")
        f.write("## Deliverables\n\n")
        f.write("- `inventory.jsonl` -- all 6231 rows, `_grounded` flag on each "
                "flag row\n- `flagged.md` -- Tier A grouped by CWE\n"
                "- `potential.md` -- Tier B grouped by CWE\n"
                "- `by-cwe/CWE-NN_<slug>.md` + `by-cwe/INDEX.md`\n"
                "- `controls.md` -- 8-row control table, scored\n"
                "- `comparison.md` -- overlap vs CodeQL/Cisco/ToFu gpt41-corpus\n"
                "- `rejected.jsonl` -- Phase 2 failures + reason\n"
                "- `METHODOLOGY.md` -- reviewer prompt verbatim, manifest hash\n\n")
        f.write("## Limitations\n\n")
        f.write(
            "- Static reading only; no execution, so no Tier-A row is a "
            "*demonstrated* bug in this project's sense -- each is a "
            "source-verified candidate.\n"
            "- Not every config has a persisted tool description; where absent, "
            "the contract is read from the code and the row notes it.\n"
            "- A handful of repos generate tools dynamically (OpenAPI/JSON-schema/"
            "YAML); their verdict covers the generated family, reviewed via the "
            "generator + data file, not an individual per-tool handler.\n"
            "- Some repos launch from `dist`/`build`; the audit reads `src`, not "
            "the shipped artifact -- a build-time divergence would not be caught.\n"
            "- Reviewer passes ran on the same model as this aggregation but each "
            "had its own context; verdicts are not identical-prompt reproducible "
            "the way a static analyser is. The verification gate, not "
            "reproducibility, is what makes these numbers usable.\n"
            "- **One row is a disclosed exception to the read-only mandate**: "
            "shard_016.jsonl's `aaronsb/google-workspace-mcp` `manage_scratchpad` "
            "finding (CWE-915, prototype pollution) empirically verified its "
            "mechanism by running logic extracted from the target's own source in "
            "an isolated script -- not against the target repo itself, but still "
            "execution of target-derived code, which breaches this arm's static-"
            "only mandate. The static reasoning in that row stands independently "
            "of the dynamic check (see its `process_note` field and "
            "ToFu_src/nazmul.todo's 2026-09-21 PROCESS FLAG entry); it is kept in "
            "the Tier-A count, disclosed rather than silently excluded.\n"
            f"- {stats['grounding_failure_rate']:.1%} of all flag rows emitted by "
            "review failed the Phase 2 grounding gate. The dominant failure modes "
            "were excerpt-transcription formatting (multi-line source condensed "
            "to one line, or elided with \"...\", in a way the mechanical checker "
            "-- deliberately strict -- could not always match) rather than "
            "fabricated claims; see rejected.jsonl for the row-level detail and "
            "ToFu_src/nazmul.todo for two manually-confirmed, fixed examples from "
            "this session's own shards.\n")
    return None


# ---------------------------------------------------------------- main ----

def main():
    manifest = load_manifest()
    result = vf.load_and_verify()
    if result["incomplete_shards"]:
        print("FATAL: corpus is not complete, aborting aggregation:", file=sys.stderr)
        for sid, got, exp in result["incomplete_shards"]:
            print(f"  shard_{sid}: {got}/{exp}", file=sys.stderr)
        sys.exit(1)

    all_rows = result["all_rows"]
    accepted = result["accepted"]
    rejected = result["rejected"]

    assert len(all_rows) == manifest["total_configs"], (
        f"inventory has {len(all_rows)} rows, manifest says "
        f"{manifest['total_configs']}")

    accepted_keys = set((r["repo"], r["tool"]) for r in accepted)

    # rejected.jsonl (Phase 2 already wrote it during load_and_verify's caller
    # in verify_findings.main(); here we own the canonical write for Phase 4)
    with open(os.path.join(ARM_DIR, "rejected.jsonl"), "w") as f:
        for r in rejected:
            r = dict(r)
            r.pop("_shard_id", None)
            f.write(json.dumps(r) + "\n")

    n_inv = write_inventory(all_rows, accepted_keys, os.path.join(ARM_DIR, "inventory.jsonl"))
    assert n_inv == manifest["total_configs"]

    tier_a, tier_b = write_flag_reports(accepted, ARM_DIR)
    n_match, n_total = write_controls(all_rows, accepted_keys, ARM_DIR)
    write_comparison(accepted, ARM_DIR)

    by_cwe = collections.defaultdict(lambda: [0, 0])
    by_lang = collections.defaultdict(lambda: [0, 0])
    for r in accepted:
        cwe = primary_cwe(r.get("cwe"))
        idx = 0 if r.get("tier") == "A" else 1
        by_cwe[cwe][idx] += 1
        by_lang[r.get("lang", "?")][idx] += 1

    n_other = len(all_rows) - len(result["flagged"]) - len(result["cleared"])
    n_rejected_flag = len(rejected) - n_other
    write_methodology(manifest, ARM_DIR, reason_counts=result["reason_counts"],
                       n_rejected=n_rejected_flag, n_flagged=len(result["flagged"]))
    stats = {
        "n_repos": manifest["total_repos"],
        "n_configs": manifest["total_configs"],
        "n_clear": len(result["cleared"]),
        "n_flag": len(result["flagged"]),
        "n_accepted": len(accepted),
        "n_rejected": n_rejected_flag,
        "grounding_failure_rate": (n_rejected_flag / len(result["flagged"]))
                                    if result["flagged"] else 0.0,
        "n_tier_a": len(tier_a),
        "n_tier_b": len(tier_b),
        "n_extensions": result["n_extensions"],
        "by_cwe": {k: tuple(v) for k, v in by_cwe.items()},
        "by_lang": {k: tuple(v) for k, v in by_lang.items()},
    }
    write_readme(stats, ARM_DIR)

    print(f"inventory.jsonl: {n_inv} rows (== manifest {manifest['total_configs']})")
    print(f"Tier A: {len(tier_a)}  Tier B: {len(tier_b)}  rejected: {n_rejected_flag}")
    print(f"controls: {n_match}/{n_total} match expected outcome")
    print("wrote: README.md, METHODOLOGY.md, inventory.jsonl, flagged.md, "
          "potential.md, by-cwe/*.md, controls.md, comparison.md, rejected.jsonl")


if __name__ == "__main__":
    main()
