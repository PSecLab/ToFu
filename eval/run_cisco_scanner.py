#!/usr/bin/env python3
"""
BASELINE: Cisco AI Defense MCP Scanner over ToFu's own target set.

Why this script exists
----------------------
Table 2 claims Cisco MCP Scanner is catalog-bounded where ToFu is
semantics-derived. That claim is only worth printing if both tools were
pointed at the *same* servers, with the same commits, from the same
prepared launch commands. So this reads `eval/state/prepared.jsonl` --
the exact records `prepare_targets.py` wrote for the ToFu campaign --
and scans those servers over stdio. No separate target list, no
re-cloning, no drift.

RESUMABLE, like run_eval.py. Every finished repo is appended to
`eval/state/cisco_runs.jsonl`; re-running skips what is already there.
Ctrl-C loses only the in-flight scan.

What is NOT comparable, and must not be written as if it were
--------------------------------------------------------------
The two tools answer different questions and their counts do not
subtract from one another:

  * Cisco MCP Scanner inspects tool *metadata* -- names, descriptions,
    schemas -- with YARA rules, an LLM reviewer, and (with a cloud
    subscription) Cisco's threat-intelligence API. It never invokes a
    tool. A "finding" is a suspicious description.
  * ToFu invokes the tool with generated arguments and checks whether
    the implementation upheld a property derived from that tool's own
    contract. A "finding" is an executed violation.

A tool with a clean description and a broken implementation is invisible
to the first and visible to the second; a tool carrying an injection
payload in its description is the reverse. Report the overlap and the
disjoint sets, not a single leaderboard number.

The `api` analyzer is OFF by default because it ships user tool
descriptions to Cisco's hosted endpoint and needs a paid key. Enabling
it changes what the baseline is; `--with-api` does so explicitly and the
choice is recorded in every run record so the paper can state it.

Usage
-----
    python3 eval/run_cisco_scanner.py --setup          # build its venv, once
    python3 eval/run_cisco_scanner.py --preflight      # check config only
    python3 eval/run_cisco_scanner.py --limit 2        # smoke test
    python3 eval/run_cisco_scanner.py                  # full baseline
    python3 eval/run_cisco_scanner.py --summary        # ToFu vs Cisco table

Environment (defaults match the local Ollama the ToFu campaign uses):
    CISCO_LLM_MODEL      default ollama_chat/llama3.1:8b   (a LiteLLM id)
    CISCO_LLM_BASE_URL   default http://localhost:11434
    MCP_SCANNER_API_KEY  only read when --with-api is passed
"""

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from threading import Lock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCANNER = os.path.join(ROOT, "Benchmarks", "Cisco-MCP-Scanner")
VENV = os.path.join(SCANNER, ".venv")
VBIN = os.path.join(VENV, "bin")
CLI = os.path.join(VBIN, "mcp-scanner")
# Pin the scanner to the build that produced the 2026-09-11 baseline. HEAD
# regressed: newer commits throw `UnboundLocalError: os` whenever a target fails
# to start, so a fresh clone errors every run. Override with CISCO_SCANNER_COMMIT.
CISCO_SCANNER_COMMIT = os.environ.get("CISCO_SCANNER_COMMIT", "16e684d8bd8f")  # v4.8.4

STATE = os.path.join(ROOT, "eval", "state")
PREPARED = os.path.join(STATE, "prepared.jsonl")
# CISCO_TAG=<name> isolates a campaign: own index (eval/state/cisco_runs.<tag>.jsonl) and raw
# outputs (eval/cisco_runs/<tag>/), so a new campaign never overwrites an earlier one's evidence.
TAG = os.environ.get("CISCO_TAG", "").strip()
RUNS = os.path.join(STATE, f"cisco_runs.{TAG}.jsonl" if TAG else "cisco_runs.jsonl")
# ToFu index to compare against. Default to the gpt-4.1 arm (runs.gpt41-full)
# when present so the LLM is held fixed against Cisco+gpt-4.1; override with
# TOFU_RUNS_INDEX. The bare runs.jsonl (old default arm) is the last resort.
TOFU_RUNS = os.environ.get("TOFU_RUNS_INDEX") or (
    os.path.join(STATE, "runs.gpt41-full.jsonl")
    if os.path.exists(os.path.join(STATE, "runs.gpt41-full.jsonl"))
    else os.path.join(STATE, "runs.jsonl"))
OUT = os.path.join(ROOT, "eval", "cisco_runs", TAG) if TAG else os.path.join(ROOT, "eval", "cisco_runs")

lock = Lock()
counter = {"done": 0, "flagged": 0, "errors": 0}


def log(m):
    print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def read_jsonl(path):
    if not os.path.exists(path):
        return []
    out = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


# --------------------------------------------------------------------- setup

def setup():
    """Build the scanner its OWN venv.

    It must not share ToFu's: it pins litellm, yara-python, tree-sitter and
    a different `mcp` than ToFu does, and installing it alongside would
    quietly change the versions the ToFu campaign runs under -- i.e.
    corrupt the very results this is meant to compare against.
    """
    if not os.path.isdir(os.path.join(SCANNER, ".git")):
        sys.exit(f"scanner checkout not found at {SCANNER}\n"
                 "  git clone https://github.com/cisco-ai-defense/mcp-scanner "
                 f"{SCANNER}")
    # Pin to the known-good commit before building -- HEAD regressed (see above).
    if CISCO_SCANNER_COMMIT:
        log(f"pinning scanner to {CISCO_SCANNER_COMMIT} (known-good build)")
        subprocess.run(["git", "-C", SCANNER, "fetch", "--quiet", "--all"], check=False)
        co = subprocess.run(["git", "-C", SCANNER, "checkout", "--quiet",
                             CISCO_SCANNER_COMMIT], capture_output=True, text=True)
        if co.returncode != 0:
            sys.exit(f"could not checkout {CISCO_SCANNER_COMMIT} in {SCANNER}: "
                     f"{co.stderr.strip()[:200]}")
    # Patch a crash in the scanner itself: cli.py main() has a local `import os`
    # in the vulnerable-package branch that shadows the module-level os, so under
    # Python's function scoping EVERY os use earlier in main() -- including
    # `os.environ["MCP_SCANNER_STDIO_TIMEOUT"] = ...` on the --stdio-timeout path
    # we always take -- raises UnboundLocalError before a single target is
    # scanned (0/N every run). Removing the redundant local import fixes it; the
    # global `import os` covers that branch. Pure crash-fix, no analyzer change.
    cli = os.path.join(SCANNER, "mcpscanner", "cli.py")
    try:
        src = open(cli).read()
        patched = src.replace(
            '        elif args.cmd == "vulnerable-package":\n            import os\n',
            '        elif args.cmd == "vulnerable-package":\n')
        if patched != src:
            open(cli, "w").write(patched)
            log("patched cli.py: removed shadowing local 'import os' (UnboundLocalError)")
        else:
            log("cli.py patch: no shadowing 'import os' found (already fixed or moved)")
    except Exception as e:
        log(f"WARN: could not patch cli.py ({e})")
    log(f"building scanner venv at {VENV}")
    if shutil.which("uv"):
        cmds = [["uv", "venv", "--python", "3.11", VENV],
                ["uv", "pip", "install", "--python", os.path.join(VBIN, "python"),
                 "-e", SCANNER]]
    else:
        cmds = [[sys.executable, "-m", "venv", VENV],
                [os.path.join(VBIN, "pip"), "install", "-e", SCANNER]]
    for c in cmds:
        log("  $ " + " ".join(c))
        p = subprocess.run(c, cwd=SCANNER)
        if p.returncode != 0:
            sys.exit(f"setup failed at: {' '.join(c)}")
    log(f"OK -- {CLI}")
    ver = subprocess.run([CLI, "--help"], capture_output=True)
    log("scanner CLI responds" if ver.returncode == 0 else
        "WARNING: CLI did not respond to --help")


def scanner_version():
    """Pin the exact baseline build in every record, so the number in the
    paper can be reproduced against one commit rather than 'latest'."""
    info = {}
    try:
        info["commit"] = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=SCANNER,
            capture_output=True, text=True).stdout.strip()[:12]
    except Exception:
        pass
    try:
        with open(os.path.join(SCANNER, "pyproject.toml")) as f:
            for line in f:
                if line.startswith("version"):
                    info["version"] = line.split("=", 1)[1].strip().strip('"')
                    break
    except Exception:
        pass
    return info


def build_env(analyzers, with_api):
    env = os.environ.copy()
    env["MCP_SCANNER_LLM_MODEL"] = os.environ.get(
        "CISCO_LLM_MODEL", "ollama_chat/llama3.1:8b")
    env["MCP_SCANNER_LLM_BASE_URL"] = os.environ.get(
        "CISCO_LLM_BASE_URL", "http://localhost:11434")
    # Key resolution: an explicit MCP_SCANNER_LLM_API_KEY wins; else for a
    # non-ollama base_url (e.g. OpenAI) use OPENAI_API_KEY; else the ollama
    # placeholder. Without this the llm analyzer sends "ollama" as the bearer
    # token to OpenAI and every call 401s.
    if not env.get("MCP_SCANNER_LLM_API_KEY"):
        base_l = env["MCP_SCANNER_LLM_BASE_URL"].lower()
        if "11434" in base_l or "ollama" in base_l:
            env["MCP_SCANNER_LLM_API_KEY"] = "ollama"
        else:
            env["MCP_SCANNER_LLM_API_KEY"] = os.environ.get("OPENAI_API_KEY", "")
    env["MCP_SCANNER_LLM_TIMEOUT"] = os.environ.get("CISCO_LLM_TIMEOUT", "120")
    if not with_api:
        # Make sure a stray key in the shell cannot silently turn the cloud
        # analyzer on and change what the baseline means.
        env.pop("MCP_SCANNER_API_KEY", None)
    return env


def preflight(analyzers, with_api):
    ok = True
    if not os.path.exists(CLI):
        log(f"PREFLIGHT FAIL: {CLI} missing -- run with --setup first")
        return False
    log(f"scanner: {scanner_version()}")
    log(f"analyzers: {analyzers}")
    if "api" in analyzers:
        if not os.environ.get("MCP_SCANNER_API_KEY"):
            log("PREFLIGHT FAIL: 'api' analyzer needs MCP_SCANNER_API_KEY "
                "(a paid Cisco AI Defense key)")
            ok = False
        else:
            log("NOTE: the api analyzer uploads tool descriptions to Cisco's "
                "hosted endpoint. Record this in the paper's setup.")
    else:
        log("NOTE: 'api' analyzer DISABLED (needs a Cisco AI Defense "
            "subscription). State this as a limitation -- the baseline is "
            "the open-source analyzers only.")
    if "llm" in analyzers:
        env = build_env(analyzers, with_api)
        base = env["MCP_SCANNER_LLM_BASE_URL"]
        model = env["MCP_SCANNER_LLM_MODEL"]
        log(f"llm analyzer -> {model} @ {base}")
        base_l = base.lower()
        if "11434" in base_l or "ollama" in base_l:
            # local Ollama: verify the model is actually pulled
            try:
                import urllib.request
                with urllib.request.urlopen(base.rstrip("/") + "/api/tags",
                                            timeout=10) as r:
                    tags = json.loads(r.read().decode())
                names = [m.get("name", "") for m in tags.get("models", [])]
                want = model.split("/", 1)[-1]
                if want in names:
                    log(f"  OK -- '{want}' is pulled locally")
                else:
                    log(f"  PREFLIGHT FAIL: '{want}' not in local Ollama. Have: {names}")
                    ok = False
            except Exception as e:
                log(f"  PREFLIGHT FAIL: cannot reach Ollama at {base} ({e})")
                ok = False
        else:
            # hosted provider (e.g. OpenAI): just require a key is present
            if env.get("MCP_SCANNER_LLM_API_KEY"):
                log(f"  OK -- hosted provider, key present (len={len(env['MCP_SCANNER_LLM_API_KEY'])})")
            else:
                log("  PREFLIGHT FAIL: no LLM API key (set OPENAI_API_KEY or MCP_SCANNER_LLM_API_KEY)")
                ok = False
    targets = read_jsonl(PREPARED)
    ready = [t for t in targets if t.get("status") == "ready"]
    log(f"targets: {len(ready)} ready servers "
        f"({sum(t.get('n_tools_probed', 0) for t in ready)} tools) from {PREPARED}")
    if not ready:
        log("PREFLIGHT FAIL: no prepared targets -- run eval/prepare_targets.py")
        ok = False
    return ok


# ----------------------------------------------------------------- one server

def count_findings(results):
    """Tolerant reduction of the scanner's per-tool JSON.

    Shape is a list of ToolScanResult: {tool_name, status, findings:
    {<analyzer>: ...}, is_safe}. Written defensively so a schema change
    downgrades the summary rather than losing the scan -- the raw JSON is
    always kept on disk regardless of what this makes of it.
    """
    per_tool, n_flagged, by_analyzer, by_sev = {}, 0, {}, {}
    if isinstance(results, dict):
        results = (results.get("scan_results") or results.get("raw_results")
                   or results.get("results") or [])
    if not isinstance(results, list):
        return {}, 0, {}, {}
    for r in results:
        if not isinstance(r, dict):
            continue
        name = r.get("tool_name", "?")
        safe = r.get("is_safe")
        findings = r.get("findings") or {}
        n = 0
        if isinstance(findings, dict):
            for analyzer, val in findings.items():
                c = 0
                if isinstance(val, list):
                    c = len(val)
                elif isinstance(val, dict):
                    # total_findings is authoritative when present: a SAFE tool
                    # reports total_findings=0 with a populated result dict, so
                    # the old `or (1 if val else 0)` fallback counted EVERY safe
                    # tool as one finding (excel-reader: 0 real -> 14 phantom).
                    if "total_findings" in val:
                        c = int(val.get("total_findings") or 0)
                    else:
                        sev0 = str(val.get("severity", "")).upper()
                        c = 1 if (val and sev0 not in ("", "SAFE", "NONE")) else 0
                    sev = val.get("severity")
                    if sev and c:
                        by_sev[sev] = by_sev.get(sev, 0) + c
                n += c
                if c:
                    by_analyzer[analyzer] = by_analyzer.get(analyzer, 0) + c
        elif isinstance(findings, list):
            n = len(findings)
        per_tool[name] = n
        if n or safe is False:
            n_flagged += 1
    return per_tool, n_flagged, by_analyzer, by_sev


def one(target, analyzers, with_api, timeout, source_scan):
    repo = target["repo"]
    slug = repo.replace("/", "__")
    outfile = os.path.join(OUT, slug + ".json")
    errfile = os.path.join(OUT, slug + ".stderr.log")
    logfile = os.path.join(OUT, slug + ".log")
    t0 = time.time()
    rec = {"repo": repo, "set": target.get("set"), "lang": target.get("lang"),
           "commit": target.get("commit"), "started": time.time(),
           "analyzers": analyzers, "api_analyzer": bool(with_api),
           "llm_model": os.environ.get("CISCO_LLM_MODEL") if ("llm" in analyzers or "behavioral" in analyzers) else None,
           "scanner": scanner_version(),
           "n_tools_expected": target.get("n_tools_probed")}
    try:
        # Argument ORDER matters: --analyzers/--format/--output/--source-path
        # and --stdio-timeout live on the top-level parser, so they must
        # precede the `stdio` subcommand; only --stdio-* and --stderr-file
        # belong to the subparser. The README's own example is
        #   mcp-scanner --stdio-timeout 180 stdio --stdio-command uvx ...
        # Getting this backwards makes argparse reject the whole call.
        cmd = [CLI,
               "--analyzers", ",".join(analyzers),
               "--stdio-timeout", str(min(timeout, 300)),
               "--format", "raw",
               "--output", outfile]
        if source_scan and "behavioral" in analyzers:
            cmd += ["--source-path", target.get("cwd", ROOT)]
        cmd += ["stdio",
                "--stdio-command", target["command"],
                "--stderr-file", errfile]
        for a in target.get("args", []):
            cmd += ["--stdio-arg", a]
        rec["cmd"] = " ".join(cmd)
        p = subprocess.run(cmd, cwd=target.get("cwd", ROOT),
                           env=build_env(analyzers, with_api),
                           capture_output=True, timeout=timeout)
        out = (p.stdout.decode(errors="ignore") + "\n"
               + p.stderr.decode(errors="ignore"))
        with open(logfile, "w") as f:
            f.write(out)
        rec["returncode"] = p.returncode
        rec["log"] = os.path.relpath(logfile, ROOT)
        # The scanner honours --output only for some formats; with --format raw
        # it prints the JSON report to STDOUT. Prefer the --output file, else
        # parse stdout (which we already captured). Both are the same schema.
        results = None
        if os.path.exists(outfile):
            with open(outfile) as f:
                results = json.load(f)
        else:
            stdout_txt = p.stdout.decode(errors="ignore").strip()
            if stdout_txt.startswith("{"):
                try:
                    results = json.loads(stdout_txt)
                    with open(outfile, "w") as f:
                        f.write(stdout_txt)   # persist for later inspection
                except json.JSONDecodeError:
                    results = None
        if results is not None:
            per_tool, flagged, by_analyzer, by_sev = count_findings(results)
            rec.update(raw=os.path.relpath(outfile, ROOT),
                       n_tools_scanned=len(per_tool),
                       n_tools_flagged=flagged,
                       n_findings=sum(per_tool.values()),
                       findings_by_analyzer=by_analyzer,
                       findings_by_severity=by_sev,
                       flagged_tools=sorted(t for t, n in per_tool.items() if n),
                       ok=p.returncode == 0)
        else:
            tail = [l for l in out.splitlines() if l.strip()][-1:] or ["no output"]
            rec.update(ok=False, error=tail[-1][:200])
        rec["seconds"] = round(time.time() - t0, 1)
        with lock:
            counter["done"] += 1
            if not rec.get("ok"):
                counter["errors"] += 1
            elif rec.get("n_tools_flagged"):
                counter["flagged"] += 1
    except subprocess.TimeoutExpired:
        rec.update(ok=False, error=f"timeout after {timeout}s",
                   seconds=round(time.time() - t0, 1))
        with lock:
            counter["done"] += 1
            counter["errors"] += 1
    except Exception as e:
        rec.update(ok=False, error=f"{type(e).__name__}: {e}"[:200],
                   seconds=round(time.time() - t0, 1))
        with lock:
            counter["done"] += 1
            counter["errors"] += 1
    with lock:
        with open(RUNS, "a") as f:
            f.write(json.dumps(rec) + "\n")
    return rec


# ------------------------------------------------------------------- summary

def summarize():
    cisco = read_jsonl(RUNS)
    tofu = read_jsonl(TOFU_RUNS)
    if not cisco:
        log(f"no cisco runs yet ({RUNS})")
        return
    ok = [r for r in cisco if r.get("ok")]
    print()
    print("=" * 72)
    print("Cisco AI Defense MCP Scanner -- baseline over ToFu's target set")
    print("=" * 72)
    v = ok[0].get("scanner", {}) if ok else {}
    print(f"  scanner           : v{v.get('version','?')} @ {v.get('commit','?')}")
    print(f"  analyzers         : {ok[0].get('analyzers') if ok else '?'}"
          f"   (cloud api analyzer: "
          f"{'ON' if ok and ok[0].get('api_analyzer') else 'OFF'})")
    print(f"  servers scanned   : {len(ok)} ok / {len(cisco)} attempted")
    print(f"  tools scanned     : {sum(r.get('n_tools_scanned',0) for r in ok)}")
    print(f"  tools flagged     : {sum(r.get('n_tools_flagged',0) for r in ok)}")
    print(f"  findings (total)  : {sum(r.get('n_findings',0) for r in ok)}")
    agg = {}
    for r in ok:
        for a, n in (r.get("findings_by_analyzer") or {}).items():
            agg[a] = agg.get(a, 0) + n
    if agg:
        print(f"  by analyzer       : "
              + ", ".join(f"{a}={n}" for a, n in sorted(agg.items())))
    print(f"  median wall-clock : "
          f"{sorted(r.get('seconds',0) for r in ok)[len(ok)//2] if ok else 0}s/server")

    if tofu:
        tok = [r for r in tofu if r.get("ok")]
        print()
        print("  ToFu on the same targets")
        print(f"    tool-runs        : {len(tok)} ok / {len(tofu)} attempted")
        print(f"    runs with hits   : {sum(1 for r in tok if r.get('finding_hits'))}")
        sel = sum(1 for r in tofu if r.get("llm_selection") == "ok")
        print(f"    LLM selection ok : {sel}/{len(tofu)} runs")
        if sel == 0 and tofu:
            print("    !! LLM selection never succeeded -- those runs are the "
                  "deterministic fallback, not ToFu. Do not compare them.")
        c_repos = {r["repo"] for r in ok if r.get("n_tools_flagged")}
        t_repos = {r.get("repo") for r in tok if r.get("finding_hits")}
        print()
        print("  Repos flagged by ...")
        print(f"    Cisco only : {sorted(c_repos - t_repos)}")
        print(f"    ToFu only  : {sorted(t_repos - c_repos)}")
        print(f"    both       : {sorted(c_repos & t_repos)}")
    print()
    print("  The two columns are NOT a leaderboard: Cisco reads tool metadata")
    print("  and never invokes a tool; ToFu executes tools and checks derived")
    print("  properties. Report the disjoint sets, not a difference.")
    print("=" * 72)


# ---------------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--setup", action="store_true", help="build the scanner venv and exit")
    ap.add_argument("--preflight", action="store_true", help="check config and exit")
    ap.add_argument("--summary", action="store_true", help="print the comparison and exit")
    ap.add_argument("--analyzers", default="yara,llm",
                    help="comma list of: yara, llm, behavioral, api (default: %(default)s)")
    ap.add_argument("--with-api", action="store_true",
                    help="enable Cisco's hosted api analyzer (needs a paid key; "
                         "uploads tool descriptions)")
    ap.add_argument("--behavioral", action="store_true",
                    help="also pass --source-path so the behavioral analyzer "
                         "can read the cloned source")
    ap.add_argument("--timeout", type=int, default=900, help="per-server seconds")
    ap.add_argument("--workers", type=int, default=2)
    ap.add_argument("--limit", type=int, default=0, help="scan at most N servers")
    ap.add_argument("--set", dest="only_set", default=None, help="restrict to set A or B")
    ap.add_argument("--repos-file", default=None,
                    help="exact repo names, one per line ('#' lines ignored); RESUMABLE: repos "
                         "with an ok row in the index are skipped")
    ap.add_argument("--exact", action="store_true", help="--only-repo entries are exact repo names")
    ap.add_argument("--no-summary", action="store_true", help="skip the ToFu-vs-Cisco summary at the end")
    ap.add_argument("--only-repo", default=None,
                    help="comma-separated substrings; scan ONLY servers whose repo matches "
                         "one. Bypasses the done-set so you can re-scan named repos (e.g. to "
                         "add the llm analyzer to repos already YARA-scanned).")
    a = ap.parse_args()

    if a.setup:
        return setup()
    if a.summary:
        return summarize()

    analyzers = [x.strip() for x in a.analyzers.split(",") if x.strip()]
    if a.with_api and "api" not in analyzers:
        analyzers.append("api")
    if a.behavioral and "behavioral" not in analyzers:
        analyzers.append("behavioral")

    for d in (STATE, OUT):
        os.makedirs(d, exist_ok=True)

    if not preflight(analyzers, a.with_api):
        sys.exit(1)
    if a.preflight:
        return

    done = {r["repo"] for r in read_jsonl(RUNS) if r.get("ok")}
    ready = [t for t in read_jsonl(PREPARED) if t.get("status") == "ready"]
    ready = list({t["repo"]: t for t in ready}.values())     # latest prepared row per repo wins
    if a.repos_file:
        want = [l.strip() for l in open(a.repos_file) if l.strip() and not l.startswith("#")]
        by = {t["repo"]: t for t in ready}
        miss = [r for r in want if r not in by]
        if miss:
            log(f"WARNING {len(miss)} listed repos not prepared here: {miss[:8]}")
        targets = [by[r] for r in want if r in by and r not in done]
        log(f"--repos-file: {len(want)} listed, {len(want) - len(targets) - len(miss)} already ok, {len(targets)} to scan")
    elif a.only_repo and a.exact:
        names = {p.strip() for p in a.only_repo.split(",") if p.strip()}
        targets = [t for t in ready if t["repo"] in names]
    elif a.only_repo:
        pats = [p.strip().lower() for p in a.only_repo.split(",") if p.strip()]
        targets = [t for t in ready if any(p in t["repo"].lower() for p in pats)]
        log(f"--only-repo {pats}: {len(targets)} servers (done-set bypassed for re-scan)")
    else:
        targets = [t for t in ready if t["repo"] not in done]
    if a.only_set:
        targets = [t for t in targets if t.get("set") == a.only_set]
    if a.limit:
        targets = targets[:a.limit]
    if not targets:
        log("nothing to do -- every prepared server is already scanned")
        return None if a.no_summary else summarize()

    log(f"scanning {len(targets)} servers, workers={a.workers}, "
        f"timeout={a.timeout}s each")
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        fn = lambda t: one(t, analyzers, a.with_api, a.timeout, a.behavioral)
        for i, r in enumerate(ex.map(fn, targets), 1):
            tag = ("FLAG" if r.get("n_tools_flagged") else
                   "ERR " if not r.get("ok") else "    ")
            log(f"{tag} [{i}/{len(targets)}] {r['repo']} {r.get('seconds')}s "
                f"tools={r.get('n_tools_scanned','-')} "
                f"flagged={r.get('n_tools_flagged','-')} "
                f"findings={r.get('n_findings','-')}"
                + (f" :: {r.get('error')}" if not r.get("ok") else ""))
    log(f"DONE {counter['done']} servers, {counter['flagged']} with flagged "
        f"tools, {counter['errors']} errors, {(time.time()-t0)/3600:.2f} h")
    log(f"  raw json -> {OUT}")
    log(f"  index    -> {RUNS}")
    if not a.no_summary:
        summarize()


if __name__ == "__main__":
    main()
