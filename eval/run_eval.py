#!/usr/bin/env python3
"""
STEP 2 of the ToFu evaluation: run the fuzzing campaign over prepared configs.

RESUMABLE. Every completed run is appended to eval/state/runs.jsonl; re-running
skips them. Ctrl-C is safe -- the in-flight run is lost, nothing else.

Each run invokes ToFu exactly as a user would:
    python -m src --config <cfg> --time <budget>
with override_rules EMPTY, so llm.select_sanitizers() actually runs.

Usage:
    export TOFU_LLM_BASE_URL=http://localhost:11434/v1
    export TOFU_LLM_MODEL=llama3.1:8b
    export OLLAMA_CLOUD_API_KEY=ollama
    python3 eval/run_eval.py --time 900 --workers 4
    python3 eval/run_eval.py --time 60 --limit 3      # smoke test first!
    python3 eval/run_eval.py --status                 # progress only
    python3 eval/run_eval.py --reparse                # rebuild the index from logs

WHY --reparse EXISTS: the per-run log is written to disk BEFORE it is parsed,
so a bug in the parser can never destroy a campaign's data again. If the
parser is fixed or extended, re-derive every record from eval/runs/*.log
instead of re-running the campaign.
"""
import argparse, importlib.util, json, os, platform, re, shutil, signal, subprocess, sys, threading, time, uuid
from concurrent.futures import ThreadPoolExecutor

ROOT  = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Loaded by path, not `import src...`: src/__init__ pulls in the fuzzer and
# atheris, which the harness interpreter need not have.
_spec = importlib.util.spec_from_file_location(
    "tofu_procreap", os.path.join(ROOT, "src", "runners", "procreap.py"))
procreap = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(procreap)
EVAL  = os.path.join(ROOT, "eval")
CFG   = os.path.join(EVAL, "configs")
STATE = os.path.join(EVAL, "state")
OUT   = os.path.join(EVAL, "runs")
RUNS  = os.path.join(STATE, "runs.jsonl")

# item 91 -- cwd ISOLATION. In-process Python targets run inside the fuzzer
# process, so their filesystem ops resolve against the fuzzer's cwd. That cwd
# used to be ROOT, so a target with a delete/write tool (e.g.
# UltimateCoderMCP::tool_delete_path, 2026-09-18) fed a traversal/`.` path
# deleted the HARNESS repo -- it wiped eval/configs, .venv and 116 tracked
# files mid-run. Each config now runs in a throwaway per-config scratch dir
# OUTSIDE the repo, so relative-path damage stays in scratch (absolute-path
# damage still needs a real sandbox -- see nazmul.todo). Kept off the repo tree
# on purpose; override with TOFU_SCRATCH_ROOT.
SCRATCH_ROOT = os.environ.get("TOFU_SCRATCH_ROOT") or os.path.join(
    os.path.expanduser("~"), ".tofu_scratch")

# ARM SCOPING. A model comparison is worthless if two arms write to one index:
# done_set() would make arm B skip every config arm A already ran, and the
# summary would average two different models together. --arm NAME (or
# TOFU_ARM) redirects the index, the per-run logs, corpora and metrics into
# arm-specific paths. Default "" keeps the existing layout byte-for-byte so
# nothing already recorded moves.
ARM = os.environ.get("TOFU_ARM", "").strip()


def _apply_arm(arm):
    global ARM, OUT, RUNS
    ARM = arm
    if not arm:
        return
    safe = "".join(c if (c.isalnum() or c in "-_.") else "_" for c in arm)
    OUT = os.path.join(EVAL, "runs", safe)
    RUNS = os.path.join(STATE, f"runs.{safe}.jsonl")
    os.makedirs(OUT, exist_ok=True)


_apply_arm(ARM)

lock = threading.Lock()
counter = {"done": 0, "findings": 0, "errors": 0, "harness_errors": 0}

# In-flight fuzzer subprocesses -> their reap tag. They run in their own
# sessions (start_new_session=True), so a terminal Ctrl-C never reaches them;
# without this registry an interrupted campaign leaves them fuzzing for the
# rest of their budget and they double-run on resume. _abort() kills them all.
#
# Killing the fuzzer's process group is NOT enough: JSRunner puts the node
# server in a session of its own, so killpg(fuzzer) never reached it, and on a
# normal exit libFuzzer's C exit() skips JSRunner.stop(). Every node config
# leaked its server -- 663 orphans / ~47 GB on the VM, 2026-09-23. Each config
# therefore gets a unique TOFU_REAP_TAG in its environment, inherited by every
# descendant, and reap() kills whatever still carries it (procreap.py).
_LIVE = {}
_LIVE_LOCK = threading.Lock()


def reap(tag):
    try:
        return procreap.reap_tagged(procreap.TAG_ENV, tag)
    except Exception:
        return 0


def _abort(signum, frame):
    with _LIVE_LOCK:
        live = list(_LIVE.items())
    for p, _tag in live:
        try: os.killpg(p.pid, signal.SIGKILL)
        except Exception: pass
    for _p, tag in live:
        reap(tag)
    # take the index lock so no record is torn mid-write, then leave at once
    # (a normal exit would block in ThreadPoolExecutor shutdown for up to
    # budget + TOFU_KILL_GRACE seconds).
    lock.acquire(timeout=5)
    sys.stderr.write(f"\n[run_eval] interrupted (signal {signum}): killed {len(live)} "
                     f"in-flight config(s); they are not in the index and re-run on resume\n")
    sys.stderr.flush()
    os._exit(130)

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def done_set():
    s = set()
    if os.path.exists(RUNS):
        for line in open(RUNS):
            try: s.add(json.loads(line)["config"])
            except Exception: pass
    return s

def provenance(budget, workers):
    """Per-run provenance. The paper's experimental-setup subsection needs
    these and they cannot be reconstructed after the fact."""
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT,
                                capture_output=True, timeout=15
                                ).stdout.decode().strip() or None
    except Exception:
        commit = None
    v = sys.version_info
    return {
        "budget_s": budget,
        "workers": workers,
        "tofu_commit": commit,
        "llm_model": os.environ.get("TOFU_LLM_MODEL"),
        "llm_base_url": os.environ.get("TOFU_LLM_BASE_URL"),
        # Sampling settings decide whether a run is reproducible at all, and
        # whether a model-vs-model comparison is measuring the model or noise.
        "llm_temperature": os.environ.get("TOFU_LLM_TEMPERATURE", "0"),
        "llm_seed": os.environ.get("TOFU_LLM_SEED", "20260910"),
        # Reasoning is an EXPERIMENTAL VARIABLE for a thinking model, not a
        # tuning knob: it changes how sanitizers get selected, which is what
        # RQ2/RQ3 measure. gemma4:12b with reasoning uncapped hung past the
        # harness ceiling without completing one call (2026-09-10).
        "llm_reasoning": os.environ.get("TOFU_LLM_REASONING", "none"),
        "llm_max_tokens": os.environ.get("TOFU_LLM_MAX_TOKENS", "4096"),
        "js_cov_slots": os.environ.get("TOFU_JS_COV_SLOTS", "10000"),
        "python": f"{v.major}.{v.minor}.{v.micro}",
        "platform": f"{platform.system()}-{platform.machine()}",
    }


# --------------------------------------------------------------------------
# LOG PARSING
# --------------------------------------------------------------------------
# Every string matched here was verified against a REAL campaign log, not
# against what the code was assumed to print. The reporter emits:
#     [POTENTIAL VULNERABILITY / BUG FOUND] in '<tool>' !
#     WARNING:src.reporters:   -> Analysis     : [...] Silent Bug Alert:
#         Sanitizers ['check_x', ...] flagged this input as malicious, but ...
#     WARNING:src.reporters:   -> Triggered Sanitizers : ['check_x', ...]
# The banner and the "Silent Bug Alert" text are TWO LINES OF ONE FINDING, so
# summing both (as the previous version did) double-counts every finding.

_RE_BANNER   = re.compile(r"\[POTENTIAL VULNERABILITY / BUG FOUND\]")
_RE_TRIGGER  = re.compile(r"Triggered Sanitizers\s*:\s*(\[[^\]]*\])")
_RE_FLAGGED  = re.compile(r"Sanitizers\s*(\[[^\]]*\])\s*flagged")
_RE_CHECK    = re.compile(r"check_[A-Za-z0-9_]+")
_RE_SEL_OK   = re.compile(r"LLM_SELECTION_OK\b[^\n]*?n_selected=(\d+)\s+n_dropped=(\d+)")
_RE_SEED_OK  = re.compile(r"LLM_SEEDGEN_OK\b[^\n]*?n_seeds=(\d+)")

_RE_EXEC = re.compile(
    r"EXEC_SUMMARY tool=(\S+) n_exec=(\d+) n_success=(\d+) success_rate=([\d.]+)")
_RE_EXEC_ERR = re.compile(r"EXEC_ERROR n=(\d+) detail=(.+)")


def parse_log(out: str) -> dict:
    """Derive every measured quantity from one run's captured output."""
    rec = {}

    # finding_hits = the reporter's finding banner, counted ONCE per finding.
    rec["finding_hits"] = len(_RE_BANNER.findall(out))

    # Raw alerts are overwhelmingly duplicates of one another. The number that
    # belongs in the paper is the deduplicated count, so record both and let
    # the analysis choose -- never silently report the raw number as findings.
    fired, sets = set(), set()
    for rx in (_RE_TRIGGER, _RE_FLAGGED):
        for m in rx.finditer(out):
            names = tuple(sorted(set(_RE_CHECK.findall(m.group(1)))))
            if names:
                sets.add(names)
                fired.update(names)
    rec["triggered_sanitizers"] = sorted(fired)
    rec["finding_classes"] = len(sets)          # distinct sanitizer-set signatures
    rec["finding_signatures"] = [list(s) for s in sorted(sets)]

    # Did the LLM stage actually run? Without this the campaign degrades
    # silently to the deterministic fallback while the logs look healthy.
    if "LLM_SELECTION_OK" in out:
        rec["llm_selection"] = "ok"
    elif "LLM_SELECTION_FAILED" in out or "Falling back to default sanitizers" in out:
        rec["llm_selection"] = "failed"
    else:
        rec["llm_selection"] = "unknown"
    m = _RE_SEL_OK.search(out)
    if m:
        rec["llm_n_selected"], rec["llm_n_dropped"] = int(m.group(1)), int(m.group(2))

    if "LLM_SEEDGEN_OK" in out:
        rec["llm_seeds"] = "ok"
    elif "LLM_SEEDGEN_FALLBACK" in out:
        rec["llm_seeds"] = "fallback"
    else:
        rec["llm_seeds"] = "unknown"
    m = _RE_SEED_OK.search(out)
    if m:
        rec["llm_n_seeds"] = int(m.group(1))

    # DID THE TOOL ACTUALLY RUN? A tool whose every execution returns
    # isError/JSON-RPC-error never executed, so no sanitizer could fire and
    # coverage cannot vary -- yet the run looks like a clean "0 findings".
    # Measured 2026-09-10: all 32 api7/apisix-mcp tools are in this state
    # because the server is an Admin-API client and nothing listens on :9180.
    # "Ran and found nothing" must never be recorded the same way as
    # "never actually ran".
    # LAST summary wins: it is emitted periodically during fuzzing because the
    # post-fuzz epilogue never runs (libFuzzer exits the process itself).
    # A deliberate fail-fast is NOT a target failure. sys.exit(0) from the fuzz
    # callback makes libFuzzer print "ERROR: libFuzzer: fuzz target exited" and
    # return non-zero, which would otherwise be recorded as ok=False with a
    # crash-looking error -- the same harness-bug-masquerading-as-target-failure
    # class the audit already fixed once. The log is the authority.
    rec["stopped_early"] = "FAILFAST" in out

    _all = _RE_EXEC.findall(out)
    m = None
    if _all:
        class _M:
            def __init__(self, g): self._g = g
            def group(self, i): return self._g[i - 1]
        m = _M(_all[-1])
    if m:
        rec["n_exec"] = int(m.group(2))
        rec["n_exec_success"] = int(m.group(3))
        rec["exec_success_rate"] = float(m.group(4))
        rec["executable"] = "no" if rec["n_exec_success"] == 0 and rec["n_exec"] > 0 else "yes"
    else:
        rec["n_exec"] = rec["n_exec_success"] = None
        rec["exec_success_rate"] = None
        rec["executable"] = "unknown"
    # INSTRUMENT FAILURE, NOT TARGET FAILURE (item 86/89, 2026-09-15). libFuzzer
    # prints "INFO: seed corpus: files: N" and then "#N INITED cov: C". When the
    # fuzzed package is not in atheris' include set it sees ZERO coverage
    # features and calls C exit(1) right after the seeds -- before INITED, and
    # before its own "no interesting inputs" message can leave the stderr pipe
    # engine._fuzz_with_interception reads from (the process is gone). The log
    # then shows one EXEC_SUMMARY n_exec=1 n_success=0 and nothing else, which
    # the rule above would record as executable=no -- an exclusion the target
    # never earned. uml-mcp (`python server.py`, code in mcp_core/) hit this.
    seeds_seen = "seed corpus:" in out
    inited = " INITED " in out or "INITED cov:" in out
    if seeds_seen and not inited:
        rec["libfuzzer_exited_before_inited"] = True
        rec["executable"] = "unknown"
        rec["note_instrument"] = ("libFuzzer exited after the seed corpus without INITED: no coverage "
                                  "features, i.e. the target package was not instrumented. Harness "
                                  "defect; not evidence about the target.")
    errs = [(int(a), b.strip()) for a, b in _RE_EXEC_ERR.findall(out)]
    if errs:
        rec["exec_errors"] = [{"n": a, "detail": b} for a, b in errs[:3]]
        # A 0-success run is AMBIGUOUS and must not be reported as one thing.
        # Two very different causes produce it:
        #   (a) the tool cannot run at all -- mcp-server-weread answers every
        #       input with the same missing-cookie error. A real exclusion.
        #   (b) the tool runs fine and rejects OUR inputs -- text_editor
        #       answered "Path must be absolute" 428 times because not one of
        #       2000 mutated paths was absolute. That is a SEED-QUALITY defect
        #       in ToFu, and calling it an exclusion would quietly drop a
        #       working, security-relevant target out of the denominator.
        # Recorded, not guessed: the share held by the single most common error
        # is a hint (one invariant message across wildly different inputs looks
        # like (a); varied validation messages look like (b)), but the call is
        # the operator's. summarize() prints both and refuses to pick.
        tot = sum(a for a, _ in errs)
        rec["exec_error_kinds"] = len(errs)
        rec["exec_error_top_share"] = round(max(a for a, _ in errs) / tot, 3) if tot else None
    return rec

def error_tail(out: str, returncode) -> str:
    tail = [ln for ln in out.splitlines()
            if ("Error" in ln or "error:" in ln.lower()) and ln.strip()]
    return tail[-1].strip()[:200] if tail else f"exit {returncode}"


def one(cfgfile, budget, prov):
    name    = os.path.basename(cfgfile)[:-5]
    cfgpath = os.path.join(CFG, os.path.basename(cfgfile))
    logpath = os.path.join(OUT, name + ".log")
    # Each run gets its OWN corpus and metrics directory. The fuzzer rmtree's
    # its corpus dir at tool start; with a shared default ("./fuzz_corpus")
    # and >1 worker, concurrent runs delete each other's corpora mid-campaign.
    # Arm-scoped so two arms never share a corpus or overwrite each other's
    # coverage timelines.
    _a      = ("_" + ARM) if ARM else ""
    corpus  = os.path.join(EVAL, "corpora" + _a, name)
    metrics = os.path.join(EVAL, "metrics" + _a, name)
    t0  = time.time()
    rec = {"config": os.path.basename(cfgfile), "started": time.time()}
    rec.update(prov)
    out, rc, timed_out, harness_err = "", None, False, None
    scratch = None
    tag = f"{name}.{uuid.uuid4().hex}"
    try:
        cfg = json.load(open(cfgpath))
        rec.update(repo=cfg.get("_repo"), set=cfg.get("_set"),
                   lang=cfg.get("_lang"), tool=cfg.get("target_tool"),
                   commit=cfg.get("_commit"))
        os.makedirs(corpus, exist_ok=True); os.makedirs(metrics, exist_ok=True)
        # start_new_session puts the child in its own process group so the
        # MCP server it spawns is killed too. Without it a timed-out run
        # leaks node/python servers for the rest of the campaign.
        # Per-run seed dir. The LLM's create_pdf/create_json/... @tool writers
        # used to write into the TRACKED src/predefined_seeds/, so every run
        # polluted the source tree and inherited the previous run's files.
        seeds = os.path.join(ROOT, "eval", "seeds", os.path.splitext(cfgfile)[0])
        os.makedirs(seeds, exist_ok=True)
        for _f in os.listdir(os.path.join(ROOT, "src", "predefined_seeds")):
            _src = os.path.join(ROOT, "src", "predefined_seeds", _f)
            _dst = os.path.join(seeds, _f)
            if os.path.isfile(_src) and not os.path.exists(_dst):
                shutil.copy(_src, _dst)
        env = dict(os.environ, TOFU_SEED_DIR=seeds)
        # LLM replay cache: one file per config keyed by its name. On a re-run an
        # already-cached tool costs ZERO LLM calls; a new/uncached tool calls the
        # model and records it. Default dir under eval/state; opt out by exporting
        # TOFU_LLM_CACHE_DISABLE=1. See src/llm.py + eval/gen_llm_cache.py.
        if not os.environ.get("TOFU_LLM_CACHE_DISABLE"):
            env.setdefault("TOFU_LLM_CACHE_DIR",
                           os.path.join(ROOT, "eval", "state", "llm_cache"))
            env["TOFU_LLM_CACHE_KEY"] = os.path.splitext(os.path.basename(cfgfile))[0]

        # item 91: run the fuzzer (and thus any in-process Python target) in a
        # throwaway per-config scratch dir OUTSIDE the repo, so a target's
        # relative-path filesystem writes/deletes land in scratch, not the harness
        # tree. PYTHONPATH carries ROOT so `-m src` still imports; every path the
        # fuzzer is given (config/corpus/metrics/seeds) is already absolute.
        scratch = os.path.join(SCRATCH_ROOT, name)
        shutil.rmtree(scratch, ignore_errors=True)
        os.makedirs(scratch, exist_ok=True)
        env["PYTHONPATH"] = ROOT + (os.pathsep + env["PYTHONPATH"]
                                    if env.get("PYTHONPATH") else "")
        # item 91 (env isolation): a fuzzed session/terminal-manager target
        # inherits $TMUX and drives the HARNESS's OWN tmux server --
        # nickgnd/tmux-mcp's kill-session/execute-command killed the campaign's
        # tmux session mid-run (2026-09-18). Detach the child from any tmux and
        # point tmux at the throwaway scratch, so a target's tmux ops land on an
        # isolated socket instead of the operator's sessions.
        env.pop("TMUX", None)
        env.pop("TMUX_PANE", None)
        env["TMUX_TMPDIR"] = scratch
        env[procreap.TAG_ENV] = tag

        p = subprocess.Popen(
            [sys.executable, "-m", "src", "--config", cfgpath, "--time", str(budget),
             "--corpus-dir", corpus, "--metrics-dir", metrics],
            cwd=scratch, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, env=env)
        with _LIVE_LOCK:
            _LIVE[p] = tag
        # TOFU_KILL_GRACE (default 600) = seconds ALLOWED beyond the fuzz budget
        # before the whole subprocess is SIGKILLed. atheris caps the fuzz loop at
        # -max_total_time already; the grace only covers LLM + startup + cleanup
        # (~15s). 600 let a HUNG per-exec network call (node tools run ~1 exec/s
        # and block on the target's outbound API) sit for 11 min. The corpus
        # campaign sets 60; keep 600 default for other arms.
        _grace = int(os.environ.get("TOFU_KILL_GRACE", "600"))
        try:
            so, se = p.communicate(timeout=budget + _grace)
            rc = p.returncode
        except subprocess.TimeoutExpired:
            timed_out = True
            try: os.killpg(p.pid, signal.SIGKILL)
            except Exception: pass
            # A server holding the fuzzer's stdout/stderr open would block
            # communicate() forever; kill the tagged tree before draining.
            rec["reaped"] = reap(tag)
            so, se = p.communicate()
            rc = p.returncode
        with _LIVE_LOCK:
            _LIVE.pop(p, None)
        out = (so or b"").decode(errors="ignore") + "\n" + (se or b"").decode(errors="ignore")
    except Exception as e:
        # A failure HERE is our bug, not the target's. Keep it in its own
        # field so a harness bug can never masquerade as a target result.
        harness_err = f"{type(e).__name__}: {e}"[:300]
    finally:
        # Whatever this config started and is still alive -- on a normal exit,
        # a timeout or a harness exception alike -- dies here. Nonzero means
        # the wrapper's orphan guard and PDEATHSIG both missed something.
        rec["reaped"] = rec.get("reaped", 0) + reap(tag)

    # item 91: drop the throwaway scratch cwd (disposable; whatever the target
    # wrote/deleted in it goes with it, keeping the harness tree clean).
    if scratch:
        shutil.rmtree(scratch, ignore_errors=True)

    # The log is written BEFORE parsing, unconditionally -- including on
    # timeout, which the previous version discarded entirely along with any
    # findings the run had already produced.
    if out.strip():
        try:
            with open(logpath, "w") as f: f.write(out)
            rec["log"] = os.path.relpath(logpath, ROOT)
        except Exception as e:
            harness_err = harness_err or f"log write failed: {e}"[:300]
    try:
        rec.update(parse_log(out))
    except Exception as e:
        harness_err = harness_err or f"parse_log failed: {type(e).__name__}: {e}"[:300]

    # A fail-fast exit is intentional: the tool never executed successfully and
    # the run stopped on purpose. Its measurements are valid and it must not be
    # counted as an error.
    stopped_early = bool(rec.get("stopped_early"))
    failed = timed_out or (rc != 0 and not stopped_early) or harness_err is not None
    rec.update(returncode=rc, seconds=round(time.time() - t0, 1),
               timed_out=timed_out, ok=not failed)
    if harness_err:
        rec["harness_error"] = harness_err
    if timed_out:
        rec["error"] = f"timeout after {budget + _grace}s"
    elif stopped_early:
        rec["error"] = None
        rec["note"] = (f"stopped early: {rec.get('n_exec')} executions, none succeeded "
                       f"(TOFU_FAILFAST_EXECS). Not a target failure, and NOT a clean run.")
    elif rc not in (0, None):
        rec["error"] = error_tail(out, rc)

    with lock:
        counter["done"] += 1
        if harness_err: counter["harness_errors"] += 1
        if failed: counter["errors"] += 1
        # Count findings independently of failure: a run that crashed AFTER
        # producing findings still produced them.
        if rec.get("finding_hits"): counter["findings"] += 1
        with open(RUNS, "a") as f: f.write(json.dumps(rec) + "\n")
    return rec


def reparse(quiet=False):
    """Rebuild runs.jsonl from the per-run logs on disk.

    Existing records are matched by config name; parsed fields are refreshed
    and everything else (timings, provenance, returncode) is preserved. Logs
    with no record at all get a minimal one, so a run whose record was lost
    to a harness bug is recovered rather than re-run."""
    recs, order = {}, []
    if os.path.exists(RUNS):
        for line in open(RUNS):
            try: r = json.loads(line)
            except Exception: continue
            c = r.get("config")
            if c not in recs: order.append(c)
            recs[c] = r          # last record for a config wins
    n_new = n_upd = 0
    for fn in sorted(os.listdir(OUT)) if os.path.isdir(OUT) else []:
        if not fn.endswith(".log"): continue
        cfg = fn[:-4] + ".json"
        try:
            out = open(os.path.join(OUT, fn), errors="ignore").read()
        except Exception:
            continue
        parsed = parse_log(out)
        if cfg in recs:
            before = recs[cfg].get("finding_hits")
            recs[cfg].update(parsed)
            recs[cfg]["reparsed"] = True
            recs[cfg].pop("harness_error", None)
            if before != parsed["finding_hits"]: n_upd += 1
        else:
            r = {"config": cfg, "log": os.path.join("eval", "runs", fn),
                 "reparsed": True, "recovered_from_log_only": True}
            r.update(parsed)
            recs[cfg] = r; order.append(cfg); n_new += 1
    bak = RUNS + ".pre-reparse-" + time.strftime("%Y%m%d_%H%M%S")
    if os.path.exists(RUNS):
        os.replace(RUNS, bak)
    with open(RUNS, "w") as f:
        for c in order:
            f.write(json.dumps(recs[c]) + "\n")
    if not quiet:
        log(f"reparsed {len(recs)} records from {OUT}")
        log(f"  {n_upd} records had their finding counts corrected, {n_new} recovered from log only")
        log(f"  previous index saved to {os.path.basename(bak)}")
    return recs

def summarize(allrecs):
    if not allrecs: return
    sel, seed = {}, {}
    for r in allrecs:
        sel[r.get("llm_selection", "unknown")]  = sel.get(r.get("llm_selection", "unknown"), 0) + 1
        seed[r.get("llm_seeds", "unknown")]     = seed.get(r.get("llm_seeds", "unknown"), 0) + 1
    log("  LLM sanitizer selection: " + ", ".join(f"{k}={v}" for k, v in sorted(sel.items())))
    log("  LLM seed generation:     " + ", ".join(f"{k}={v}" for k, v in sorted(seed.items())))
    if sel.get("ok", 0) == 0:
        log("  !! LLM selection never succeeded -- every run used the "
            "deterministic fallback. Do NOT report these as ToFu results.")
    hits  = [r for r in allrecs if r.get("finding_hits")]
    raw   = sum(r.get("finding_hits", 0) for r in allrecs)
    dedup = sum(r.get("finding_classes", 0) for r in allrecs)
    log(f"  runs with alerts: {len(hits)}/{len(allrecs)}   raw alerts: {raw}   "
        f"distinct sanitizer-set signatures: {dedup}")
    if raw and dedup and raw / max(dedup, 1) > 5:
        log("  NOTE: alerts are heavily duplicated. Report the deduplicated "
            "count, and triage signatures before calling any of them findings.")
    # EXECUTABILITY. The single most important thing to know before reading a
    # "0 findings" result: did the tool ever actually execute? A tool that
    # errors on every input cannot fire a sanitizer and cannot vary coverage,
    # so its clean run means nothing about the tool.
    ex = {}
    for r in allrecs:
        ex[r.get("executable", "unknown")] = ex.get(r.get("executable", "unknown"), 0) + 1
    log("  tool executability:      " + ", ".join(f"{k}={v}" for k, v in sorted(ex.items())))
    dead = [r for r in allrecs if r.get("executable") == "no"]
    if dead:
        log(f"  !! {len(dead)} run(s) had ZERO successful executions. Their "
            f"'0 findings' is not evidence about the target. BUT 0 successes is "
            f"AMBIGUOUS -- decide per row which of these it is:")
        log("       (a) the tool cannot run here      -> a real environment exclusion")
        log("       (b) the tool rejected OUR inputs  -> a ToFu seed-quality defect,")
        log("           and the target must STAY in the denominator")
        seen = {}
        for r in dead:
            d = (r.get("exec_errors") or [{}])[0].get("detail", "?")
            seen.setdefault(d, []).append(r.get("config"))
        for d, cfgs in sorted(seen.items(), key=lambda kv: -len(kv[1]))[:5]:
            ex = next((r for r in dead if r.get("config") == cfgs[0]), {})
            share, kinds = ex.get("exec_error_top_share"), ex.get("exec_error_kinds")
            hint = ""
            if share is not None:
                hint = (f"  [top error {share:.0%} of failures across {kinds} kind(s)"
                        f" -- {'looks invariant, likely (a)' if share >= 0.9 and kinds <= 2 else 'varied, likely (b)'}]")
            log(f"       {len(cfgs):3d} run(s): {d[:100]}{hint}")
            log(f"            e.g. {cfgs[0]}")
    part = [r for r in allrecs
            if r.get("exec_success_rate") is not None and 0 < r["exec_success_rate"] < 0.05]
    if part:
        log(f"  !! {len(part)} run(s) executed successfully on under 5% of inputs -- "
            f"mostly-error paths, treat their coverage and findings with care.")

    he = [r for r in allrecs if r.get("harness_error")]
    if he:
        log(f"  !! {len(he)} runs recorded a HARNESS error (our bug, not the target's):")
        for r in he[:5]: log(f"       {r.get('config')}: {r.get('harness_error')}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--time", type=int, default=900, help="fuzzing seconds per tool")
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--limit", type=int, default=None)
    # Repo filters. 108 of the 116 remaining configs belong to repos that
    # cannot execute here at all (no APISIX on :9180, no graphlit credential,
    # no n8n backend), so an unordered sweep spends ~7h re-confirming that.
    # These only choose WHICH configs run; they change nothing about how.
    ap.add_argument("--arm", default=None,
                    help="name this experimental arm; its index, logs, corpora and "
                         "metrics are kept separate from every other arm")
    ap.add_argument("--only-repo", default=None,
                    help="comma-separated substrings; run only configs whose _repo matches one")
    ap.add_argument("--skip-repo", default=None,
                    help="comma-separated substrings; skip configs whose _repo matches one")
    ap.add_argument("--set", default=None,
                    help="restrict to one set: A, B or D (Set D is opt-in)")
    ap.add_argument("--priority-repos-file", default=None,
                    help="file with a repo list (comma/newline separated); configs whose "
                         "_repo matches one run FIRST. Ordering only -- nothing is dropped. "
                         "Use with Benchmarks/extraction/set_e2_repos.txt to fuzz the "
                         "bug-bearing (tier-1) repos before the log/network-only tail.")
    ap.add_argument("--skip-repos-file", default=None,
                    help="file with a repo list (comma/newline separated); configs whose "
                         "_repo matches one are SKIPPED. Use with set_e2_unsafe_repos.txt to "
                         "exclude host-control targets (process kill/spawn, tmux, FS delete) "
                         "that crash the harness when fuzzed without a sandbox.")
    ap.add_argument("--only-configs-file", default=None,
                    help="file of exact config names (eval/configs basenames, one per "
                         "line or comma-separated); run ONLY those. Exact, tool-level, "
                         "no substring collisions. Used by eval/run_deep24.sh.")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--reparse", action="store_true",
                    help="rebuild runs.jsonl from eval/runs/*.log and exit")
    ap.add_argument("--skip-preflight", action="store_true")
    a = ap.parse_args()
    if a.arm:
        _apply_arm(a.arm)
        log(f"--arm {a.arm}: index -> {os.path.relpath(RUNS, ROOT)}, "
            f"logs -> {os.path.relpath(OUT, ROOT)}")

    for d in (STATE, OUT): os.makedirs(d, exist_ok=True)

    if a.reparse:
        recs = reparse()
        summarize(list(recs.values()))
        return

    if not os.path.isdir(CFG):
        log("no eval/configs/ -- run prepare_targets.py first"); sys.exit(1)

    all_cfg = sorted(f for f in os.listdir(CFG) if f.endswith(".json"))
    if a.set:
        want, keep = a.set.strip().upper(), []
        for f in all_cfg:
            try:
                if str(json.load(open(os.path.join(CFG, f))).get("_set", "")).upper() == want:
                    keep.append(f)
            except Exception: pass
        all_cfg = keep
        log(f"--set {want}: {len(all_cfg)} configs")

    def _repo_of(f):
        try:
            return str(json.load(open(os.path.join(CFG, f))).get("_repo", ""))
        except Exception:
            return ""

    if a.only_repo:
        pats = [p.strip().lower() for p in a.only_repo.split(",") if p.strip()]
        all_cfg = [f for f in all_cfg if any(p in _repo_of(f).lower() for p in pats)]
        log(f"--only-repo {pats}: {len(all_cfg)} configs")
    if a.skip_repo:
        pats = [p.strip().lower() for p in a.skip_repo.split(",") if p.strip()]
        before = len(all_cfg)
        all_cfg = [f for f in all_cfg if not any(p in _repo_of(f).lower() for p in pats)]
        log(f"--skip-repo {pats}: dropped {before - len(all_cfg)}, {len(all_cfg)} remain")

    if a.only_configs_file:
        # Exact config-name allowlist (basename without .json, one per line or
        # comma-separated). Unlike --only-repo this is exact, tool-level, and
        # collision-free -- used by the 24h deep campaign to fuzz only the
        # reachable, still-climbing tools chosen by eval/select_deep24.py.
        raw = open(a.only_configs_file).read()
        want = {p.strip() for p in raw.replace("\n", ",").split(",")
                if p.strip() and not p.strip().startswith("#")}
        want = {w[:-5] if w.endswith(".json") else w for w in want}
        all_cfg = [f for f in all_cfg if os.path.splitext(f)[0] in want]
        missing = want - {os.path.splitext(f)[0] for f in all_cfg}
        log(f"--only-configs-file: {len(all_cfg)} configs kept"
            + (f", {len(missing)} listed but not found in eval/configs" if missing else ""))

    if a.skip_repos_file and os.path.exists(a.skip_repos_file):
        raw = open(a.skip_repos_file).read()
        unsafe = {p.strip().lower() for p in raw.replace("\n", ",").split(",") if p.strip()}
        before = len(all_cfg)
        all_cfg = [f for f in all_cfg if _repo_of(f).lower() not in unsafe]
        log(f"--skip-repos-file: dropped {before - len(all_cfg)} unsafe-target configs, "
            f"{len(all_cfg)} remain")

    if a.priority_repos_file:
        raw = open(a.priority_repos_file).read()
        prio = {p.strip().lower() for p in raw.replace("\n", ",").split(",") if p.strip()}
        # stable partition: priority configs keep their (alphabetical) order and
        # move to the front; everything else follows. Ordering only -- the set of
        # configs is unchanged, so the run stays resumable and complete.
        head = [f for f in all_cfg if _repo_of(f).lower() in prio]
        tail = [f for f in all_cfg if _repo_of(f).lower() not in prio]
        all_cfg = head + tail
        log(f"--priority-repos-file: {len(head)} configs first, then {len(tail)}")

    done = done_set()
    todo = [f for f in all_cfg if f not in done]

    if a.status:
        log(f"configs={len(all_cfg)} done={len(done)} remaining={len(todo)}")
        if os.path.exists(RUNS):
            recs = [json.loads(l) for l in open(RUNS) if l.strip()]
            log(f"runs recorded={len(recs)} "
                f"with_alerts={sum(1 for r in recs if r.get('finding_hits'))} "
                f"errors={sum(1 for r in recs if not r.get('ok'))}")
            summarize(recs)
        return

    base_url = os.environ.get("TOFU_LLM_BASE_URL", "https://ollama.com/v1")
    model    = os.environ.get("TOFU_LLM_MODEL", "minimax-m3:cloud")
    is_local  = "localhost" in base_url or "127.0.0.1" in base_url
    is_openai = "openai.com" in base_url
    # OPENAI_API_KEY counts as a configured backend. This check knew only about
    # OLLAMA_CLOUD_API_KEY and refused to start the hosted gpt-4.1 arm even
    # though src/llm.py and src/__main__.py both resolve the OpenAI key.
    api_key = (os.environ.get("OPENAI_API_KEY") if is_openai else None) \
        or os.environ.get("OLLAMA_CLOUD_API_KEY")
    if not is_local and not api_key:
        log("ERROR: no LLM backend configured.")
        log("  LOCAL Ollama:  export TOFU_LLM_BASE_URL=http://localhost:11434/v1")
        log("                 export TOFU_LLM_MODEL=gemma4:12b")
        log("                 export OLLAMA_CLOUD_API_KEY=ollama")
        log("  or OPENAI:     export TOFU_LLM_BASE_URL=https://api.openai.com/v1")
        log("                 export TOFU_LLM_MODEL=gpt-4.1")
        log("                 export OPENAI_API_KEY=<key>   (eval/run_arm_gpt41.sh does this)")
        sys.exit(1)
    log(f"LLM backend: model={model} base_url={base_url}")

    if not a.skip_preflight:
        try:
            import urllib.request
            req = urllib.request.Request(
                base_url.rstrip("/") + "/chat/completions",
                data=json.dumps({"model": model, "max_tokens": 8,
                                 "messages": [{"role": "user", "content": "reply with OK"}]}).encode(),
                headers={"Content-Type": "application/json",
                         "Authorization": "Bearer " + (api_key or "ollama")})
            with urllib.request.urlopen(req, timeout=90) as r:
                body = json.loads(r.read().decode())
            log(f"preflight OK -- model answered: {body['choices'][0]['message'].get('content','')[:60]!r}")
        except Exception as e:
            log(f"PREFLIGHT FAILED: {str(e)[:200]}")
            if is_local:
                log("  Is the daemon up?    ollama serve")
                log("  Is the model pulled? ollama pull " + model)
            log("  Re-run with --skip-preflight to bypass this check.")
            sys.exit(1)

    imp = subprocess.run([sys.executable, "-c", "import src.fuzzer"],
                         cwd=ROOT, capture_output=True, timeout=120)
    if imp.returncode != 0:
        raw = imp.stderr.decode(errors="ignore").strip()
        log("PREFLIGHT FAILED: ToFu is not importable. Full traceback:")
        for ln in raw.splitlines()[-25:]: log("    " + ln)
        v = sys.version_info
        log(f"  python: {v.major}.{v.minor}.{v.micro}  ({sys.executable})")
        if "dis" in raw and "Positions" in raw:
            log("  DIAGNOSIS: atheris/Python version mismatch. dis.Positions exists")
            log(f"             only in Python 3.11+, but you are on {v.major}.{v.minor}.")
            log("  Fix: use a Python 3.11-3.13 venv (3.13 preferred: Python targets are "
                "imported in-process and their venvs must match, item 86), then "
                "pip install -r requirements.txt")
        elif "ModuleNotFoundError" in raw:
            log("  Fix:  pip install -r requirements.txt")
        sys.exit(1)
    log("preflight OK -- src.fuzzer imports")

    # A static undefined-name check over the harness itself. Two whole
    # campaigns were destroyed by NameErrors that only fire deep inside a
    # run (a missing `import re` here; a missing seed_generators import in
    # src/llm.py), so this is checked before burning hours of compute.
    try:
        import pyflakes.api, pyflakes.reporter, io
        buf = io.StringIO()
        rep = pyflakes.reporter.Reporter(buf, buf)
        for f in (os.path.abspath(__file__), os.path.join(ROOT, "src", "llm.py"),
                  os.path.join(ROOT, "src", "fuzzer.py"), os.path.join(ROOT, "src", "input_parser.py")):
            if os.path.exists(f): pyflakes.api.checkPath(f, rep)
        undef = [l for l in buf.getvalue().splitlines() if "undefined name" in l]
        if undef:
            log("PREFLIGHT FAILED: undefined names found -- these become NameErrors mid-run:")
            for l in undef[:20]: log("    " + l)
            sys.exit(1)
        log("preflight OK -- no undefined names in the harness or LLM path")
    except ImportError:
        log("note: pyflakes not installed, skipping the undefined-name preflight "
            "(pip install pyflakes -- it is cheap insurance)")

    if a.limit: todo = todo[:a.limit]
    prov = provenance(a.time, a.workers)
    log(f"configs={len(all_cfg)} done={len(done)} todo={len(todo)} "
        f"budget={a.time}s/tool workers={a.workers}")
    log(f"provenance: commit={prov['tofu_commit']} model={prov['llm_model']} "
        f"python={prov['python']} {prov['platform']}")
    log(f"rough wall-clock estimate: {len(todo) * a.time / max(a.workers,1) / 3600:.1f} h")

    signal.signal(signal.SIGINT, _abort)
    signal.signal(signal.SIGTERM, _abort)
    signal.signal(signal.SIGHUP, _abort)   # tmux/ssh session closed under us
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        for i, r in enumerate(ex.map(lambda f: one(f, a.time, prov), todo), 1):
            tag = ("BUG " if r.get("harness_error") else
                   "HIT " if r.get("finding_hits") else
                   "ERR " if not r.get("ok") else "    ")
            log(f"{tag}[{i}/{len(todo)}] {r.get('repo')}::{r.get('tool')} "
                f"{r.get('seconds')}s alerts={r.get('finding_hits',0)} "
                f"sigs={r.get('finding_classes',0)} llm={r.get('llm_selection')}")
    log(f"DONE {counter['done']} runs, {counter['findings']} with alerts, "
        f"{counter['errors']} errors, {counter['harness_errors']} harness bugs, "
        f"{(time.time()-t0)/3600:.2f} h")
    try:
        allrecs = [json.loads(l) for l in open(RUNS) if l.strip()]
    except Exception:
        allrecs = []
    summarize(allrecs)
    log(f"  per-run logs -> {OUT}")
    log(f"  index        -> {RUNS}")

if __name__ == "__main__":
    main()
