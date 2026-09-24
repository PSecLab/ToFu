#!/usr/bin/env python3
"""Per-repository deep fuzzing: a 24 worker-hour budget per repo with
saturation-based early termination (RQ4).

PROTOCOL (report it exactly like this -- a repo that stops early was NOT fuzzed
for 24 h, and the paper must not say it was):

  * Each repository gets BUDGET worker-hours (default 24) on ONE worker; up to
    --workers repositories run in parallel, one per core.
  * Its reachable tools (>=1 successful execution in the source arm) are fuzzed
    in round-robin SLICES (default plateau + 10 min = 70 min). Every slice resumes from that tool's
    saved corpus (TOFU_KEEP_CORPUS=1), so revisiting a tool continues its search.
  * A tool is SATURATED once it has accumulated PLATEAU fuzz-seconds (default
    1 h) with no new coverage edge AND no new finding signature. "New finding"
    means a new triggered-sanitizer set, not a new distinct input: libFuzzer
    keeps producing distinct inputs for a bug it already found, and the corpus
    replay at the start of every slice re-fires old alerts.
  * The repo stops when every tool is saturated or dead (all_saturated), or when
    the budget is spent (budget_exhausted). Both the budget and the hours
    actually used are recorded per repo.

Time accounting: worker_h counts wall time of every slice including startup;
fuzz_h counts only fuzz-loop time from the coverage timelines. Tool clocks are
cumulative over slices, and the stitched coverage/findings series for each tool
are written to eval/metrics_<arm>/<config>/stitched_{coverage,findings}.csv.

Resumable and Ctrl-C-safe: the ledger (eval/state/repo24_state.<arm>.json) is
rewritten atomically after every slice; an interrupted slice is not in the
ledger and simply re-runs. Ctrl-C kills every in-flight fuzzer (run_eval._abort).

Run through eval/run_repo24.sh, never directly (it sets the model, temperature,
seed and hides .env). Selection: --select N writes eval/repo24_repos.txt.
"""
import argparse, collections, csv, glob, json, os, signal, sys, threading, time
from concurrent.futures import ThreadPoolExecutor

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import run_eval as RE        # one(): scratch cwd, env scrub, LLM cache, kill grace, Ctrl-C registry
import select_deep24 as SD   # load_jsonl(), timeline(), momentum()

STATE_LOCK = threading.Lock()
MIN_SLICE = 300              # do not start a slice shorter than this


def log(m):
    RE.log(m)


# ---------------------------------------------------------------- selection
def load_exclusions():
    out = set()
    for rel in ("Benchmarks/extraction/set_e2_unsafe_repos.txt",
                "Benchmarks/extraction/deep24_exclude_repos.txt"):
        p = os.path.join(ROOT, rel)
        if os.path.exists(p):
            out |= {x.strip().lower() for x in open(p).read().replace("\n", ",").split(",") if x.strip()}
    return out


def repo_inventory(source_arm):
    """repo -> {'lang', 'reachable': [(config, tool, prior_momentum_dict)], 'unreachable': [tool]}"""
    runs = SD.load_jsonl(os.path.join(ROOT, "eval", "state", f"runs.{source_arm}.jsonl"))
    latest = {}
    for r in runs:
        c = (r.get("config") or "").strip()
        if c.endswith(".json"):
            c = c[:-5]
        if c:
            latest[c] = r
    metrics_root = os.path.join(ROOT, "eval", f"metrics_{source_arm}")
    inv = collections.defaultdict(lambda: {"lang": "?", "reachable": [], "unreachable": []})
    for cfg, r in latest.items():
        repo = r.get("repo") or ""
        if not repo:
            continue
        e = inv[repo]
        e["lang"] = r.get("lang") or e["lang"]
        if r.get("ok") and (r.get("n_exec_success") or 0) > 0:
            pts = SD.timeline(metrics_root, cfg)
            m = SD.momentum(pts) if len(pts) >= 3 else {"score": 0.0, "cov_final": 0, "t_end": 0}
            e["reachable"].append((cfg, r.get("tool") or "", m))
        else:
            e["unreachable"].append(r.get("tool") or cfg)
    return inv


def select(n, source_arm, out_path):
    excl = load_exclusions()
    inv = repo_inventory(source_arm)
    ranked = []
    for repo, e in inv.items():
        if repo.lower() in excl or not e["reachable"]:
            continue
        score = sum(max(0.0, m["score"]) for _, _, m in e["reachable"])
        if score <= 0:
            continue  # every reachable tool already saturated in the corpus run
        ranked.append((score, repo, e))
    ranked.sort(key=lambda x: -x[0])
    pick = ranked[:n]
    with open(out_path, "w") as f:
        f.write(f"# repo24 selection {time.strftime('%Y-%m-%d')}: top {len(pick)} repos by summed "
                f"coverage momentum (source arm {source_arm}); unsafe + deep24_exclude removed\n")
        for score, repo, e in pick:
            f.write(repo + "\n")
    print(f"{len(ranked)} candidate repos; wrote top {len(pick)} -> {os.path.relpath(out_path, ROOT)}")
    for score, repo, e in pick:
        print(f"  {score:8.1f}  {e['lang']:6} tools={len(e['reachable']):2d} "
              f"(unreachable {len(e['unreachable'])})  {repo}")


# ---------------------------------------------------------------- ledger
def state_path(arm):
    return os.path.join(RE.STATE, f"repo24_state.{arm}.json")


def load_state(arm):
    p = state_path(arm)
    if os.path.exists(p):
        try:
            return json.load(open(p))
        except Exception:
            pass
    return {"repos": {}}


def save_state(arm, st):
    p = state_path(arm)
    tmp = p + ".tmp"
    with open(tmp, "w") as f:
        json.dump(st, f, indent=1)
    os.replace(tmp, p)   # atomic: an interrupt can never leave a torn ledger


def new_tool(cfg, tool, prior):
    return {"config": cfg, "tool": tool, "status": "active", "fuzz_s": 0.0,
            "best_cov": 0, "t_last_edge": 0.0, "t_last_sig": 0.0,
            "sigs": [], "n_inputs": 0, "hashes": [], "slices": 0, "failures": 0,
            "worker_s": 0.0, "prior_cov_final": prior.get("cov_final", 0),
            "prior_t_end": prior.get("t_end", 0), "prior_momentum": prior.get("score", 0.0)}


# ---------------------------------------------------------------- one slice
def _read_rows(path):
    try:
        return list(csv.DictReader(open(path)))
    except Exception:
        return []


def run_slice(arm, t, slice_s, prov, plateau):
    """Fuzz one tool for one slice, fold its timelines into the tool ledger."""
    name = t["config"]
    metrics = os.path.join(RE.EVAL, f"metrics_{arm}", name)
    os.makedirs(metrics, exist_ok=True)
    before = set(glob.glob(os.path.join(metrics, "*_timeline_*.csv")))
    rec = RE.one(name + ".json", slice_s, prov)
    new_files = sorted(set(glob.glob(os.path.join(metrics, "*_timeline_*.csv"))) - before)

    # keep every slice's log (one() writes <name>.log and would overwrite it)
    lp = os.path.join(RE.OUT, name + ".log")
    if os.path.exists(lp):
        os.replace(lp, os.path.join(RE.OUT, f"{name}.slice{t['slices'] + 1:03d}.log"))

    base = t["fuzz_s"]
    cov_rows, fnd_rows = [], []
    for fp in new_files:
        rows = _read_rows(fp)
        (cov_rows if os.path.basename(fp).startswith("coverage_timeline_") else fnd_rows).extend(rows)

    t_end = 0.0
    stitched_cov = []
    for r in sorted(cov_rows, key=lambda r: float(r.get("relative_time_sec") or 0)):
        try:
            rt = float(r["relative_time_sec"]); cov = int(float(r["cov_edges"]))
        except Exception:
            continue
        t_end = max(t_end, rt)
        if cov > t["best_cov"]:
            t["best_cov"] = cov
            t["t_last_edge"] = base + rt
        stitched_cov.append((round(base + rt, 1), t["best_cov"]))

    seen_sigs, seen_h = set(t["sigs"]), set(t["hashes"])
    stitched_fnd = []
    for r in sorted(fnd_rows, key=lambda r: float(r.get("relative_time_sec") or 0)):
        try:
            rt = float(r["relative_time_sec"])
        except Exception:
            continue
        sig = r.get("triggered_sanitizers") or ""
        h = r.get("input_hash") or ""
        if h and h not in seen_h:
            seen_h.add(h); t["n_inputs"] += 1
        new_sig = sig and sig not in seen_sigs
        if new_sig:
            seen_sigs.add(sig); t["t_last_sig"] = base + rt
        stitched_fnd.append((round(base + rt, 1), sig, h, int(bool(new_sig))))
    t["sigs"], t["hashes"] = sorted(seen_sigs), sorted(seen_h)

    ok = bool(rec.get("ok")) and (rec.get("n_exec_success") or 0) > 0 and t_end > 0
    t["slices"] += 1
    t["worker_s"] += float(rec.get("seconds") or 0)
    t["fuzz_s"] = base + t_end
    t.setdefault("seed_sources", []).append(rec.get("llm_seeds") or "unknown")
    strict = os.environ.get("TOFU_REQUIRE_LLM_SEEDS", "").strip().lower() not in ("", "0", "false", "no")
    if not ok:
        t["failures"] += 1
        t["last_error"] = (rec.get("error") or rec.get("harness_error") or "")[-300:]
        if "SeedProvenanceError" in t["last_error"] or "SEED_PROVENANCE_FAIL" in t["last_error"]:
            # the LLM already retried 4x inside generate_seeds; at temperature 0 and a
            # fixed seed another slice would replay the same failure -- stop now
            t["status"] = "no_llm_seeds"
        elif t["failures"] >= 2:
            t["status"] = "dead"
    elif strict and rec.get("llm_seeds") != "ok":
        # belt and braces: strict mode should make this impossible. If a slice
        # still ran on non-LLM seeds, stop fuzzing the tool and say why.
        t["status"] = "no_llm_seeds"
        t["last_error"] = f"slice ran with llm_seeds={rec.get('llm_seeds')!r} under TOFU_REQUIRE_LLM_SEEDS"
    idle = t["fuzz_s"] - max(t["t_last_edge"], t["t_last_sig"])
    if t["status"] == "active" and t["fuzz_s"] >= plateau and idle >= plateau:
        t["status"] = "saturated"

    with open(os.path.join(metrics, "stitched_coverage.csv"), "a", newline="") as f:
        w = csv.writer(f)
        if f.tell() == 0:
            w.writerow(["tool_clock_s", "cov_edges_best"])
        w.writerows(stitched_cov)
    with open(os.path.join(metrics, "stitched_findings.csv"), "a", newline="") as f:
        w = csv.writer(f)
        if f.tell() == 0:
            w.writerow(["tool_clock_s", "triggered_sanitizers", "input_hash", "new_signature"])
        w.writerows(stitched_fnd)
    return rec, ok, idle


# ---------------------------------------------------------------- one repo
def run_repo(arm, repo, inv_e, st, budget_s, slice_s, plateau, prov):
    with STATE_LOCK:
        R = st["repos"].get(repo)
        if R is None:
            R = {"repo": repo, "lang": inv_e["lang"], "budget_h": budget_s / 3600,
                 "worker_s": 0.0, "status": "running", "stop_reason": None,
                 "started": time.time(), "finished": None,
                 "unreachable_tools": inv_e["unreachable"],
                 "tools": [new_tool(c, tl, m) for c, tl, m in
                           sorted(inv_e["reachable"], key=lambda x: -x[2].get("score", 0))]}
            st["repos"][repo] = R
            save_state(arm, st)
    if R["status"] == "done":
        return R
    tools, n = R["tools"], len(R["tools"])
    cur = R.get("cursor", 0)   # stable round-robin over the full list: a tool that
                               # saturates must not make the scheduler skip its successor
    while True:
        if not any(t["status"] == "active" for t in tools):
            R["stop_reason"] = "all_saturated"; break
        remaining = budget_s - R["worker_s"]
        if remaining < MIN_SLICE:
            R["stop_reason"] = "budget_exhausted"; break
        while tools[cur % n]["status"] != "active":
            cur += 1
        t = tools[cur % n]; cur += 1
        R["cursor"] = cur % n
        this = int(min(slice_s, remaining))
        rec, ok, idle = run_slice(arm, t, this, prov, plateau)
        with STATE_LOCK:
            R["worker_s"] += float(rec.get("seconds") or 0)
            save_state(arm, st)
        log(f"{'    ' if ok else 'ERR '}{repo}::{t['tool']} slice {t['slices']} "
            f"{rec.get('seconds')}s cov={t['best_cov']} sigs={len(t['sigs'])} "
            f"idle={idle/60:.0f}m -> {t['status']}  repo {R['worker_s']/3600:.2f}/{budget_s/3600:.3g}h")
    with STATE_LOCK:
        for t in R["tools"]:
            if t["status"] == "active":
                t["status"] = "budget"
        R["status"], R["finished"] = "done", time.time()
        save_state(arm, st)
        res = {"repo": repo, "lang": R["lang"], "budget_h": R['budget_h'],
               "worker_h": round(R["worker_s"] / 3600, 2),
               "fuzz_h": round(sum(t["fuzz_s"] for t in R["tools"]) / 3600, 2),
               "stop_reason": R["stop_reason"], "n_tools": len(R["tools"]),
               "unreachable_tools": R["unreachable_tools"],
               "tools": [{k: t.get(k) for k in ("tool", "config", "status", "slices", "best_cov",
                                                "prior_cov_final", "prior_t_end", "n_inputs",
                                                "seed_sources", "last_error")}
                         | {"fuzz_h": round(t["fuzz_s"] / 3600, 2),
                            "t_last_edge_h": round(t["t_last_edge"] / 3600, 2),
                            "t_last_sig_h": round(t["t_last_sig"] / 3600, 2),
                            "signatures": t["sigs"]} for t in R["tools"]]}
        with open(os.path.join(RE.STATE, f"repo24_results.{arm}.jsonl"), "a") as f:
            f.write(json.dumps(res) + "\n")
    log(f"DONE {repo}: {R['stop_reason']} after {res['worker_h']}h of {R['budget_h']:.3g}h")
    return R


# ---------------------------------------------------------------- main
def status(arm):
    st = load_state(arm)
    for repo, R in st["repos"].items():
        c = collections.Counter(t["status"] for t in R["tools"])
        print(f"{R['status']:8} {R['worker_s']/3600:5.2f}/{R['budget_h']:.3g}h "
              f"{dict(c)}  {R.get('stop_reason') or ''}  {repo}")
    if not st["repos"]:
        print("no repos started yet")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--arm", default="repo24")
    ap.add_argument("--time", type=int, default=None,
                    help="slice length in seconds (default plateau + 600, so a tool that stops "
                         "gaining early can be declared saturated within one slice)")
    ap.add_argument("--workers", type=int, default=5, help="repos in parallel (one core each)")
    ap.add_argument("--budget-h", type=float, default=24.0, help="worker-hours per repo")
    ap.add_argument("--plateau-s", type=int, default=3600,
                    help="fuzz-seconds with no new edge and no new signature => saturated")
    ap.add_argument("--source-arm", default="gpt41-corpus")
    ap.add_argument("--repos-file", default="eval/repo24_repos.txt")
    ap.add_argument("--select", type=int, default=None, help="write the top-N repo list and exit")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--limit", type=int, default=None, help="only the first N repos (smoke)")
    a = ap.parse_args()

    RE._apply_arm(a.arm)
    if not a.time:
        a.time = a.plateau_s + 600
    repos_file = os.path.join(ROOT, a.repos_file)
    if a.select:
        select(a.select, a.source_arm, repos_file); return
    if a.status:
        status(a.arm); return
    if not os.path.exists(repos_file):
        log(f"no {a.repos_file} -- run with --select N first"); sys.exit(1)
    repos = [l.strip() for l in open(repos_file) if l.strip() and not l.startswith("#")]
    if a.limit:
        repos = repos[:a.limit]
    os.environ["TOFU_KEEP_CORPUS"] = "1"          # resume each tool across slices
    os.environ.setdefault("TOFU_FINDINGS_TIMELINE", "1")

    inv = repo_inventory(a.source_arm)
    missing = [r for r in repos if r not in inv or not inv[r]["reachable"]]
    for r in missing:
        log(f"skip {r}: no reachable tools in {a.source_arm}")
    repos = [r for r in repos if r not in missing]

    st = load_state(a.arm)
    prov = RE.provenance(a.time, a.workers)
    prov.update(protocol="repo24", budget_h=a.budget_h, slice_s=a.time, plateau_s=a.plateau_s)
    todo = [r for r in repos if st["repos"].get(r, {}).get("status") != "done"]
    log(f"repo24: {len(repos)} repos ({len(repos) - len(todo)} done), budget {a.budget_h}h/repo, "
        f"slice {a.time}s, plateau {a.plateau_s}s, {a.workers} in parallel")
    log(f"worst case wall: {-(-len(todo) // max(a.workers, 1)) * a.budget_h:.3g} h")

    signal.signal(signal.SIGINT, RE._abort)
    signal.signal(signal.SIGTERM, RE._abort)
    signal.signal(signal.SIGHUP, RE._abort)    # tmux/ssh closed: reap, don't orphan
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        list(ex.map(lambda r: run_repo(a.arm, r, inv[r], st, a.budget_h * 3600,
                                       a.time, a.plateau_s, prov), todo))
    status(a.arm)


if __name__ == "__main__":
    main()
