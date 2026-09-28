#!/usr/bin/env python3
"""Seed a tagged Viper campaign with earlier valid runs instead of re-running (and re-paying
for) them. For each listed repo, take its LAST row in the source index; if it is ok and its
own outputs show the runtime hook was injected (else Phase II ran blind and the run is not
evidence), copy its output dir + log into eval/viper_runs/<tag>/ and append a row to
eval/state/viper_runs.<tag>.jsonl with every count recomputed from the copied files, the
same way run_viper.py records a fresh run. The source outputs are never modified.
Idempotent: repos that already have an ok row in the tag index are left alone.

  python3 eval/viper_reuse_runs.py --tag c251 --repos-file Benchmarks/extraction/ablation_251_repos.txt \
      --lang node [--dry-run]
"""
import argparse, glob, json, os, re, shutil, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "eval", "state")


def read_jsonl(p):
    out = []
    if os.path.exists(p):
        for l in open(p):
            try: out.append(json.loads(l))
            except Exception: pass
    return out


def recount(resdir, slug):
    """Same fields as run_viper.one(), from a run's output files."""
    c = {}
    rep = glob.glob(os.path.join(resdir, "codeql_output", "*", "report.json"))
    if rep:
        try: c["n_static"] = len(json.load(open(rep[0])).get("vulnerabilities", []))
        except Exception: pass
    conf, chains = 0, set()
    for fp in glob.glob(os.path.join(resdir, "fuzz_results", "**", "triggered_vulnerability_prompts.json"), recursive=True):
        try:
            for e in json.load(open(fp)):
                hj = (e or {}).get("hit_judge") or {}
                if hj.get("sink_reached") and hj.get("effect_success"):
                    conf += 1
                    if e.get("target_call_chain"): chains.add(e["target_call_chain"])
        except Exception: pass
    c.update(n_confirmed=conf, n_confirmed_distinct=len(chains), n_hit_markers=conf)
    op = os.path.join(resdir, "oracle.json")
    ev = [l for l in open(op, errors="ignore") if l.strip()] if os.path.exists(op) else []
    flog = os.path.join(resdir, "fuzzer.log")
    max_hits, hook_seen = 0, False
    if os.path.exists(flog):
        txt = open(flog, errors="ignore").read()
        hits = [int(x) for x in re.findall(r"oracle_hits=(\d+)", txt)]
        max_hits = max(hits) if hits else 0
        hook_seen = "hook_init" in txt
    c["n_oracle_events_on_disk"] = len(ev)
    c["n_sink_events"] = sum(1 for l in ev if '"hook_init"' not in l)
    c["max_oracle_hits_in_round"] = max_hits
    c["hook_injected"] = any('"hook_init"' in l for l in ev) or hook_seen or max_hits > 0
    return c


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", required=True)
    ap.add_argument("--repos-file", required=True)
    ap.add_argument("--from-index", default=os.path.join(STATE, "viper_runs.jsonl"))
    ap.add_argument("--from-out", default=os.path.join(ROOT, "eval", "viper_runs"))
    ap.add_argument("--lang", default=None, help="only reuse runs of this language")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()
    want = [l.strip() for l in open(a.repos_file) if l.strip() and not l.startswith("#")]
    tidx = os.path.join(STATE, f"viper_runs.{a.tag}.jsonl")
    tout = os.path.join(ROOT, "eval", "viper_runs", a.tag)
    have = {r["repo"] for r in read_jsonl(tidx) if r.get("ok")}
    last = {}
    for r in read_jsonl(a.from_index):
        if not r.get("test_agent"): last[r["repo"]] = r
    reused, skipped = [], []
    for repo in want:
        r = last.get(repo)
        if repo in have or not r: continue
        if a.lang and r.get("lang") != a.lang: continue
        slug = repo.replace("/", "__")
        src = os.path.join(a.from_out, slug)
        if not r.get("ok") or not os.path.isdir(src):
            skipped.append((repo, "not ok / no outputs")); continue
        c = recount(src, slug)
        if not c["hook_injected"]:
            skipped.append((repo, "hook never injected -> Phase II blind, re-run")); continue
        if a.dry_run:
            reused.append((repo, c)); continue
        os.makedirs(tout, exist_ok=True)
        dst = os.path.join(tout, slug)
        if os.path.isdir(dst): shutil.rmtree(dst)
        shutil.copytree(src, dst, symlinks=True)
        if r.get("log") and os.path.exists(os.path.join(ROOT, r["log"])):
            shutil.copy2(os.path.join(ROOT, r["log"]), os.path.join(tout, slug + ".log"))
        row = dict(r); row.update(recount(dst, slug))
        row.update(log=os.path.relpath(os.path.join(tout, slug + ".log"), ROOT),
                   reused_from=os.path.relpath(src, ROOT),
                   reused_at=time.strftime("%Y-%m-%d %H:%M:%S"),
                   reused_run_started=time.strftime("%Y-%m-%d", time.localtime(r.get("started") or 0)))
        with open(tidx, "a") as f: f.write(json.dumps(row) + "\n")
        reused.append((repo, c))
    print(f"{'would reuse' if a.dry_run else 'reused'} {len(reused)}; not reusable {len(skipped)} (will be re-run)")
    for repo, why in skipped: print(f"  skip {repo}: {why}")
    tot = lambda k: sum(1 for _, c in reused if (c.get(k) or 0) > 0)
    print(f"  reused: static>0 {tot('n_static')}  sink>0 {tot('n_sink_events')}  confirmed>0 {tot('n_confirmed_distinct')}")


if __name__ == "__main__":
    main()
