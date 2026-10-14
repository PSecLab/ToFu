#!/usr/bin/env python3
"""Stock-CodeQL security-extended baseline over an ENTIRE sampling set.

STATIC ONLY: codeql reads source (--build-mode=none), never executes a tool ->
no install, no Docker. Source is taken from eval/targets/<slug> when already
prepared, else shallow-cloned at the pinned commit to a scratch dir and deleted
after analysis (peak disk = one clone + one DB).

Distinct from Viper Phase I (Viper's 3 custom taint queries); this is
off-the-shelf CodeQL security-extended = "what stock SAST finds".

  python3 eval/run_codeql_set.py e                 # Set E (300), resumable
  python3 eval/run_codeql_set.py a --limit 5       # smoke
  python3 eval/run_codeql_set.py e --summary       # print the table

Resumable: eval/state/codeql_runs_<set>.jsonl (append-only, keyed by repo).
Resource-capped: CODEQL_THREADS (2), CODEQL_RAM (4096). Ctrl-C safe.
"""
import argparse, collections, json, os, shutil, subprocess, sys, tempfile, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODEQL = os.environ.get("CODEQL", "codeql")
THREADS = os.environ.get("CODEQL_THREADS", "2")
RAM = os.environ.get("CODEQL_RAM", "4096")
CLONE_TIMEOUT = int(os.environ.get("CODEQL_CLONE_TIMEOUT", "300"))
DB_TIMEOUT = int(os.environ.get("CODEQL_DB_TIMEOUT", "900"))

SUITE = {
    "node": "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls",
    "python": "codeql/python-queries:codeql-suites/python-security-extended.qls",
}
LANGQL = {"node": "javascript", "python": "python"}


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def parse_sarif(path):
    d = json.load(open(path))
    res = [r for run in d.get("runs", []) for r in run.get("results", [])]
    return len(res), dict(collections.Counter(r.get("ruleId") for r in res))


def summarize(index):
    rows = [json.loads(l) for l in open(index)] if os.path.exists(index) else []
    ok = [r for r in rows if r.get("ok")]
    print(f"CodeQL security-extended: {len(ok)} ok / {len(rows)} attempted")
    print(f"  total findings: {sum(r.get('n_findings', 0) for r in ok)}")
    byrule = collections.Counter()
    for r in ok:
        for k, v in (r.get("by_rule") or {}).items():
            byrule[k] += v
    for k, v in byrule.most_common(20):
        print(f"    {v:5d}  {k}")
    flagged = sorted((r for r in ok if r.get("n_findings")), key=lambda x: -x["n_findings"])
    print(f"  repos with >=1 finding: {len(flagged)}")
    for r in flagged[:20]:
        print(f"    {r['n_findings']:5d}  {r['repo']}")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("set", help="sampling set letter: a b d e (reads Benchmarks/extraction/set_<set>.json)")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--summary", action="store_true")
    a = ap.parse_args()

    setfile = os.path.join(ROOT, "Benchmarks", "extraction", f"set_{a.set}.json")
    if not os.path.exists(setfile):
        sys.exit(f"no {setfile}")
    index = os.path.join(ROOT, "eval", "state", f"codeql_runs_{a.set}.jsonl")
    out = os.path.join(ROOT, "eval", f"codeql_baseline_{a.set}")
    os.makedirs(out, exist_ok=True)
    os.makedirs(os.path.dirname(index), exist_ok=True)

    if a.summary:
        summarize(index); return

    if not shutil.which(CODEQL):
        sys.exit("codeql not on PATH")
    subprocess.run([CODEQL, "pack", "download", "codeql/javascript-queries", "codeql/python-queries"],
                   capture_output=True)

    rows = json.load(open(setfile))[f"set_{a.set}"]
    done = set()
    if os.path.exists(index):
        for l in open(index):
            try: done.add(json.loads(l)["repo"])
            except Exception: pass
    todo = [r for r in rows if r["repo"] not in done]
    if a.limit:
        todo = todo[:a.limit]
    log(f"set {a.set}: {len(rows)} repos, {len(done)} done, {len(todo)} todo")

    scratch = tempfile.mkdtemp(prefix="codeql_src_")
    ok = fail = 0
    try:
        for i, r in enumerate(todo, 1):
            repo, commit, lang = r["repo"], r.get("commit"), r.get("lang")
            slug = repo.replace("/", "__")
            if lang not in SUITE:
                fail += 1; continue
            # source: prepared target if present, else shallow clone
            src = os.path.join(ROOT, "eval", "targets", slug)
            clone = None
            head_sha = None          # actual analyzed commit, for traceability
            if not os.path.isdir(src):
                clone = os.path.join(scratch, slug)
                env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GIT_ASKPASS="echo")
                url = f"https://github.com/{repo}.git"
                try:
                    # blobless shallow clone: fast even on huge monorepos
                    # (pollinations etc.). History blobs skipped; HEAD tree
                    # blobs fetched on the implicit checkout.
                    p = subprocess.run(["git", "clone", "--quiet", "--no-tags",
                                        "--single-branch", "--depth", "1",
                                        "--filter=blob:none", url, clone],
                                       capture_output=True, timeout=CLONE_TIMEOUT, env=env)
                    if p.returncode != 0:
                        raise RuntimeError("clone: " + p.stderr.decode(errors="ignore")[-200:])
                    if commit:
                        # pin the exact sha (GitHub allows sha fetch); if the
                        # server refuses, fall back to cloned HEAD (recorded).
                        fp = subprocess.run(["git", "-C", clone, "fetch", "--quiet",
                                             "--depth", "1", "origin", commit],
                                            capture_output=True, timeout=CLONE_TIMEOUT, env=env)
                        if fp.returncode == 0:
                            subprocess.run(["git", "-C", clone, "checkout", "--quiet", commit],
                                           capture_output=True, timeout=60, env=env)
                    h = subprocess.run(["git", "-C", clone, "rev-parse", "HEAD"],
                                       capture_output=True, timeout=30, env=env)
                    if h.returncode == 0:
                        head_sha = h.stdout.decode(errors="ignore").strip()
                except subprocess.TimeoutExpired:
                    log(f"({i}/{len(todo)}) {repo}  CLONE TIMEOUT ({CLONE_TIMEOUT}s)")
                    with open(index, "a") as f:
                        f.write(json.dumps({"repo": repo, "lang": lang, "ok": False,
                                            "stage": "clone", "error": "timeout"}) + "\n")
                    fail += 1; shutil.rmtree(clone, ignore_errors=True); continue
                except Exception as e:
                    log(f"({i}/{len(todo)}) {repo}  CLONE FAIL {str(e)[:80]}")
                    with open(index, "a") as f:
                        f.write(json.dumps({"repo": repo, "lang": lang, "ok": False,
                                            "stage": "clone", "error": str(e)[:200]}) + "\n")
                    fail += 1; shutil.rmtree(clone, ignore_errors=True); continue
                src = clone
            db = os.path.join(out, slug, "db")
            sarif = os.path.join(out, slug, "results.sarif")
            os.makedirs(os.path.dirname(db), exist_ok=True)
            t0 = time.time()
            try:
                c = subprocess.run([CODEQL, "database", "create", db, f"--language={LANGQL[lang]}",
                                    f"--source-root={src}", "--build-mode=none", "--overwrite",
                                    f"--threads={THREADS}", f"--ram={RAM}"],
                                   capture_output=True, timeout=DB_TIMEOUT)
                if c.returncode != 0:
                    raise RuntimeError("db create: " + c.stderr.decode(errors="ignore")[-200:])
                z = subprocess.run([CODEQL, "database", "analyze", db, SUITE[lang],
                                    "--format=sarif-latest", f"--output={sarif}",
                                    f"--threads={THREADS}", f"--ram={RAM}"],
                                   capture_output=True, timeout=DB_TIMEOUT)
                if z.returncode != 0:
                    raise RuntimeError("analyze: " + z.stderr.decode(errors="ignore")[-200:])
                n, by = parse_sarif(sarif)
                with open(index, "a") as f:
                    f.write(json.dumps({"repo": repo, "lang": lang, "ok": True, "seconds": int(time.time() - t0),
                                        "n_findings": n, "by_rule": by, "stars": r.get("stars"),
                                        "commit": commit, "analyzed_sha": head_sha,
                                        "source": "prepared" if clone is None else "clone"}) + "\n")
                ok += 1
                log(f"({i}/{len(todo)}) {repo}  {n} findings  {int(time.time()-t0)}s")
            except Exception as e:
                with open(index, "a") as f:
                    f.write(json.dumps({"repo": repo, "lang": lang, "ok": False, "error": str(e)[:200]}) + "\n")
                fail += 1
                log(f"({i}/{len(todo)}) {repo}  ERR {str(e)[:80]}")
            finally:
                shutil.rmtree(db, ignore_errors=True)          # DBs are large
                if clone: shutil.rmtree(clone, ignore_errors=True)
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    log(f"DONE set {a.set}: ok={ok} fail={fail}. summary: python3 eval/run_codeql_set.py {a.set} --summary")


if __name__ == "__main__":
    main()
