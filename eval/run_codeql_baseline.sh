#!/usr/bin/env bash
# Standalone CodeQL security baseline over the prepared targets.
#
# STATIC ONLY: codeql reads source (--build-mode=none) and NEVER executes the
# tools -> no Docker needed. This is DISTINCT from Viper Phase I, which runs
# Viper's 3 custom taint queries; here we run CodeQL's off-the-shelf
# security-extended suite = "what does stock CodeQL find on these servers".
#
#   ./eval/run_codeql_baseline.sh            # all prepared targets, resumable
#   ./eval/run_codeql_baseline.sh summary    # print the results table
#
# Resumable: eval/state/codeql_runs.jsonl; re-running skips done repos.
# Resource-capped (CODEQL_THREADS/CODEQL_RAM) so it co-exists with a running
# ToFu container. Ctrl-C safe.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 1
CODEQL="${CODEQL:-codeql}"
PREPARED="eval/state/prepared.jsonl"
TGT="eval/targets"
OUT="eval/codeql_baseline"
INDEX="eval/state/codeql_runs.jsonl"
THREADS="${CODEQL_THREADS:-2}"
RAM="${CODEQL_RAM:-4096}"
PY="${PY:-.venv/bin/python}"
mkdir -p "$OUT" "$(dirname "$INDEX")"

suite_for(){ case "$1" in
  node) echo "codeql/javascript-queries:codeql-suites/javascript-security-extended.qls";;
  python) echo "codeql/python-queries:codeql-suites/python-security-extended.qls";;
esac; }
lang_for(){ case "$1" in node) echo javascript;; python) echo python;; esac; }

if [ "${1:-}" = "summary" ]; then
  exec "$PY" - "$INDEX" <<'PYEOF'
import json,sys,collections
rows=[json.loads(l) for l in open(sys.argv[1])] if __import__('os').path.exists(sys.argv[1]) else []
ok=[r for r in rows if r.get("ok")]
print(f"CodeQL security-extended baseline: {len(ok)} ok / {len(rows)} attempted")
print(f"  total findings: {sum(r.get('n_findings',0) for r in ok)}")
byrule=collections.Counter()
for r in ok:
    for k,v in (r.get('by_rule') or {}).items(): byrule[k]+=v
for k,v in byrule.most_common(15): print(f"    {v:4d}  {k}")
flagged=[r['repo'] for r in ok if r.get('n_findings')]
print(f"  repos with >=1 finding: {len(flagged)}")
for r in sorted(ok,key=lambda x:-x.get('n_findings',0))[:12]:
    print(f"    {r.get('n_findings',0):4d}  {r['repo']}")
PYEOF
fi

command -v "$CODEQL" >/dev/null || { echo "codeql not on PATH"; exit 1; }
echo "== ensuring standard query packs (one-time download) =="
"$CODEQL" pack download codeql/javascript-queries codeql/python-queries >/dev/null 2>&1 || {
  echo "pack download failed (network?)"; exit 1; }

done_repos(){ [ -f "$INDEX" ] && "$PY" -c "import json,sys;[print(json.loads(l)['repo']) for l in open('$INDEX')]" 2>/dev/null || true; }
DONE="$(done_repos)"

while IFS= read -r line; do
  status=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1]).get('status',''))" "$line")
  [ "$status" = "ready" ] || continue
  repo=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['repo'])" "$line")
  lang=$("$PY" -c "import json,sys;print(json.loads(sys.argv[1])['lang'])" "$line")
  slug=$(echo "$repo" | sed 's#/#__#g')
  echo "$DONE" | grep -qxF "$repo" && { echo "skip (done) $repo"; continue; }
  src="$TGT/$slug"
  [ -d "$src" ] || { echo "SKIP $repo (no source at $src)"; continue; }
  db="$OUT/$slug/db"; sarif="$OUT/$slug/results.sarif"
  mkdir -p "$OUT/$slug"
  echo ">> $repo [$lang]"
  t0=$(date +%s)
  if ! "$CODEQL" database create "$db" --language="$(lang_for "$lang")" \
        --source-root="$src" --build-mode=none --overwrite \
        --threads="$THREADS" --ram="$RAM" >"$OUT/$slug/create.log" 2>&1; then
    echo "   ERR db create (see $OUT/$slug/create.log)"
    "$PY" -c "import json;open('$INDEX','a').write(json.dumps({'repo':'$repo','lang':'$lang','ok':False,'stage':'create'})+chr(10))"
    continue
  fi
  if ! "$CODEQL" database analyze "$db" "$(suite_for "$lang")" \
        --format=sarif-latest --output="$sarif" \
        --threads="$THREADS" --ram="$RAM" >"$OUT/$slug/analyze.log" 2>&1; then
    echo "   ERR analyze (see $OUT/$slug/analyze.log)"
    "$PY" -c "import json;open('$INDEX','a').write(json.dumps({'repo':'$repo','lang':'$lang','ok':False,'stage':'analyze'})+chr(10))"
    continue
  fi
  secs=$(( $(date +%s) - t0 ))
  "$PY" - "$repo" "$lang" "$sarif" "$secs" "$INDEX" <<'PYEOF'
import json,sys,collections
repo,lang,sarif,secs,index=sys.argv[1:6]
d=json.load(open(sarif)); res=[r for run in d.get('runs',[]) for r in run.get('results',[])]
by=collections.Counter(r.get('ruleId') for r in res)
open(index,'a').write(json.dumps({'repo':repo,'lang':lang,'ok':True,'seconds':int(secs),
    'n_findings':len(res),'by_rule':dict(by),'sarif':sarif})+"\n")
print(f"   {len(res)} findings in {secs}s")
PYEOF
  # DBs are large; drop after analyze to save disk (SARIF kept)
  rm -rf "$db"
done < "$PREPARED"
echo "== done. summary: ./eval/run_codeql_baseline.sh summary =="
