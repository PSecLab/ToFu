#!/usr/bin/env python3
"""True tool/sink distribution over the extracted corpus, then draw Set A (50)
and identify Set B candidates (rare-sink coverage)."""
import json, collections, random, statistics, sys, hashlib

R = [json.loads(l) for l in open('/tmp/extraction/results.jsonl')]
# keep only repos where we actually found MCP tool registrations
tooled = [r for r in R if r['n_tools'] > 0]
NL = len(R)

print("="*78); print(f"EXTRACTED {NL} repos ({len(tooled)} with >=1 detected tool registration)"); print("="*78)

# ---- A. tools per repo ----
tc = [r['n_tools'] for r in tooled]
print(f"\n[A] TOOLS PER REPO (n={len(tooled)})")
print(f"    total tools discovered : {sum(tc)}")
print(f"    median {statistics.median(tc):.0f} | mean {statistics.mean(tc):.1f} | max {max(tc)}")
for lo,hi,lab in [(1,2,'1-2'),(3,5,'3-5'),(6,10,'6-10'),(11,20,'11-20'),(21,10**6,'21+')]:
    n=sum(1 for t in tc if lo<=t<=hi); print(f"    {lab:>6} tools: {n:4}  {'#'*int(50*n/len(tooled))}")

# ---- B. by language ----
print(f"\n[B] BY LANGUAGE")
for lang in ('python','node'):
    s=[r for r in tooled if r['lang']==lang]
    if s: print(f"    {lang:7} repos={len(s):4}  tools={sum(x['n_tools'] for x in s):5}  median_tools={statistics.median([x['n_tools'] for x in s]):.0f}")

# ---- C. TRUE sink-family distribution (measured, not keyword-guessed) ----
print(f"\n[C] SINK FAMILIES ACTUALLY PRESENT IN SOURCE (n={len(tooled)} tooled repos)")
fam = collections.Counter(); fam_lang = collections.defaultdict(collections.Counter)
for r in tooled:
    for k in r['sinks']:
        fam[k]+=1; fam_lang[k][r['lang']]+=1
print(f"    {'family':26} {'repos':>6} {'%':>6} {'py':>5} {'node':>5}")
for k,n in fam.most_common():
    print(f"    {k:26} {n:6} {100*n/len(tooled):5.1f}% {fam_lang[k]['python']:5} {fam_lang[k]['node']:5}")
missing = [k for k in ['FileAccess','FileWrite','CommandExecution','SQLExecution','CodeExecution',
    'NetworkExecution','TempFileLeak','LogInjection','SensitiveDataLogging','SSLCertValidation',
    'UnrestrictedIPBinding','ReDoS','BlockingEventLoopCall','WeakHash','WeakPRNG','NonceReuse',
    'UnverifiedCodeDownload','XXE','DataAmplification','LoopCondition','Deserialization'] if k not in fam]
print(f"    families with ZERO repos: {missing or 'none'}")

# ---- D. sink diversity per repo ----
div = collections.Counter(len(r['sinks']) for r in tooled)
print(f"\n[D] DISTINCT SINK FAMILIES PER REPO")
for k in sorted(div): print(f"    {k:2} families: {div[k]:4}  {'#'*int(45*div[k]/len(tooled))}")

# ---- E. SET A: seeded stratified draw of 50 ----
SEED=20260909; N=50
random.seed(SEED)
def tier(r):
    t=r['n_tools']
    return 'low' if t<=2 else ('mid' if t<=8 else 'high')
strata=collections.defaultdict(list)
for r in tooled: strata[(r['lang'],tier(r))].append(r)
for k in strata: strata[k].sort(key=lambda r:r['repo'])
total=len(tooled)
alloc={k:max(1,round(N*len(v)/total)) for k,v in strata.items()}
while sum(alloc.values())>N: alloc[max(alloc,key=lambda k:alloc[k])]-=1
while sum(alloc.values())<N: alloc[max(alloc,key=lambda k:len(strata[k])-alloc[k])]+=1
setA=[]
for k,n in sorted(alloc.items()):
    setA.extend(random.sample(strata[k], min(n,len(strata[k]))))
setA.sort(key=lambda r:r['repo'])
print(f"\n[E] SET A -- seeded stratified draw, seed={SEED}, n={len(setA)}")
print(f"    strata (lang, tool-tier) -> allocated / available")
for k in sorted(alloc): print(f"      {str(k):22} {alloc[k]:3} / {len(strata[k]):4}")
covA=collections.Counter()
for r in setA:
    for k in r['sinks']: covA[k]+=1
print(f"    Set A sink coverage: {len(covA)}/{len(fam)} families present in corpus")
gaps=[k for k in fam if k not in covA]
print(f"    families MISSED by Set A: {gaps or 'none'}")

# ---- F. SET B candidates: best carriers of the rarest families ----
print(f"\n[F] SET B CANDIDATES -- rarest families and their best carrier repos")
rare=[k for k,n in fam.most_common()[::-1]][:8]
for k in rare:
    cands=sorted([r for r in tooled if k in r['sinks']],
                 key=lambda r:(-len(r['sinks']), -r['stars']))[:3]
    print(f"    {k:26} ({fam[k]} repos) -> " + ", ".join(f"{c['repo']}({c['stars']}*)" for c in cands))

fp=hashlib.sha256(",".join(sorted(r['repo'] for r in setA)).encode()).hexdigest()[:12]
json.dump({'seed':SEED,'fingerprint':fp,'set_a':[{k:r[k] for k in
    ('repo','lang','stars','commit','n_tools','tools','sinks','category','last_commit')} for r in setA]},
    open('/tmp/extraction/set_a.json','w'), indent=1)
print(f"\n    Set A written to set_a.json | fingerprint {fp}")
