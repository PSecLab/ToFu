#!/usr/bin/env python3
"""Set B: purposive, covers families Set A misses or barely touches.
Avoids mega-monorepos (unfuzzable, and they trivially match everything) and
never picks the same repo twice."""
import json, collections, random

R=[json.loads(l) for l in open('/tmp/extraction/results.jsonl')]
tooled=[r for r in R if r['n_tools']>0]
setA=json.load(open('/tmp/extraction/set_a.json'))
inA={r['repo'] for r in setA['set_a']}

# coverage already achieved by Set A
covA=collections.Counter()
for r in setA['set_a']:
    for k in r['sinks']: covA[k]+=1

ALL=['FileAccess','FileWrite','CommandExecution','SQLExecution','CodeExecution','NetworkExecution',
 'TempFileLeak','LogInjection','SensitiveDataLogging','SSLCertValidation','UnrestrictedIPBinding',
 'ReDoS','BlockingEventLoopCall','WeakHash','WeakPRNG','NonceReuse','UnverifiedCodeDownload',
 'XXE','DataAmplification','LoopCondition','Deserialization']

# thin = missing from Set A, or represented by <=3 Set A repos
thin=[k for k in ALL if covA.get(k,0)<=3]
print("families Set A leaves thin (<=3 repos):")
for k in thin: print(f"   {k:26} setA={covA.get(k,0)}")

# fuzzable candidates: real but not enormous
def ok(r): return 3 <= r['n_tools'] <= 40 and r['n_loc'] <= 60000 and r['repo'] not in inA
pool=[r for r in tooled if ok(r)]
print(f"\ncandidate pool (3-40 tools, <=60k LOC, not in Set A): {len(pool)}")

random.seed(20260909)
chosen=[]; picked=set(); cov=collections.Counter(covA)
# greedy set-cover over the thin families, 2 repos per family target
for target in thin:
    for _ in range(2):
        cands=[r for r in pool if target in r['sinks'] and r['repo'] not in picked]
        if not cands: break
        # prefer repos that also close OTHER thin gaps, then smaller/simpler
        cands.sort(key=lambda r:(-sum(1 for k in r['sinks'] if cov[k]<=3), r['n_loc'], r['repo']))
        pick=cands[0]; chosen.append(pick); picked.add(pick['repo'])
        for k in pick['sinks']: cov[k]+=1
        if cov[target]>3: break

print(f"\nSET B: {len(chosen)} repos")
for r in sorted(chosen, key=lambda r:r['repo']):
    hits=[k for k in r['sinks'] if k in thin]
    print(f"   {r['repo']:48} {r['lang']:6} {r['stars']:>5}* tools={r['n_tools']:>3} covers={','.join(sorted(hits)[:4])}")

print("\nCOMBINED COVERAGE (Set A + Set B), repos per family:")
for k in ALL:
    a=covA.get(k,0); tot=cov[k]
    flag='' if tot>=3 else '   <-- STILL THIN'
    print(f"   {k:26} A={a:>3}  A+B={tot:>3}{flag}")

json.dump({'seed':20260909,'set_b':[{k:r[k] for k in
   ('repo','lang','stars','commit','n_tools','tools','sinks','category','n_loc')} for r in chosen]},
   open('/tmp/extraction/set_b.json','w'), indent=1)
print(f"\nwritten set_b.json")
