#!/usr/bin/env python3
"""Set E -- the EXPANSION set. Seeded, stratified uniformly over sink families.

WHY A NEW SET AND NOT A BIGGER SET A
Set A is final and fingerprinted (seed 20260909, aa6f0cffff64). Redrawing it
would invalidate every statement already made about it. Set E is drawn from the
SAME population with the SAME method, disjoint from A/B/D, and is reported
separately. If you later want one big ecosystem set, A+E is defensible because
both are seeded draws from the same frame; A alone remains citable on its own.

WHY IT EXISTS
Measured 2026-09-10: of 58 repos attempted (Set A 50 + Set B 8), 44 failed
preparation and only ~6 of the surviving 14 execute without external
infrastructure. That is a ~10% end-to-end yield, and it is a property of the
MCP ecosystem -- most servers are thin wrappers over a hosted or paid API --
not a defect in ToFu. To reach 30 usable repos at that yield we must attempt
several hundred.

STRATIFICATION
results.jsonl carries a real per-repo `sinks` map, produced by parsing each
repo's source for the sink APIs behind the 21 runtime tracers. Repos are drawn
ROUND-ROBIN across sink families so rare families (Deserialization, XXE, ReDoS,
BlockingEventLoop) are represented at all -- a uniform random draw hits none of
them with high probability, which is the tension recorded in nazmul.todo under
"THE CENTRAL TENSION".

IPBinding is EXCLUDED from stratification: the probe matched 84.7% of the
corpus ("server|port|host" matches nearly every MCP description) and is a known
measurement artifact, not a signal.

    python3 Benchmarks/extraction/select_set_e.py --n 300
    python3 Benchmarks/extraction/select_set_e.py --n 300 --seed 20260910
"""
import argparse, hashlib, json, os, random, collections

HERE = os.path.dirname(os.path.abspath(__file__))
BROKEN_PROBE = {"UnrestrictedIPBinding"}


def load(name, key):
    p = os.path.join(HERE, f"{name}.json")
    return {r["repo"] for r in json.load(open(p))[key]} if os.path.exists(p) else set()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=300, help="how many repos to draw")
    ap.add_argument("--seed", type=int, default=20260910)
    ap.add_argument("--out", default=os.path.join(HERE, "set_e.json"))
    a = ap.parse_args()

    rows = [json.loads(l) for l in open(os.path.join(HERE, "results.jsonl")) if l.strip()]
    already = load("set_a", "set_a") | load("set_b", "set_b") | load("set_d", "set_d")

    # ToFu ships exactly two runners; other languages are a stated exclusion.
    pool = [r for r in rows
            if r.get("ok") and r.get("commit") and r.get("n_tools", 0) > 0
            and r.get("lang") in ("python", "node") and r["repo"] not in already]
    print(f"pool: {len(pool)} repos (excluding {len(already)} already in Set A/B/D)")

    # bucket by sink family
    buckets = collections.defaultdict(list)
    for r in pool:
        fams = [f for f in (r.get("sinks") or {}) if f not in BROKEN_PROBE]
        for f in (fams or ["_no_sink_family"]):
            buckets[f].append(r)

    rng = random.Random(a.seed)
    for f in buckets:
        buckets[f].sort(key=lambda r: r["repo"])       # deterministic base order
        rng.shuffle(buckets[f])

    # round-robin, rarest family first so scarce families are not crowded out
    order = sorted(buckets, key=lambda f: len(buckets[f]))
    picked, seen = [], set()
    while len(picked) < a.n:
        progressed = False
        for f in order:
            if len(picked) >= a.n:
                break
            while buckets[f]:
                r = buckets[f].pop()
                if r["repo"] in seen:
                    continue
                seen.add(r["repo"]); picked.append(r); progressed = True
                break
        if not progressed:
            break

    fp = hashlib.sha256(
        ("|".join(sorted(r["repo"] for r in picked))).encode()).hexdigest()[:12]
    out = {
        "seed": a.seed,
        "fingerprint": fp,
        "_about": "Set E: expansion set, seeded round-robin over sink families, "
                  "disjoint from Set A/B/D. Report separately from Set A.",
        "_method": "results.jsonl sinks map; UnrestrictedIPBinding excluded as a "
                   "broken probe (matched 84.7% of the corpus).",
        "set_e": [{k: r.get(k) for k in
                   ("repo", "lang", "stars", "commit", "n_tools", "tools", "sinks")}
                  for r in picked],
    }
    json.dump(out, open(a.out, "w"), indent=1)

    print(f"drew {len(picked)} repos  seed={a.seed}  fingerprint={fp}")
    print(f"wrote {a.out}\n")
    fam = collections.Counter()
    for r in picked:
        for f in (r.get("sinks") or {}):
            if f not in BROKEN_PROBE:
                fam[f] += 1
    print("sink-family representation in Set E:")
    for f, n in fam.most_common():
        print(f"   {f:<32} {n}")
    print(f"\nlangs: {collections.Counter(r['lang'] for r in picked)}")


if __name__ == "__main__":
    main()
