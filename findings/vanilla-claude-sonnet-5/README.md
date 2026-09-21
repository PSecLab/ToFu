# vanilla-claude-sonnet-5 -- LLM-only static audit baseline

**484 repos, 6231 configs (repo x tool pairs). 474 Tier-A findings, 274 Tier-B findings, both grounded by a mechanical verification gate (Phase 2). 16.0% of all `flag` rows emitted by review failed that gate and are excluded from these counts (see rejected.jsonl).**

Static source reading only -- no target was executed, installed, started, or contacted. This is the null-model baseline for ToFu's runtime findings: what a frontier LLM concludes from reading code alone, with no fuzzing.

## Headline

| | count |
|---|---|
| repos | 484 |
| configs (repo x tool) | 6231 |
| clear | 5340 |
| flag rows emitted | 891 |
| flag rows grounded (Phase 2 accepted) | 748 |
| flag rows rejected (ungrounded) | 143 |
| grounding-failure rate | 16.0% |
| **Tier A (headline findings)** | **474** |
| Tier B (potential) | 274 |
| CWE-taxonomy extensions (off-list, justified) | 8 |

## Tallies by CWE (grounded, Tier A + Tier B)

| CWE | title | Tier A | Tier B | total |
|---|---|---|---|---|
| CWE-22 | Path Traversal | 95 | 122 | 217 |
| CWE-918 | Server-Side Request Forgery (SSRF) | 130 | 20 | 150 |
| CWE-73 | External Control of File Name or Path | 55 | 26 | 81 |
| CWE-89 | SQL Injection | 60 | 13 | 73 |
| CWE-78 | OS Command Injection | 55 | 5 | 60 |
| CWE-88 | Argument Injection | 20 | 21 | 41 |
| CWE-94 | Code Injection | 27 | 12 | 39 |
| CWE-200 | Information Exposure | 6 | 10 | 16 |
| CWE-377 | Insecure Temporary File | 6 | 9 | 15 |
| CWE-400 | Uncontrolled Resource Consumption | 3 | 8 | 11 |
| CWE-862 | Missing Authorization | 2 | 7 | 9 |
| CWE-1333 | Inefficient Regular Expression Complexity (ReDoS) | 4 | 3 | 7 |
| CWE-532 | Insertion of Sensitive Information into Log File | 2 | 3 | 5 |
| CWE-598 | (extension) | 0 | 5 | 5 |
| CWE-798 | Use of Hard-coded Credentials | 0 | 3 | 3 |
| CWE-502 | Deserialization of Untrusted Data | 2 | 1 | 3 |
| CWE-95 | Eval Injection | 1 | 2 | 3 |
| CWE-306 | Missing Authentication for Critical Function | 0 | 2 | 2 |
| CWE-23 | Relative Path Traversal | 2 | 0 | 2 |
| CWE-829 | Inclusion of Functionality from Untrusted Control Sphere | 1 | 1 | 2 |
| CWE-915 | (extension) | 1 | 0 | 1 |
| CWE-552 | Files or Directories Accessible to External Parties | 0 | 1 | 1 |
| CWE-352 | (extension) | 1 | 0 | 1 |
| CWE-295 | (extension) | 1 | 0 | 1 |

## By language

| lang | Tier A | Tier B |
|---|---|---|
| node | 345 | 163 |
| python | 129 | 111 |

## Method (10 lines)

1. Built a deterministic shard manifest from prepared.jsonl + eval/configs/, asserted union == exact config set, disjoint (`_scripts/build_shards.py`).
2. One reviewer pass per shard, same rubric (Tier A/B, explicit anti-FP rules, fixed CWE taxonomy), read-only, no memory of prior findings -- every tool judged fresh from its own code.
3. Reviewer emits one JSONL row per config: `flag` (tier, CWE, file:line, verbatim excerpt, param->sink, guard, why) or `clear` (reason enum + one-line why).
4. Phase 2 (`_scripts/verify_findings.py`) mechanically re-grounds every `flag` row against the source tree -- file exists, excerpt is a real substring within +/-10 lines of the cited line, tool/config match, CWE/tier well-formed. Failures excluded, not counted.
5. Phase 4 (`_scripts/aggregate.py`, this run) merges, tallies, and writes every deliverable below.

## Deliverables

- `inventory.jsonl` -- all 6231 rows, `_grounded` flag on each flag row
- `flagged.md` -- Tier A grouped by CWE
- `potential.md` -- Tier B grouped by CWE
- `by-cwe/CWE-NN_<slug>.md` + `by-cwe/INDEX.md`
- `controls.md` -- 8-row control table, scored
- `comparison.md` -- overlap vs CodeQL/Cisco/ToFu gpt41-corpus
- `rejected.jsonl` -- Phase 2 failures + reason
- `METHODOLOGY.md` -- reviewer prompt verbatim, manifest hash

## Limitations

- Static reading only; no execution, so no Tier-A row is a *demonstrated* bug in this project's sense -- each is a source-verified candidate.
- Not every config has a persisted tool description; where absent, the contract is read from the code and the row notes it.
- A handful of repos generate tools dynamically (OpenAPI/JSON-schema/YAML); their verdict covers the generated family, reviewed via the generator + data file, not an individual per-tool handler.
- Some repos launch from `dist`/`build`; the audit reads `src`, not the shipped artifact -- a build-time divergence would not be caught.
- Reviewer passes ran on the same model as this aggregation but each had its own context; verdicts are not identical-prompt reproducible the way a static analyser is. The verification gate, not reproducibility, is what makes these numbers usable.
- **One row is a disclosed exception to the read-only mandate**: shard_016.jsonl's `aaronsb/google-workspace-mcp` `manage_scratchpad` finding (CWE-915, prototype pollution) empirically verified its mechanism by running logic extracted from the target's own source in an isolated script -- not against the target repo itself, but still execution of target-derived code, which breaches this arm's static-only mandate. The static reasoning in that row stands independently of the dynamic check (see its `process_note` field and ToFu_src/nazmul.todo's 2026-09-21 PROCESS FLAG entry); it is kept in the Tier-A count, disclosed rather than silently excluded.
- 16.0% of all flag rows emitted by review failed the Phase 2 grounding gate. The dominant failure modes were excerpt-transcription formatting (multi-line source condensed to one line, or elided with "...", in a way the mechanical checker -- deliberately strict -- could not always match) rather than fabricated claims; see rejected.jsonl for the row-level detail and ToFu_src/nazmul.todo for two manually-confirmed, fixed examples from this session's own shards.
