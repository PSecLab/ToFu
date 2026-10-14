# Comparison vs other baselines -- vanilla-claude-sonnet-5 (2026-09-21)

Repo-level: does the system report ANYTHING for this repo at all (no severity/confidence weighting). Tool-level: only computable against Cisco YARA (`flagged_tools`) and the ToFu gpt41-corpus arm (`finding_hits`) -- CodeQL's index has no per-tool attribution.

## Repo-level overlap

- **CodeQL**: this audit flags 201 repos; CodeQL flags 154 repos (482 repos scanned). Overlap: 94. Only this audit: 107. Only CodeQL: 60.
- **Cisco YARA**: this audit flags 201 repos; Cisco YARA flags 51 repos (484 repos scanned). Overlap: 36. Only this audit: 165. Only Cisco YARA: 15.
- **ToFu gpt41-corpus arm**: this audit flags 201 repos; ToFu gpt41-corpus arm flags 219 repos (481 repos in that arm's corpus subset). Overlap: 108. Only this audit: 93. Only ToFu gpt41-corpus arm: 111.

## Tool-level overlap

- **Cisco YARA flagged_tools**: this audit flags 748 (repo,tool) pairs; Cisco flags 113. Overlap: 20.
- **ToFu gpt41-corpus arm finding_hits**: this audit flags 748 pairs; that arm has 1152 oracle-hit pairs (UNCONFIRMED candidates, not verified findings). Overlap: 178.

**Caveat**: none of these indexes share a common notion of severity or verification state with this audit's Tier-A/grounded rows -- overlap counts are a recall/coverage signal, not agreement on correctness. CodeQL/Cisco alerts are raw tool output, not human- or Phase-2-verified. The ToFu gpt41-corpus numbers are oracle *candidates* (finding_hits), same caveat as findings/potential/.
