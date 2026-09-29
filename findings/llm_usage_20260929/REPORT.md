# LLM usage per analyzer (2026-09-29) -- no new LLM calls were made

Token counts use GPT-4.1's tokenizer (o200k_base; gpt-4.1-mini uses the same).

| analyzer | unit | calls / unit | input tok / unit | output tok / unit | total calls | total input | total output | measured on |
|---|---|---|---|---|---|---|---|---|
| ToFu | tool | 2.14 | 4,712 | 452 | 3,853 | 8,482,297 | 814,487 | 1,800 tools / 265 servers |
| ToolFuzz | tool | 14.3 | 12,317 | 1,259 | 21,614 | 18,672,696 | 1,908,983 | 1,516 tools / 258 servers |
| VIPER | server | 168.7 | 205,689 | 19,171 | 39,982 | 48,748,092 | 4,543,459 | 237 servers |
| Cisco (LLM + behavioral) | server | 18.5 | 135,143 | 2,498 | 4,915 | 35,948,051 | 664,431 | 266 servers |

Sources
- **ToFu**: reconstructed. ToFu's replay cache (PC eval/state/llm_cache_ablation, 1,800 entries) holds the LLM
  outputs; the requests are rebuilt exactly from src/llm.py's two prompt templates, the 73-sanitizer list,
  the seed bank, the cached selection, and each tool's name/description/schema taken from the tool
  definitions Viper's agent sent to the API (1,611 tools; 189 fall back to Cisco's description + the
  argument names in the cached seeds). Calls = 2 per tool + one per file-builder round seen in the seeds
  (253). JSON-parse retries are not recorded in the cache and are not included. `count_tofu_tokens.py`.
- **ToolFuzz**: API usage recorded per tool in findings/toolfuzz_h2h273_20260928/runs.toolfuzz_h2h273.jsonl.
- **VIPER / Cisco**: VM proxy ledgers (eval/state/{viper,cisco}_llm_cache/_ledger.jsonl) over the campaign
  windows, replayed calls counted with their recorded usage (eval/tofu_llm_usage_summary.py). VIPER's 29
  servers reused from 09-13/09-20 runs have no ledger.
- **Sonnet-5 audit**: an agent session reading whole repositories; not metered, not comparable.
