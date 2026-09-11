# Why these 9 runs are quarantined

**Quarantined 2026-09-10, after the `src/input_parser.py` parse-order fix.**

These runs are NOT evidence about ToFu. They were produced by a build in which
`FuzzInputParser.parse()` called `_generate_fallback_inputs` before attempting
JSON parsing. That method populates every declared property unconditionally, so
it always returned a non-empty dict and the JSON branch below it was
unreachable for any tool with a schema -- which is every MCP tool.

The consequence: **no semantic seed ever reached a target intact.** Seed bytes
went to `atheris.FuzzedDataProvider` and came back through
`ConsumeUnicodeNoSurrogates` in a wide encoding. The `Faulty Input` values in
these logs are the UTF-16 reading of ToFu's own files -- e.g.
`'慬杮慵敧㨢∠慪慶Ⱒ'` is `language": "java", "useElement":`, the seed file's
own JSON text, and `'牣慥整灟晤㨢笠瀢牡浡瑥牥≳'` is `create_pdf": {"parameters"`,
ToFu's own LLM tool-call schema.

So the 1390 alerts recorded here were raised on garbage input, not on payloads.
They collapse to 5 distinct sanitizer-set signatures (one per appium tool), and
in most of those signatures 3 of the 4 sanitizers are the always-on Layer-1
`BASE_MANDATORY_SANITIZERS`, not LLM selections.

## What these logs ARE still good for

1. **Proof of the input-parser bug.** The mojibake in the `Faulty Input` lines
   is the primary evidence. Do not delete them.
2. **Sanitizer-selection precision data.** `LLM_SELECTION_OK` fired on 7 of 9
   runs and the selections are real, e.g. llama3.1:8b choosing
   `check_markitdown_uri_validation` and the SSRF/URL family for an Appium
   gesture code generator taking `{language, useElement, elementId, x, y}`.
   Selection precision does not depend on what the seeds turned into, so this
   evidence survives the quarantine.

## What they must NOT be used for

Any finding, alert, coverage or FNR number in the paper. Do not merge this file
back into `eval/state/runs.jsonl`.

## Recovering the numbers

    python3 eval/run_eval.py --reparse   # rebuilds the ACTIVE index from eval/runs/*.log

The logs here were moved out of `eval/runs/` precisely so `--reparse` cannot
pull them back into the active index.

See the "DEEP AUDIT" section at the end of `ToFu_src/nazmul.todo` for the full
account, and `eval/state/quarantine-pre-llmfix/WHY.md` for the earlier one.
