# Quarantined: every run in here used the deterministic fallback, not the LLM

These runs were produced before the fix in `src/llm.py` (2026-09-09).

`LLMHandler.select_sanitizers()` parsed the model reply with

    content.strip().strip("```json").strip("```").strip()
    json.loads(content)

which is wrong twice over:

1. `str.strip(chars)` removes a *character set*, not a substring, so
   ``.strip("```json")`` strips any of the characters `` ` j s o n `` from
   both ends of the reply.
2. Nothing there survives prose outside the fence.

`llama3.1:8b` returns valid JSON but wraps it in an explanation plus a
bare ``` fence, so every call raised
`Expecting value: line 1 column 1 (char 0)`. `fuzzer.py` caught that and
logged `Falling back to default sanitizers` -- and the campaign carried on
looking healthy while the LLM stage never ran once.

`src/seed_bank/` had also been deleted in commit 87d8602, so
`generate_seeds()` short-circuited to `_local_fallback_mapping()` on every
tool as well. Both LLM roles were dead.

Nothing in this directory is evidence about ToFu's design. Do not report
it. Kept only as the before-half of the fix.
