# ToFu — project rules for Claude Code

**Read `HANDOFF.md` first, then `ToFu_src/nazmul.todo`, before touching anything.**
`HANDOFF.md` is the current state of the project; `nazmul.todo` is the lab
notebook explaining how each conclusion was reached. Both live in this repo on
purpose — they are the single source of truth and they travel with the code.

## The failure mode of this codebase

ToFu does not fail by crashing. It fails by reporting a healthy-looking
"0 findings" while something upstream is silently broken. That has happened four
separate times, each destroying a campaign (HANDOFF.md §0).

**When this codebase reports nothing, suspect the instrument before the target.**
Verify every measurement against a real log, never against what the source
appears to print. A fixture written from reading the code is how the original
never-matching keyword set shipped.

## Hard rules

1. **Never write a citation, a number, or a claim you have not verified against a
   primary source.** A previous model fabricated much of `paper.bib`; 13 of 19
   audited entries had invented titles or author names. See HANDOFF.md §9. If you
   cannot verify it, say so plainly rather than filling the gap.
2. **Never delete a "TO DOUBLE-CHECK" item** in `ToFu_src/nazmul.todo`, and never
   strip a `\TODO{Pierre...}` comment from a `.tex` file. Ananto removes those
   himself. Add to them freely.
3. **Never report a number you cannot trace to a log file.** Pre-fix runs are
   quarantined under `eval/state/quarantine-*/` and are not evidence about ToFu —
   each has a `WHY.md` saying why.
4. **Do not launch long campaigns through a tool call.** They must run natively in
   Ananto's Terminal. Prepare resumable, Ctrl-C-safe scripts for him instead.
5. **Record what you find in `nazmul.todo`** as a dated section. That is how this
   project carries state across sessions.

## Before any campaign whose numbers might be published

- `python3 -m pytest tests/ -q` → expect 66 passed, 1 skipped
- `pip install pyflakes` — `run_eval.py` has an undefined-name preflight that
  skips silently without it, and two campaigns have already been lost to
  NameErrors
- `TOFU_LLM_TEMPERATURE=0` and a fixed `TOFU_LLM_SEED`. Never run a campaign at
  the 0.7 default — selections become samples and nothing is reproducible
- Verify the JS coverage acceptance test in HANDOFF.md §4: `cov:` must increase
  during a run, `corp:` must grow, `exec/s` must rise

## Attribution trap

`fuzzer.py` merges 10 always-on `BASE_MANDATORY_SANITIZERS` into whatever the LLM
selects. An alert firing is **not** evidence for the LLM-selection design until
you subtract the mandatory layer. HANDOFF.md §2.

## Environment

Python 3.11 required (Atheris needs `dis.Positions`). Local Ollama on a 16 GB
M2 Pro; `gemma4:12b` is the chosen local arm. `arxiv.org`, `doi.org` and
HuggingFace are blocked by the egress proxy; GitHub and `git ls-remote` work.
