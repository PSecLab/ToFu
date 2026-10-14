# Precision-labelling rubric (2026-09-27)

Sample: `sample.json` / `evidence.json` (98 bugs from the 508 headline; census of small
classes, seeded proportional draw of the rest; only bugs with surviving evidence).
Threat model: the tool argument is attacker-influenced (it arrives through the LLM).
Label from (1) the evidence record (triggering input, tool output, analysis) and
(2) the tool's source at the pinned commit. READ ONLY: never run, install, or import
target code.

## Labels
- **TP** — code + evidence show the tool performs the unsafe behavior on the
  caller-controlled argument, with a plausible security consequence.
- **TP-low** — the behavior is real but the impact is limited, or it is the tool's
  documented purpose (state which).
- **FP** — the evidence does not show the claimed behavior; or the code validates /
  neutralizes the input before the sink; or the observed event comes from the tool's
  own internals rather than the argument.
- **UNCLEAR** — cannot be decided from code and evidence.

## Class rules
- **reflected-xss**: input markup appears unescaped in the output. TP when the output is
  HTML/Markdown/SVG or other content meant to be rendered (docs, pages, charts, notes shown
  in a UI). TP-low when the output is plain text/JSON that only goes back to the LLM.
- **log-injection**: a caller string with CR/LF reaches a logger or log file without
  neutralization (CWE-117). TP for a persistent/aggregated log; TP-low for stderr/debug-only
  output.
- **path-traversal**: a caller path reaches a file operation with no containment, and the
  tool's documented role implies a scope (workspace, project, vault, output dir). TP-low if
  the tool documents arbitrary filesystem access. FP if a containment check exists and holds.
- **ssrf**: a caller URL/host is contacted by the server with no restriction on internal,
  loopback, or metadata destinations. FP if the URL is only forwarded as an identifier to a
  third-party API and never dialed by the server.
- **insecure-temp-file**: the tool itself creates a temp file/dir and leaves it behind or
  creates it with a predictable name / weak permissions. FP if the tool did not create it.
- **os-command-injection**: caller input reaches a shell or builds command arguments that
  allow an unintended command. TP-low if running commands is the tool's documented purpose.
- **data-exfiltration**: a sensitive file chosen by the input is read and its content is
  sent to an outbound destination in the same call.

## Output (one JSON list per group)
`{"id": <int>, "label": "TP|TP-low|FP|UNCLEAR", "reason": "<=25 words", "code_ref": "path:line"}`
Describe inputs in words ("a script tag", "a ../ path"); do not paste payloads.

## Coordinator decisions (2026-09-27)
- Template-brace-only echoes (no markup) into plain text/JSON/errors/generated code = FP.
- `basis: code-only`: the alert itself was incidental, but the tool's code confirms the reported
  weakness for the flagged argument (ids 5, 6 stored XSS via bundled viewer innerHTML; ids 67, 70,
  72, 77 argument written unescaped to a persistent log file). Labelled TP; precision is reported
  both alert-grounded (excluding code-only) and bug-exists (including them).
- id 62 (browse_webpage, SSRF): TP, basis code-only. SSRF rule has no documented-purpose
  exception; code fetches any URL; the dial is shown in an earlier run log, not this sample's.
- id 43 (roo-code append_memory_bank_entry, path-traversal): TP rests on code (run used backslash paths that stayed inside on Linux) -> basis code-only.
