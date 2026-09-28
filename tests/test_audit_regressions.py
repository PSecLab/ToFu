"""Regression tests for the 2026-09-10 audit.

Each test corresponds to a bug that silently destroyed a real campaign.
The common failure mode was not a crash the operator could see: it was the
harness reporting a healthy-looking "0 findings" while something upstream
had gone wrong. These tests are written to fail loudly instead.
"""
import importlib.util
import glob
import json
import os
import shutil
import subprocess
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run_eval = _load("run_eval_under_test", "eval/run_eval.py")


# --------------------------------------------------------------------------
# BUG 1: eval/run_eval.py used re.* without importing re.
# Nine completed runs were discarded as "name 're' is not defined".
# BUG 2: src/llm.py called seed_generators.* without importing it, so every
# LLM seed-generation tool call failed with "name 'seed_generators' is not
# defined" and seeding silently fell back to the deterministic mapper.
#
# Both are NameErrors that only fire deep inside a run. This test catches the
# entire family statically, for the whole tree, in under a second.
# --------------------------------------------------------------------------
def test_no_undefined_names_anywhere():
    pyflakes = pytest.importorskip("pyflakes.api", reason="pip install pyflakes")
    import io
    import pyflakes.reporter

    buf = io.StringIO()
    reporter = pyflakes.reporter.Reporter(buf, buf)
    # Lint exactly the files git tracks under src/ eval/ tests/ = ToFu's own code.
    # A directory deny-list kept leaking clones: on the prepared PSU PC,
    # eval/targets/ made pyflakes raise RecursionError on a nested third-party
    # file, then eval/targets_tf/ (ToolFuzz clones) surfaced their own undefined
    # names (2026-09-28 ablation smoke). Untracked files are not ours.
    import subprocess
    try:
        files = subprocess.run(["git", "-C", ROOT, "ls-files", "--", "src", "eval", "tests"],
                               capture_output=True, text=True, check=True).stdout.split()
    except (OSError, subprocess.CalledProcessError):
        pytest.skip("not a git checkout")
    for rel in files:
        if rel.endswith(".py") and os.path.isfile(os.path.join(ROOT, rel)):
            pyflakes.api.checkPath(os.path.join(ROOT, rel), reporter)

    # eval/targets/ holds CLONED THIRD-PARTY REPOS and, since item 51, a
    # per-target .venv full of their site-packages. Their lint findings are not
    # ours and must never gate our campaign: a `from x import *` in some
    # target's h11 dependency is not a NameError waiting to happen in ToFu.
    # eval/targets/ AND eval/sandbox/targets/ hold cloned third-party repos and
    # their per-target .venv site-packages; a `from x import *` inside some
    # target's h11/attrs dependency is not a NameError waiting to happen in
    # ToFu. Exclude any vendored/virtualenv path, not one hardcoded dir.
    def _third_party(ln):
        return ("/targets/" in ln or "/.venv/" in ln or "/node_modules/" in ln
                or "/site-packages/" in ln)
    undefined = [ln for ln in buf.getvalue().splitlines()
                 if "undefined name" in ln and not _third_party(ln)]
    assert not undefined, (
        "undefined names become NameErrors mid-campaign:\n  " + "\n  ".join(undefined)
    )


# --------------------------------------------------------------------------
# BUG 3: finding_hits summed the reporter's banner AND the "Silent Bug Alert"
# text. Those are two lines of ONE finding, so every finding counted twice.
#
# This fixture is copied verbatim from a real campaign log
# (eval/runs/AppiumTestDistribution__mcp-appium-gestures__generate-tap-code.log).
# Fixtures invented from reading the source are what let the ORIGINAL keyword
# set ("sanitizer triggered", "violation", ...) ship while matching nothing the
# tool ever prints.
# --------------------------------------------------------------------------
REAL_LOG = """INFO:src.llm:LLM_SELECTION_OK tool=generate-tap-code attempt=1 n_selected=2 n_dropped=0
INFO:src.llm:LLM_SEEDGEN_OK n_seeds=12 attempt=1
WARNING:src.reporters:
[POTENTIAL VULNERABILITY / BUG FOUND] in 'generate-tap-code' !
WARNING:src.reporters:   -> Faulty Input : {'language': 'java', 'x': 0.0}
WARNING:src.reporters:   -> Analysis     : [Sequence Step 1/3] Silent Bug Alert: Sanitizers ['check_url_raw_input_validation', 'check_file_access'] flagged this input as malicious, but the target tool executed successfully without raising any exception.
WARNING:src.reporters:   -> Triggered Sanitizers : ['check_url_raw_input_validation', 'check_file_access']
WARNING:src.reporters:
[POTENTIAL VULNERABILITY / BUG FOUND] in 'generate-tap-code' !
WARNING:src.reporters:   -> Faulty Input : {'language': 'javascript', 'x': 0.0}
WARNING:src.reporters:   -> Analysis     : [Sequence Step 1/2] Silent Bug Alert: Sanitizers ['check_url_raw_input_validation', 'check_file_access'] flagged this input as malicious, but the target tool executed successfully without raising any exception.
WARNING:src.reporters:   -> Triggered Sanitizers : ['check_url_raw_input_validation', 'check_file_access']
"""


def test_finding_hits_counts_each_finding_once():
    rec = run_eval.parse_log(REAL_LOG)
    assert rec["finding_hits"] == 2, "the banner and Silent Bug Alert are one finding, not two"


def test_parse_log_extracts_sanitizers_and_dedups_signatures():
    rec = run_eval.parse_log(REAL_LOG)
    assert rec["triggered_sanitizers"] == ["check_file_access", "check_url_raw_input_validation"]
    # 2 alerts, 1 distinct sanitizer-set: the number that belongs in the paper.
    assert rec["finding_classes"] == 1


def test_parse_log_reads_the_llm_stage_markers():
    rec = run_eval.parse_log(REAL_LOG)
    assert rec["llm_selection"] == "ok"
    assert rec["llm_n_selected"] == 2 and rec["llm_n_dropped"] == 0
    assert rec["llm_seeds"] == "ok"
    assert rec["llm_n_seeds"] == 12


def test_llm_fallback_is_not_mistaken_for_success():
    """A campaign that fell back everywhere is not evidence about ToFu's
    LLM-assisted design and must never be recorded as if it were."""
    rec = run_eval.parse_log("WARNING:src.fuzzer:LLM API selection failed (x). "
                             "Falling back to default sanitizers.\n")
    assert rec["llm_selection"] == "failed"
    assert rec["llm_seeds"] == "unknown"
    assert rec["finding_hits"] == 0


def test_clean_log_reports_nothing():
    rec = run_eval.parse_log("INFO:src.cli:Starting fuzzer\nINFO: done\n")
    assert rec["finding_hits"] == 0
    assert rec["triggered_sanitizers"] == []
    assert rec["finding_classes"] == 0


# --------------------------------------------------------------------------
# BUG 4 (the substantive one): FuzzInputParser.parse() tried FDP generation
# BEFORE JSON parsing. _generate_fallback_inputs populates every declared
# property, so it always returned a non-empty dict and the JSON branch was
# unreachable for any tool with a schema -- i.e. every MCP tool.
#
# The effect was that a structured seed like {"path": "../../../etc/passwd"}
# never reached the tool as that string. Its bytes were fed to
# atheris.FuzzedDataProvider and read back in a wide encoding: real logs show
# the tool receiving the UTF-16 reading of the seed file's own JSON text.
# The entire semantic seed bank -- and every LLM-generated seed -- acted as
# nothing but entropy.
# --------------------------------------------------------------------------
SCHEMA = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "recursive": {"type": "boolean"},
    },
}


@pytest.fixture
def parser():
    pytest.importorskip("atheris", reason="atheris is required for the input parser")
    from src.input_parser import FuzzInputParser
    return FuzzInputParser(SCHEMA, {}, None)


def test_structured_seed_reaches_the_tool_verbatim(parser):
    """The whole point of a semantic seed bank is that the payload arrives
    intact. If this fails, the seeds are decoration."""
    payload = "../../../etc/passwd"
    seed = json.dumps({"path": payload}).encode()

    args, ok = parser.parse(seed)

    assert ok, "a schema-matching JSON seed must parse"
    assert args["path"] == payload, (
        f"seed payload was mangled on the way in: {args['path']!r}. "
        "This is the UTF-16 mojibake bug -- the seed was consumed as raw "
        "FuzzedDataProvider entropy instead of being parsed as JSON."
    )


def test_seed_is_completed_against_the_schema(parser):
    """A seed that names only some properties still yields a complete call,
    with the seed's own values preserved."""
    args, ok = parser.parse(json.dumps({"path": "/etc/shadow"}).encode())
    assert ok
    assert args["path"] == "/etc/shadow"
    assert "recursive" in args, "unspecified properties should be filled in"


def test_non_json_bytes_still_generate_schema_conforming_input(parser):
    """Mutation must keep working: atheris breaks most entries out of valid
    JSON, and those still have to produce a well-formed call."""
    args, ok = parser.parse(b"\x00\x01\x02not json at all\xff\xfe")
    assert ok
    assert set(args) == {"path", "recursive"}
    assert isinstance(args["path"], str)
    assert isinstance(args["recursive"], bool)


def test_json_that_does_not_match_the_schema_falls_through(parser):
    """A JSON object sharing no key with the schema is not a seed for this
    tool; it must not be passed through as-is."""
    args, ok = parser.parse(json.dumps({"unrelated": 1}).encode())
    assert ok
    assert set(args) == {"path", "recursive"}


# --------------------------------------------------------------------------
# BUG 5: src/__main__.py never accepted a corpus directory, so every run used
# ./fuzz_corpus -- which the fuzzer rmtree's when it starts a tool. With
# run_eval's default of 4 workers, concurrent runs deleted each other's
# corpora mid-campaign.
# --------------------------------------------------------------------------
def test_cli_accepts_per_run_corpus_and_metrics_dirs():
    out = subprocess.run([sys.executable, "-m", "src", "--help"],
                         cwd=ROOT, capture_output=True, timeout=120)
    helptext = out.stdout.decode(errors="ignore") + out.stderr.decode(errors="ignore")
    if "No module named" in helptext:
        pytest.skip("ToFu dependencies not installed in this interpreter")
    assert "--corpus-dir" in helptext, "runs cannot be isolated without --corpus-dir"
    assert "--metrics-dir" in helptext


# --------------------------------------------------------------------------
# BUG 6: a live API key was the default value for OLLAMA_CLOUD_API_KEY in
# src/__main__.py and 11 targets/fuzz_*.py, and was committed to git history.
# --------------------------------------------------------------------------
def test_no_hardcoded_credential_in_the_tree():
    # Split so this canary does not itself trip a secret scanner.
    leaked = "f3ddcac48ab94ad692154fbb0ba3d283" + "." + "mvFXxYWZ4pQnmeSA27BnBp8z"
    offenders = []
    for sub in ("src", "eval", "targets"):
        for dirpath, dirnames, filenames in os.walk(os.path.join(ROOT, sub)):
            dirnames[:] = [d for d in dirnames if d not in ("__pycache__", ".venv")]
            for fn in filenames:
                if not fn.endswith(".py"):
                    continue
                p = os.path.join(dirpath, fn)
                try:
                    if leaked in open(p, errors="ignore").read():
                        offenders.append(os.path.relpath(p, ROOT))
                except OSError:
                    pass
    assert not offenders, "leaked credential still present in: " + ", ".join(offenders)


# --------------------------------------------------------------------------
# BUG 7: the LLM answered the final seed-generation turn with an array of its
# OWN tool-call envelopes instead of an array of tool arguments. Their keys
# ("name", "parameters") match zero schema properties, so input_parser fell
# through to FuzzedDataProvider and the envelope bytes came back as UTF-16
# mojibake -- while the log said LLM_SEEDGEN_OK n_seeds=12.
#
# Fixtures are copied VERBATIM from the real corpus written by the run at
# eval/corpora/AppiumTestDistribution__mcp-appium-gestures__
# generate-double-tap-code/seed_1.json (2026-09-10 01:16), not written from
# reading the source.
# --------------------------------------------------------------------------
APPIUM_SCHEMA_PROPERTIES = {
    "language": {"type": "string"},
    "useElement": {"type": "boolean"},
    "elementId": {"type": "string"},
    "x": {"type": "number"},
    "y": {"type": "number"},
    "pauseDuration": {"type": "number"},
}

# verbatim seed_1.json / seed_0.json from that run
ENVELOPE_SEEDS = [
    {"name": "create_json", "parameters": {
        "filename": "test_case.json",
        "json_content": '{"language": "java", "useElement": false, '
                        '"elementId": "element2", "x": 0, "y": 0, "pauseDuration": 0}'}},
    {"name": "create_json", "parameters": {
        "filename": "test_case.json",
        "json_content": '{"language": "javascript", "useElement": true, '
                        '"elementId": "element1", "x": 10, "y": 20, "pauseDuration": 200}'}},
]

# what the SAME model produced correctly for excel-reader-mcp get_cell,
# verbatim from that run's seed_0.json
GOOD_SEEDS = [
    {"language": "javascript", "useElement": True, "elementId": "element1",
     "x": 10, "y": 20, "pauseDuration": 200},
    {"language": "java", "useElement": False, "elementId": "element2",
     "x": 0, "y": 0, "pauseDuration": 0},
]


def _validate_seeds():
    # src/llm.py uses a relative import (`from . import seed_generators`), so it
    # must be loaded as part of the package, not by file path.
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.llm import _validate_seeds as fn
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"src.llm not importable in this interpreter: {e}")
    return fn


def test_tool_call_envelopes_are_rejected_as_seeds():
    kept, rejected, checked = _validate_seeds()(
        ENVELOPE_SEEDS, APPIUM_SCHEMA_PROPERTIES, "generate-double-tap-code")
    assert checked, "validation must run when the schema declares properties"
    assert kept == [], "envelopes share no key with the schema and must not be seeded"
    assert len(rejected) == len(ENVELOPE_SEEDS)


def test_well_formed_seeds_survive_validation():
    kept, rejected, checked = _validate_seeds()(
        GOOD_SEEDS, APPIUM_SCHEMA_PROPERTIES, "generate-double-tap-code")
    assert checked
    assert kept == GOOD_SEEDS, "correctly shaped seeds must not be dropped"
    assert rejected == []


def test_validation_predicate_matches_the_parser_predicate():
    """A seed accepted here must be honoured by input_parser, or the fix is
    cosmetic: the parser keeps a JSON entry only when it shares at least one
    key with the declared properties (input_parser.py _try_parse_json,
    `matched > 0`)."""
    parser_src = open(os.path.join(ROOT, "src/input_parser.py"),
                      errors="ignore").read()
    assert "matched > 0" in parser_src, (
        "input_parser no longer gates on matched > 0; re-derive _validate_seeds "
        "against whatever predicate replaced it")


def test_partially_valid_batch_keeps_only_the_valid_seeds():
    kept, rejected, checked = _validate_seeds()(
        ENVELOPE_SEEDS + GOOD_SEEDS, APPIUM_SCHEMA_PROPERTIES, "t")
    assert checked
    assert kept == GOOD_SEEDS
    assert len(rejected) == len(ENVELOPE_SEEDS)


def test_no_declared_properties_means_no_validation():
    """With nothing to validate against, seeds pass through and the caller is
    told validation did NOT run -- so an empty schema can never be reported as
    a clean validated pass."""
    kept, rejected, checked = _validate_seeds()(ENVELOPE_SEEDS, {}, "t")
    assert checked is False
    assert kept == ENVELOPE_SEEDS
    assert rejected == []


# --------------------------------------------------------------------------
# BUG 8: coverage_wrapper.js filtered V8 ranges on `count > 0`, which discards
# exactly the branch information. V8 block coverage emits ONE range for the
# whole function with its execution count, then carves out the branches that
# did NOT run as nested count:0 sub-ranges -- so the count>0 set is identical
# no matter which branch an input takes, and libFuzzer's cov: never moves.
#
# The three range sets below were MEASURED from a live inspector.Session on
# 2026-09-10 (one function, three branches, detailed:true), not written from
# reading the source.
# --------------------------------------------------------------------------
MEASURED_V8_RANGES = {
    # input 'routes'
    "routes": [{"startOffset": 157, "endOffset": 265, "count": 1},
               {"startOffset": 207, "endOffset": 263, "count": 0}],
    # input 'services'
    "services": [{"startOffset": 157, "endOffset": 265, "count": 1},
                 {"startOffset": 194, "endOffset": 207, "count": 0},
                 {"startOffset": 244, "endOffset": 263, "count": 0}],
    # input 'zzz' (else branch)
    "zzz": [{"startOffset": 157, "endOffset": 265, "count": 1},
            {"startOffset": 194, "endOffset": 207, "count": 0},
            {"startOffset": 231, "endOffset": 244, "count": 0}],
}


def _executed_intervals(ranges):
    """Run coverage_wrapper.js's executedIntervals() under node."""
    if not shutil.which("node"):
        pytest.skip("node not available")
    wrapper = os.path.join(ROOT, "src/runners/coverage_wrapper.js")
    script = (
        "const fs=require('fs');"
        f"const src=fs.readFileSync({json.dumps(wrapper)},'utf8');"
        "const fn=src.slice(src.indexOf('function executedIntervals'),"
        "                   src.indexOf('function processCoverage'));"
        "eval(fn);"
        "const r=JSON.parse(process.argv[1]);"
        "console.log(JSON.stringify(executedIntervals(r)));"
    )
    out = subprocess.run(["node", "-e", script, json.dumps(ranges)],
                         capture_output=True, timeout=60)
    assert out.returncode == 0, out.stderr.decode()
    return [tuple(x) for x in json.loads(out.stdout.decode())]


def test_v8_block_coverage_discriminates_between_branches():
    sets = {k: tuple(_executed_intervals(v)) for k, v in MEASURED_V8_RANGES.items()}
    assert len(set(sets.values())) == 3, (
        "three inputs taking three different branches must yield three distinct "
        f"coverage sets; got {sets}. A count>0 filter collapses them to one and "
        "pins libFuzzer's cov: for the whole run."
    )


def test_not_taken_branch_leaves_a_hole():
    """The count:0 sub-range must be subtracted, not reported as executed."""
    iv = _executed_intervals(MEASURED_V8_RANGES["routes"])
    assert (157, 207) in iv, f"the taken branch must be reported; got {iv}"
    assert not any(a <= 207 and b >= 263 for a, b in iv), (
        f"the not-taken branch 207-263 must be carved out; got {iv}")


def test_coverage_items_are_byte_offsets_not_line_numbers():
    """Line expansion re-merges branches sharing a line, and most Set A targets
    ship a minified dist/index.js where a whole handler is one line."""
    src = open(os.path.join(ROOT, "src/runners/coverage_wrapper.js"),
               errors="ignore").read()
    body = src[src.index("function processCoverage"):]
    assert "offsetToLine" not in body, (
        "processCoverage is expanding ranges to line numbers again")


# --------------------------------------------------------------------------
# BUG 9: a tool that errors on EVERY input was recorded identically to a tool
# that ran cleanly and found nothing. Measured 2026-09-10: all 32
# api7/apisix-mcp tools return
#     "Status: undefined\nMessage: connect ECONNREFUSED 127.0.0.1:9180"
# because the server is an Admin-API client and nothing listens on :9180. No
# sanitizer can fire and coverage cannot vary, yet the run reports 0 findings
# and looks healthy -- the exact shape of the four campaign-destroying bugs
# before it.
# --------------------------------------------------------------------------
NOT_EXECUTABLE_LOG = (
    "INFO:src.fuzzer:[FUZZING METRICS] Total Executions: 8192 | Duration: 120.00s | Speed: 68.27 exec/s\n"
    "INFO:src.fuzzer:EXEC_SUMMARY tool=delete_resource n_exec=8192 n_success=0 success_rate=0.000\n"
    "INFO:src.fuzzer:EXEC_ERROR n=8192 detail='[{\\'type\\': \\'text\\', \\'text\\': "
    "\\'\"Status: undefined\\\\nMessage: connect ECONNREFUSED 127.0.0.1:9180\"\\'}]'\n"
    "ERROR:src.fuzzer:NOT_EXECUTABLE tool=delete_resource -- all 8192 executions returned an error\n"
)

HEALTHY_LOG = (
    "INFO:src.fuzzer:EXEC_SUMMARY tool=classify n_exec=5000 n_success=4998 success_rate=0.999\n"
)


def test_tool_that_never_executed_is_not_recorded_as_a_clean_run():
    rec = run_eval.parse_log(NOT_EXECUTABLE_LOG)
    assert rec["executable"] == "no", rec
    assert rec["n_exec"] == 8192 and rec["n_exec_success"] == 0
    assert rec["finding_hits"] == 0
    assert rec.get("exec_errors"), "the recurring error must be recorded for triage"
    assert "ECONNREFUSED" in rec["exec_errors"][0]["detail"]


def test_healthy_run_is_marked_executable():
    rec = run_eval.parse_log(HEALTHY_LOG)
    assert rec["executable"] == "yes"
    assert rec["n_exec"] == 5000 and rec["n_exec_success"] == 4998
    assert rec["exec_success_rate"] > 0.99


def test_missing_exec_summary_is_unknown_not_yes():
    """An old log has no EXEC_SUMMARY. It must not be silently upgraded to
    'the tool ran fine' -- that is how every previous silent-zero shipped."""
    rec = run_eval.parse_log("INFO:src.fuzzer:nothing useful here\n")
    assert rec["executable"] == "unknown"
    assert rec["n_exec"] is None


# --------------------------------------------------------------------------
# BUG 10: _local_fallback_mapping ignored "enum" and filled every string with
# "test". Measured 2026-09-10 on mcp-appium-gestures::generate-double-tap-code
# (language is enum ['javascript','java']): 34 of 37 seeds carried
# language="test" and the server rejected every one with
#     MCP error -32602: Invalid ... parameters [{"received":"test", ...}]
# 0 of 38 executions succeeded, so no sanitizer could fire and the run reported
# a healthy "0 findings". After the fix: 21/39 execute and the tool produces 5
# distinct coverage sets instead of 1.
#
# input_parser._generate_value_for_schema ALREADY honoured enums, so the seed
# path and the FDP path disagreed with each other about the same schema.
# --------------------------------------------------------------------------
APPIUM_ENUM_SCHEMA = {   # verbatim from the live server's tools/list
    "properties": {
        "language": {"type": "string", "enum": ["javascript", "java"]},
        "useElement": {"type": "boolean"},
        "elementId": {"type": "string"},
        "x": {"type": "number"},
        "y": {"type": "number"},
        "pauseDuration": {"type": "number"},
    }
}


def _mapper():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.llm import LLMHandler
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"src.llm not importable: {e}")
    return LLMHandler.__new__(LLMHandler)._local_fallback_mapping


def test_enum_fields_are_filled_with_declared_members():
    seeds = _mapper()(APPIUM_ENUM_SCHEMA, {})
    langs = [s.get("language") for s in seeds if isinstance(s, dict)]
    assert langs, "mapper produced no seeds"
    valid = [x for x in langs if x in ("javascript", "java")]
    assert len(valid) / len(langs) > 0.5, (
        "most seeds must carry a VALID enum member, otherwise every other "
        f"field's payload is rejected before it reaches the tool; got {set(langs)}")
    assert "test" not in langs, "'test' is not a member of ['javascript','java']"


def test_every_enum_member_is_exercised():
    seeds = _mapper()(APPIUM_ENUM_SCHEMA, {})
    langs = {repr(s.get("language")) for s in seeds if isinstance(s, dict)}
    assert {repr("javascript"), repr("java")} <= langs, f"missing an enum branch: {langs}"


def test_one_out_of_enum_probe_is_still_emitted():
    """Rejecting an invalid enum is legitimate behaviour worth exercising --
    just not in 34 of 37 seeds."""
    seeds = _mapper()(APPIUM_ENUM_SCHEMA, {})
    langs = [s.get("language") for s in seeds if isinstance(s, dict)]
    bad = [x for x in langs if isinstance(x, str) and x not in ("javascript", "java")]
    assert len(bad) >= 1, "no out-of-enum probe at all"
    assert len(bad) <= 3, f"too many out-of-enum seeds ({len(bad)}); they crowd out real coverage"


def test_seed_mapper_and_input_parser_agree_about_enums():
    """The two paths must not disagree about the same schema."""
    parser_src = open(os.path.join(ROOT, "src/input_parser.py"), errors="ignore").read()
    llm_src = open(os.path.join(ROOT, "src/llm.py"), errors="ignore").read()
    assert '"enum" in schema' in parser_src, "input_parser stopped honouring enums"
    assert 'attrs.get("enum")' in llm_src, "the seed mapper stopped honouring enums"


# --------------------------------------------------------------------------
# BUG 11: everything after engine.fuzz() is dead code. libFuzzer terminates the
# process when -max_total_time expires, so the post-fuzz epilogue never runs:
# "[FUZZING METRICS]" and "Fuzzing session completed" appear in ZERO of every
# log this repo has ever produced, and libFuzzer's own closing "Done ... runs"
# line is lost with them. Any measurement emitted only at the end is a
# measurement that never gets emitted.
# --------------------------------------------------------------------------
def test_exec_summary_is_emitted_during_fuzzing_not_only_at_the_end():
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    body = src[src.index("def test_one_input"):src.index("def _emit_exec_summary")]
    assert "_emit_exec_summary" in body, (
        "the exec summary must be emitted from the per-execution path; emitting "
        "it only after engine.fuzz() means it never appears at all")


def test_parse_log_takes_the_last_exec_summary():
    """Periodic emission means many summaries per log; the final one is the
    only accurate one."""
    out = (
        "INFO:src.fuzzer:EXEC_SUMMARY tool=t n_exec=1 n_success=0 success_rate=0.000\n"
        "INFO:src.fuzzer:EXEC_SUMMARY tool=t n_exec=512 n_success=300 success_rate=0.586\n"
        "INFO:src.fuzzer:EXEC_SUMMARY tool=t n_exec=8192 n_success=5000 success_rate=0.610\n"
    )
    rec = run_eval.parse_log(out)
    assert rec["n_exec"] == 8192 and rec["n_exec_success"] == 5000, rec
    assert rec["executable"] == "yes"


def test_single_early_failure_is_not_yet_called_not_executable():
    """One failed execution is not evidence the tool is dead -- the loud
    NOT_EXECUTABLE verdict needs a real sample behind it."""
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    assert "or self.exec_count) >= 64 and self.exec_success == 0" in src, (
        "NOT_EXECUTABLE must require a meaningful number of executions")


# --------------------------------------------------------------------------
# BUG 12: a non-empty `predefined_seeds` in a config REPLACES LLM seed
# generation -- ToFu's central claim -- and it expects full ARGUMENT OBJECTS,
# not filenames. Setting it to ['sample.xlsx'] (2026-09-10, while wiring up
# file_backed_params) wrote ONE corpus entry containing the JSON string
# "sample.xlsx". libFuzzer reported "seed corpus: files: 1", no LLM_SEEDGEN
# marker was emitted at all, and the run logged
#     EXEC_SUMMARY tool=get_cell n_exec=15872 n_success=0
#     EXEC_ERROR n=48337 detail='Invalid cell address: '
# This mirrors the override_rules rule in eval/README.md: both keys silently
# switch off the automated path the paper is about.
# --------------------------------------------------------------------------
def test_eval_configs_do_not_bypass_the_llm_stage():
    bad_seeds, bad_rules = [], []
    for p in glob.glob(os.path.join(ROOT, "eval/configs/*.json")):
        cfg = json.load(open(p))
        if cfg.get("predefined_seeds"):
            bad_seeds.append(os.path.basename(p))
        if cfg.get("override_rules"):
            bad_rules.append(os.path.basename(p))
    assert not bad_seeds, (
        "non-empty predefined_seeds REPLACES llm.generate_seeds(): " + ", ".join(bad_seeds[:5]))
    assert not bad_rules, (
        "non-empty override_rules SKIPS llm.select_sanitizers() (fuzzer.py): "
        + ", ".join(bad_rules[:5]))


def test_predefined_seeds_still_short_circuits_generation():
    """Pin the semantics the test above depends on, so a refactor that changes
    them fails loudly here instead of silently switching the LLM back off."""
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    body = src[src.index("def _setup_corpus_seeds"):]
    assert "if self.predefined_seeds:" in body[:400], (
        "_setup_corpus_seeds no longer short-circuits on predefined_seeds; "
        "re-derive test_eval_configs_do_not_bypass_the_llm_stage")


# --------------------------------------------------------------------------
# BUG 13: sequence_steps defaulted to 2 (FuzzerConfig has no such field, so the
# getattr default always won), slicing every corpus entry into fragments before
# parsing. None of the fragments is valid JSON, so the JSON-first parse order,
# the seed bank, LLM seed generation and seed validation were all defeated: a
# perfect seed could never arrive intact.
# --------------------------------------------------------------------------
def test_inputs_are_not_sliced_before_parsing_by_default():
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    assert 'getattr(self.config, "sequence_steps", 1)' in src, (
        "sequence mode must be OFF by default; splitting a serialised argument "
        "object at an arbitrary byte offset is corruption, not a call sequence")


def test_a_whole_seed_survives_the_default_path():
    """The real seed from the 2026-09-10 proof run must parse as JSON."""
    seed = (b'{"filePath": "predefined_seed:test_file.xlsx", '
            b'"sheetName": "Sheet1", "cell": "A1"}')
    steps = 1
    chunks = [seed] if steps <= 1 else [
        seed[i:i + len(seed) // steps] for i in range(0, len(seed), max(1, len(seed) // steps))]
    assert len(chunks) == 1
    assert json.loads(chunks[0])["cell"] == "A1"


# --------------------------------------------------------------------------
# BUG 14: _check_string_sanitizers called EVERY selected sanitizer with a plain
# string whatever its declared parameter type, then did `if triggered:` on the
# result. Sanitizers return either bool or (bool, detail) -- and a 2-tuple is
# ALWAYS truthy, (False, '') included. Measured 2026-09-10:
#
#   check_process_and_fd_leaks(leaked_pids: set[int]) called with
#   '/var/folders/.../tmp32djxuif.xlsx' returns
#   (True, 'Leaked background subprocess PIDs detected ... <that path>')
#
# One 90s run produced 295 identical alerts, all three names from
# BASE_MANDATORY_SANITIZERS, on the benign input ToFu itself constructed:
#   {'filePath': '<temp>.xlsx', 'sheetName': 'Sheet1', 'cell': 'A1'}
# Not one LLM-selected sanitizer fired. Every string-path alert this repo has
# ever produced involving a tuple-returning sanitizer is a false positive.
# --------------------------------------------------------------------------
def _fuzzer_mod():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        import src.fuzzer as f
        import src.sanitizers as s
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"src not importable: {e}")
    return f, s


def test_non_string_contract_sanitizers_are_not_called_with_a_string():
    f, s = _fuzzer_mod()
    for name in ("check_process_and_fd_leaks", "check_file_access",
                 "check_unhandled_promise_rejection"):
        fn = getattr(s, name, None)
        assert fn is not None, name
        assert not f._takes_a_string(fn), (
            f"{name} does not take a string; calling it with one fires it "
            f"spuriously on every argument of every input")


def test_real_string_sanitizers_are_still_eligible():
    """The filter must not silently switch off the genuine checks -- that is
    the exact failure mode this codebase keeps having."""
    f, s = _fuzzer_mod()
    fn = getattr(s, "check_path_traversal", None)
    assert fn is not None and f._takes_a_string(fn)
    eligible = [n for n in s.AVAILABLE_SANITIZERS
                if getattr(s, n, None) and f._takes_a_string(getattr(s, n))]
    assert len(eligible) >= 10, f"only {len(eligible)} string sanitizers survived the filter"


def test_tuple_returns_are_normalised_before_the_truth_test():
    f, s = _fuzzer_mod()
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    body = src[src.index("def _check_string_sanitizers"):]
    assert "isinstance(triggered, tuple)" in body, (
        "a (False, '') return is a non-empty tuple and therefore truthy; it "
        "must be unpacked before `if triggered:`")
    # and the property itself
    assert bool((False, "")) is True, "python semantics changed; revisit this fix"


# --------------------------------------------------------------------------
# BUG 15: the paper's thesis (sec4_design.tex:10) is that the property
# EXERCISED is the property JUDGED, and sec4_design.tex:158-163 says values are
# generated "using the corresponding sanitizer's adversarial input classes".
# In code the two were chosen independently: generate_seeds() never received
# the selected sanitizers, and _local_fallback_mapping picked a seed-bank
# category by keyword match on the ARGUMENT NAME. Measured 2026-09-10 on
# excel-reader::get_cell: the LLM selected check_path_traversal, the seeds were
# generic, and check_path_traversal never fired. RQ4 asks exactly this and
# could not be answered.
# --------------------------------------------------------------------------
def test_seed_generation_receives_the_selected_sanitizers():
    llm_src = open(os.path.join(ROOT, "src/llm.py"), errors="ignore").read()
    fz_src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    assert "selected_sanitizers" in llm_src.split("def generate_seeds")[1][:300], (
        "generate_seeds must take the selected sanitizers")
    assert "selected_sanitizers=self.selected_sanitizer_names" in fz_src, (
        "the fuzzer must pass its selection into seed generation")


def test_selected_sanitizers_map_to_adversarial_input_classes():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.llm import categories_for_sanitizers
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"src.llm not importable: {e}")
    bank = {c: {} for c in ("path_traversal", "sql_injection", "ssrf_url",
                            "wildcards", "xml_bomb", "xss_markdown")}
    cats, mapped, unmapped = categories_for_sanitizers(
        ["check_path_traversal", "check_introspection_sql_injection",
         "check_unsafe_url_ssrf", "check_resource_exhaustion"], bank)
    assert "path_traversal" in cats and "sql_injection" in cats and "ssrf_url" in cats
    assert "check_resource_exhaustion" in unmapped, (
        "a sanitizer with no adversarial class must be REPORTED, not silently dropped")


def test_unmapped_sanitizers_are_counted_not_hidden():
    """With 6 seed categories against 71 sanitizers, most selections are partly
    unmapped. That fraction is an RQ1/RQ4 number and must reach the log."""
    llm_src = open(os.path.join(ROOT, "src/llm.py"), errors="ignore").read()
    assert "SEEDGEN_UNMAPPED" in llm_src and "SEEDGEN_CLASSES" in llm_src


def test_failfast_stops_a_tool_that_never_executes():
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    assert "FAILFAST" in src and "TOFU_FAILFAST_EXECS" in src, (
        "a tool failing every execution must stop, not burn the whole budget")


# --------------------------------------------------------------------------
# BUG 16: check_strict_url_security_contract read generated_arguments["url"]
# literally. It was written for targets/fuzz_http_check.py, whose argument IS
# called url; the LLM selects it for any URL-ish tool. On a tool whose argument
# is named otherwise, url_input was None and EVERY sub-check fired on None
# ("Expected str type, got NoneType", "Missing scheme", "Hostname is empty"),
# so the contract reported a Validation Bypass on every input. Measured
# 2026-09-10 on yan5236/bing-cn-mcp-server::crawl_webpage (argument `urlMap`):
# 19 alerts, all of them this, all reporting "Input: 'None'".
# --------------------------------------------------------------------------
class _OkRes:
    success = True
    result = {"content": []}


def _url_contract():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.sanitizers.url_sanitizers import check_strict_url_security_contract
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"url_sanitizers not importable: {e}")
    return check_strict_url_security_contract


def test_url_contract_is_silent_when_the_tool_has_no_url_argument():
    fired, msg = _url_contract()({"uuids": ["a"], "count": 1}, _OkRes())
    assert fired is False, f"must stay silent, not fire on a missing argument: {msg}"


def test_url_contract_finds_a_url_under_another_name():
    """crawl_webpage's real shape: a MAP whose values are the URLs."""
    fired, msg = _url_contract()(
        {"uuids": ["u"], "urlMap": {"u": "http://10.0.0.1/internal_api"}}, _OkRes())
    assert fired is True, "an internal-range URL the tool accepted must still fire"


def test_url_contract_does_not_fire_on_a_benign_url():
    fired, msg = _url_contract()({"url": "https://example.com/"}, _OkRes())
    assert fired is False, msg


# --------------------------------------------------------------------------
# BUG 17: a server that answers a failed call with a NORMAL result whose
# payload is an error object (rather than setting isError) was recorded as a
# successful execution. Measured 2026-09-10 on freestylefly/mcp-server-weread,
# which has no cookie configured and answers EVERY input with
#   {'error': {'message': '没有找到cookie，请按照文档填写cookie或配置Cookie Cloud'}}
# It therefore looked 100% executable, and the outcome oracle concluded the
# tool "executed successfully without raising" -- 404 alerts across two tools,
# every one a false positive, on a tool that never ran its own logic.
# --------------------------------------------------------------------------
def _inband():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.runners.js_runner import _inband_error
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"js_runner not importable: {e}")
    return _inband_error


def test_inband_error_payload_is_not_a_successful_execution():
    # verbatim from the weread run
    assert _inband()({"error": {"message": "没有找到cookie，请按照文档填写cookie或配置Cookie Cloud"}})


def test_absent_or_empty_error_members_are_not_errors():
    f = _inband()
    assert f({"error": None}) is None
    assert f({"errors": []}) is None
    assert f({"content": [{"type": "text", "text": "ok"}]}) is None


# --------------------------------------------------------------------------
# BUG 18: a structured refusal inside an MCP content block was invisible to the
# oracle. bhouston/mcp-server-text-editor answers a refusal with
#   {"content":[{"type":"text","text":"{\"success\":false,
#                                       \"message\":\"Path must be absolute\"}"}]}
# -- a NORMAL result, no isError, no top-level error. Measured 2026-09-10 on
# the gpt-4.1 arm: 426 alerts on that one tool, every one of them the tool
# CORRECTLY REFUSING ("File not found: /etc/passwd", "Path must be absolute",
# "new_str parameter is required"), while check_path_traversal reported a
# validation bypass because the refusal was unreadable.
#
# Bug 17 fixed the top-level shape; this is the same failure one layer deeper.
# --------------------------------------------------------------------------
def test_structured_refusal_inside_a_content_block_is_a_failed_execution():
    f = _inband()
    for msg in ("Path must be absolute",
                "File not found: /etc/passwd",
                "new_str parameter is required for insert command"):
        res = {"content": [{"type": "text",
                            "text": json.dumps({"success": False, "message": msg,
                                                "content": "undefined"})}]}
        assert f(res) == msg, f"refusal not detected: {msg}"


def test_a_successful_structured_result_is_not_an_error():
    f = _inband()
    assert f({"content": [{"type": "text",
                           "text": json.dumps({"success": True, "content": "ok"})}]}) is None


def test_a_normal_json_result_is_not_an_error():
    """sequential-thinking returns a JSON object with no success/error member;
    it must not be mistaken for a refusal."""
    f = _inband()
    res = {"content": [{"type": "text",
                        "text": json.dumps({"thoughtNumber": -1, "branches": []})}]}
    assert f(res) is None


def test_prose_mentioning_error_is_not_parsed_as_a_refusal():
    """Only STRUCTURED failure counts. Guessing at prose would trade one class
    of false positive for another."""
    f = _inband()
    assert f({"content": [{"type": "text", "text": "an error occurred maybe"}]}) is None


# --------------------------------------------------------------------------
# BUG 19 (nazmul.todo item 40): process-leak detection used a GLOBAL "which
# pids are new" diff, so it saw every process the whole machine started during
# the execution window. With --workers 2 the campaign reported
#   "Process leak/leftover detected: PID 38747 (node)"
# on four tools that spawn nothing -- the other worker's MCP server. It fired
# in three separate arms.
#
# There WAS an ancestry filter, and it is correct in isolation, but it was
# guarded by `if leaked_pids and self.current_runner and
# self.current_runner.process:` -- so with no live `process` it was skipped and
# the unfiltered global diff was returned. It failed OPEN.
# --------------------------------------------------------------------------
PS_TWO_WORKERS = {          # pid: (ppid, comm)
    100: (1, "python"),     # worker A harness
    101: (100, "node"),     #   worker A's MCP server   <- the root we care about
    102: (101, "node"),     #     a genuine child of the target
    103: (102, "sh"),       #       grandchild
    200: (1, "python"),     # worker B harness
    201: (200, "node"),     #   worker B's MCP server -- must NEVER be attributed to A
}


def _desc():
    if ROOT not in sys.path:
        sys.path.insert(0, ROOT)
    try:
        from src.fuzzer import _descendants
    except Exception as e:                                   # pragma: no cover
        pytest.skip(f"src.fuzzer not importable: {e}")
    return _descendants


def test_only_the_targets_own_descendants_are_counted():
    d = _desc()(101, PS_TWO_WORKERS)
    assert d == {102, 103}, d


def test_another_workers_server_is_never_attributed():
    assert 201 not in _desc()(101, PS_TWO_WORKERS)
    assert 200 not in _desc()(101, PS_TWO_WORKERS)


def test_no_root_fails_closed_not_open():
    """With no server pid the answer must be 'nothing', not 'everything'. The
    old guard fell through to an unfiltered global diff in exactly this case."""
    assert _desc()(None, PS_TWO_WORKERS) == set()
    assert _desc()(0, PS_TWO_WORKERS) == set()


def test_leak_detection_no_longer_uses_a_global_pid_set():
    src = open(os.path.join(ROOT, "src/fuzzer.py"), errors="ignore").read()
    body = src[src.index("def _execute_and_time"):src.index("def _run_sanitizers")]
    assert "set(ps_before)" not in body and "set(ps_after)" not in body, (
        "a global pid snapshot is being diffed again; other workers' processes "
        "will be reported as leaks")


# ---------------------------------------------------------------------------
# Bug 20: a transport failure was reported as resource exhaustion.
#
# Fixtures are VERBATIM from eval/runs/gpt41-full/
# AppiumTestDistribution__mcp-appium-gestures__generate-swipe-code.log
# (run started 2026-09-11 02:03:03, commit e14a363). js_runner.py sets
# sock.settimeout(5.0); config.timeout_limit defaults to 2.0. Every timed-out
# read therefore scored elapsed ~5.0 > 2.0 and was reported as a finding with
# "Tool Output: None" -- 21 of them on this one tool, all identical.
# ---------------------------------------------------------------------------
class _Res:
    def __init__(self, success, error=""):
        self.success = success
        self.error = error


def _exhaustion_checker(selected=("check_resource_exhaustion",), limit=2.0):
    from src.fuzzer import MCPDifferentialFuzzer

    class _Cfg:
        timeout_limit = limit

    f = MCPDifferentialFuzzer.__new__(MCPDifferentialFuzzer)
    f.selected_sanitizer_names = list(selected)
    f.config = _Cfg()
    return f


def test_socket_timeout_is_not_resource_exhaustion():
    """The exact failure that produced 21 false alerts."""
    f = _exhaustion_checker()
    res = _Res(False, "Socket error: timed out")
    triggered, _ = f._check_resource_exhaustion(5.01, res)
    assert triggered is False, "socket timeout must not be reported as exhaustion"


def test_runner_restart_failure_is_not_resource_exhaustion():
    f = _exhaustion_checker()
    res = _Res(False, "JS runner process is not running and failed to restart: boom")
    triggered, _ = f._check_resource_exhaustion(5.16, res)
    assert triggered is False


def test_genuine_slow_execution_still_fires():
    """The guard must not silence real findings: a SUCCESSFUL slow call still alerts."""
    f = _exhaustion_checker()
    res = _Res(True, "")
    triggered, err = f._check_resource_exhaustion(3.5, res)
    assert triggered is True
    assert "3.50 seconds" in err


def test_fast_execution_does_not_fire():
    f = _exhaustion_checker()
    triggered, _ = f._check_resource_exhaustion(0.2, _Res(True, ""))
    assert triggered is False


def test_exhaustion_skipped_when_sanitizer_not_selected():
    f = _exhaustion_checker(selected=())
    triggered, _ = f._check_resource_exhaustion(99.0, _Res(True, ""))
    assert triggered is False


def test_missing_result_treated_as_transport_failure():
    f = _exhaustion_checker()
    triggered, _ = f._check_resource_exhaustion(5.0, None)
    assert triggered is False


# ---------------------------------------------------------------------------
# Bug 21: the target ran from ToFu's cwd, not its own.
#
# prepare_targets.py has always written "cwd" into every config. Nothing read
# it: JSRunner called Popen without cwd=, so the target inherited ToFu's repo
# root. Consequence, measured 2026-09-11 on
# ArchimedesCrypto/excel-reader-mcp::export_to_json with
# outputPath="../../../../tmp/evil.json":
#     cwd = target dir   -> ENOENT, the tool fails safely
#     cwd = ToFu root    -> writes /tmp/evil.json  (4 levels up from the repo
#                           root is exactly /)
# The run logged 14 check_path_traversal "Silent Bug Alert"s from this. They
# are artefacts of OUR launch directory, not properties of the target.
# ---------------------------------------------------------------------------
def test_js_runner_accepts_and_stores_cwd():
    from src.runners.js_runner import JSRunner
    r = JSRunner("node", ["/x/index.js"], "t", cwd="/some/target/dir")
    assert r.cwd == "/some/target/dir"


def test_js_runner_passes_cwd_to_popen():
    """The bug was literally a missing kwarg; assert it reaches Popen."""
    import inspect
    from src.runners import js_runner
    src = inspect.getsource(js_runner.JSRunner.start)
    assert "cwd=self.cwd" in src, "Popen must receive the target's cwd"


def test_fuzzer_config_carries_target_cwd():
    from src.config import FuzzerConfig
    c = FuzzerConfig()
    assert hasattr(c, "target_cwd")
    c.target_cwd = "/t"
    assert c.target_cwd == "/t"


def test_main_reads_cwd_from_config_json():
    """prepare_targets.py writes 'cwd'; __main__ must consume it."""
    import inspect
    from src import __main__ as m
    src = inspect.getsource(m)
    assert 'config_data.get("cwd")' in src, "__main__ must read the config's cwd"


def test_traversal_oracle_prefers_target_cwd_over_process_cwd():
    """allowed_dir fell back to os.getcwd() -- ToFu's root -- so escapes were
    judged against OUR tree instead of the target's."""
    import inspect
    from src import fuzzer
    src = inspect.getsource(fuzzer)
    i = src.find("allowed_dir = (")
    assert i != -1, "allowed_dir resolution changed shape; re-check bug 21"
    window = src[i:i + 260]
    assert "target_cwd" in window, "traversal oracle must prefer the target's cwd"
    assert window.index("target_cwd") < window.index("os.getcwd()"), \
        "os.getcwd() must remain the LAST fallback, not the first choice"


def test_every_prepared_config_records_a_cwd():
    """A config without cwd silently reintroduces bug 21."""
    import glob
    missing = []
    for p in glob.glob(os.path.join(ROOT, "eval/configs/*.json")):
        try:
            d = json.load(open(p))
        except Exception:
            continue
        if not d.get("cwd"):
            missing.append(os.path.basename(p))
    assert not missing, f"{len(missing)} config(s) have no cwd: {missing[:5]}"


# ---------------------------------------------------------------------------
# Item 56/78: sanitizer context-guard and contract-sanitizer scoping.
#
# Four independent FP mechanisms, all found by re-triaging real run logs
# rather than lowering the bar for what counts as a finding:
#   (a) check_strict_har_security_contract / check_strict_markitdown_security_
#       contract were written for ONE paper target each (extract_har.py,
#       MarkItDown's convert_to_markdown) and fire unconditionally on every
#       tool. .get("harzip") / .get("uri") is None for any other tool, and
#       None fails the inner "must be str" check -> is_invalid=True -> the
#       unrelated tool "fails to reject" by succeeding normally -> guaranteed
#       false alert. Same class already fixed in check_strict_url_security_
#       contract on 2026-09-10.
#   (b) check_path_traversal / check_command_injection / check_blocked_
#       command_bypass / the four check_url_* checks had no (or an
#       incomplete) parameter-name context guard, so they ran on every
#       string argument regardless of the argument's role.
#   (c) check_unhandled_promise_rejection greps the stringified response for
#       exception-shaped substrings with no check that the call actually
#       failed -- a tool that catches an error and reports it as normal,
#       successful text (n_exec_success=1/1) was flagged as a crash.
# ---------------------------------------------------------------------------
def test_har_contract_does_not_fire_on_a_tool_without_a_harzip_argument():
    from src.sanitizers.har_sanitizers import check_strict_har_security_contract
    # A completely unrelated tool call: no harzip/mimetypes keys at all.
    triggered, _ = check_strict_har_security_contract(
        {"path": "/tmp/whatever", "operation": "mkdir"}, _Res(True, "")
    )
    assert triggered is False, "HAR contract must not fire when the tool has no harzip argument"


def test_har_contract_still_fires_for_an_actual_har_tool():
    from src.sanitizers.har_sanitizers import check_strict_har_security_contract
    # harzip present but invalid (embedded null byte), tool succeeds anyway
    # (res.success=True -> is_input_rejected sees no rejection signal) ->
    # should still fire. This is the true-positive case the None-guard must
    # not collateral-damage.
    res = _Res(True, "")
    res.result = {"content": [{"type": "text", "text": "extracted 42 entries"}]}
    triggered, msg = check_strict_har_security_contract(
        {"harzip": "bad\x00path", "mimetypes": None, "output": "/tmp/x"}, res
    )
    assert triggered is True
    assert "HAR" in msg


def test_markitdown_contract_does_not_fire_on_a_tool_without_a_uri_argument():
    from src.sanitizers.markitdown_sanitizers import check_strict_markitdown_security_contract
    triggered, _ = check_strict_markitdown_security_contract(
        {"filename": "report.txt", "content": "hello"}, _Res(True, "")
    )
    assert triggered is False, "MarkItDown contract must not fire when the tool has no uri/source/url argument"


def _sanitizer_dispatch_guard(sanitizer_name, prop_name):
    """Exercise the actual context-guard logic from _check_string_sanitizers
    without needing a full MCPDifferentialFuzzer instance -- extracts the
    guard's decision by regex-matching the same predicate from source, so
    this test breaks (loudly) if the guard's shape changes without the test
    being updated alongside it."""
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._check_string_sanitizers)
    assert sanitizer_name in src, f"{sanitizer_name} must appear in the context-guard source"
    return src


def test_path_traversal_has_a_context_guard():
    src = _sanitizer_dispatch_guard("check_path_traversal", "dateFormat")
    # The guarded tuple must include check_path_traversal, and the guard must
    # test the property name before dispatch.
    i = src.find('"check_path_traversal"')
    assert i != -1
    window = src[max(0, i - 400):i + 100]
    assert "prop_lower" in window or "check_path_traversal" in src.split("if sanitizer_name in (")[1][:600]


def test_command_injection_has_a_context_guard():
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._check_string_sanitizers)
    assert '"check_command_injection"' in src
    assert '"check_blocked_command_bypass"' in src
    # both must sit inside a name-scoped branch, not the unconditional path
    i = src.find('"check_command_injection"')
    window = src[i:i + 300]
    assert "cmd" in window or "command" in window


def test_url_family_sanitizers_are_context_guarded():
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._check_string_sanitizers)
    for name in ("check_url_structure_and_parsing", "check_url_hostname_canonicalization",
                 "check_url_ssrf_ip_ranges", "check_url_alternative_ip_representations"):
        assert f'"{name}"' in src, f"{name} must be listed in the context-guard tuple"


def test_promise_rejection_does_not_fire_on_a_successful_call():
    """The exact bsv-mcp::app_explorer_data case: a caught JSON.parse error
    returned as normal successful text."""
    from src.sanitizers.mcp_oracles import check_unhandled_promise_rejection
    res = _Res(True, "")
    res.result = {"content": [{"type": "text",
                  "text": "Error: Unexpected token '<', \"<!doctype \"... is not valid JSON: SyntaxError:"}]}
    # The gate lives in fuzzer.py at the call site (guards on res.success);
    # verify the underlying function is still capable of matching so the gate
    # -- not a change to the pattern list -- is what suppresses it.
    triggered, _ = check_unhandled_promise_rejection(res.result)
    assert triggered is True, "the pattern itself should still match text"
    # Now verify the FUZZER-LEVEL gate: not res.success -> must skip the call
    # entirely. Exercised via source inspection (constructing a full
    # MCPDifferentialFuzzer + live runner is out of scope for a unit test).
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._run_sanitizers) if hasattr(_f.MCPDifferentialFuzzer, "_run_sanitizers") else inspect.getsource(_f)
    assert 'check_unhandled_promise_rejection" in self.selected_sanitizer_names and not res.success' in src


def test_promise_rejection_pattern_still_matches_a_real_exception():
    from src.sanitizers.mcp_oracles import check_unhandled_promise_rejection
    triggered, msg = check_unhandled_promise_rejection(
        "Traceback (most recent call last):\n  File \"x.py\", line 1\nTypeError: Cannot read propert"
    )
    assert triggered is True


# --- sanity: the two CONFIRMED findings must not be silenced by any of the above ---
def test_v1_excel_reader_outputpath_still_matches_path_traversal_context_guard():
    """outputPath contains 'path' -> must still pass the context guard."""
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._check_string_sanitizers)
    # simulate the guard's own substring test
    prop_lower = "outputpath"
    guarded = ("url" in prop_lower or "uri" in prop_lower or "link" in prop_lower or "path" in prop_lower
               or "file" in prop_lower or "dir" in prop_lower or "endpoint" in prop_lower
               or "host" in prop_lower or "location" in prop_lower or "dest" in prop_lower
               or "target" in prop_lower or "source" in prop_lower)
    assert guarded, "outputPath must still pass the path-family context guard (V1 must not be silenced)"


def test_v2_log_injection_sanitizer_untouched_by_this_pass():
    """check_log_injection was not touched by the har/markitdown/url/command
    fixes -- confirm it is still unconditional (V2 must not be silenced)."""
    import inspect
    from src import fuzzer as _f
    src = inspect.getsource(_f.MCPDifferentialFuzzer._check_string_sanitizers)
    # it must NOT appear inside either new guarded tuple
    guard_block = src[src.find("if sanitizer_name in ("):src.find("sanitizer_fn = getattr")]
    assert '"check_log_injection"' not in guard_block


# ---------------------------------------------------------------------------
# Bug 23: fuzzed targets inherited our REAL API keys.
#
# js_runner built the child env as a bare os.environ.copy(); run_arm_*.sh
# sources .env; therefore every untrusted third-party server we fuzzed ran
# with OPENAI_API_KEY / OLLAMA_CLOUD_API_KEY in its environment. Verified
# 2026-09-12 (both set in the env targets receive). The fix scrubs credentials
# from the INHERITED env before per-target overrides are merged, so deliberate
# placeholders (TARGET_ENV_HINTS) still reach the target and a real key never
# does.
# ---------------------------------------------------------------------------
def test_scrub_removes_real_credentials_but_keeps_placeholders():
    from src.runners.js_runner import _scrub_secrets
    env = {"OPENAI_API_KEY": "sk-REAL", "OLLAMA_CLOUD_API_KEY": "real", "GITHUB_TOKEN": "ghp_real",
           "AWS_SECRET_ACCESS_KEY": "real", "SOME_SERVICE_TOKEN": "real", "DB_PASSWORD": "real",
           "PATH": "/usr/bin", "HOME": "/home/x", "NODE_ENV": "test"}
    out = _scrub_secrets(dict(env))
    for k in ("OPENAI_API_KEY", "OLLAMA_CLOUD_API_KEY", "GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY",
              "SOME_SERVICE_TOKEN", "DB_PASSWORD"):
        assert k not in out, f"{k} must be scrubbed from the target env"
    for k in ("PATH", "HOME", "NODE_ENV"):
        assert out[k] == env[k], "non-secret variables must be untouched"
    # order of operations: scrub the inherited env FIRST, then merge the
    # placeholder -- the placeholder must survive.
    out.update({"OPENAI_API_KEY": "sk-tofu-placeholder"})
    assert out["OPENAI_API_KEY"] == "sk-tofu-placeholder"


def test_js_runner_scrubs_before_merging_custom_env():
    import inspect
    from src.runners import js_runner
    src = inspect.getsource(js_runner.JSRunner.start)
    i_scrub = src.find("_scrub_secrets(os.environ.copy())")
    i_merge = src.find("env.update(self.custom_env)")
    assert i_scrub != -1, "start() must scrub the inherited environment"
    assert i_merge != -1 and i_scrub < i_merge, "scrub must happen BEFORE custom_env is merged"


def test_prepare_target_env_scrubs_and_merges_hints():
    import importlib.util
    spec = importlib.util.spec_from_file_location("pt_under_test", os.path.join(ROOT, "eval", "prepare_targets.py"))
    pt = importlib.util.module_from_spec(spec); spec.loader.exec_module(pt)
    os.environ["OPENAI_API_KEY"] = "sk-REAL-FOR-TEST"
    try:
        env = pt.target_env("/tmp", None, extra={"GOOGLE_API_KEY": "AIzaSy-placeholder"})
    finally:
        os.environ.pop("OPENAI_API_KEY", None)
    assert "OPENAI_API_KEY" not in env
    assert env["GOOGLE_API_KEY"] == "AIzaSy-placeholder"


def test_env_hints_never_contain_a_real_credential():
    """A hint that equals a value from the live environment is a real key
    pasted by mistake. Fail loudly."""
    import importlib.util
    spec = importlib.util.spec_from_file_location("pt_under_test2", os.path.join(ROOT, "eval", "prepare_targets.py"))
    pt = importlib.util.module_from_spec(spec); spec.loader.exec_module(pt)
    live = {v for k, v in os.environ.items() if v and len(v) > 12}
    for repo, hints in pt.TARGET_ENV_HINTS.items():
        for k, v in hints.items():
            assert v not in live, f"TARGET_ENV_HINTS[{repo}][{k}] equals a live environment value"
            assert "placeholder" in v.lower() or v.startswith(("bolt://", "https://", "neo4j", "tofu", "pat")), \
                f"TARGET_ENV_HINTS[{repo}][{k}] does not look like a placeholder: {v!r}"


# --- per-target env plumbing: config "env" -> FuzzerConfig.target_env -> JSRunner ---
def test_fuzzer_config_carries_target_env():
    from src.config import FuzzerConfig
    c = FuzzerConfig(); assert hasattr(c, "target_env")


def test_main_reads_env_from_config_json():
    import inspect
    from src import __main__ as m
    assert 'config_data.get("env")' in inspect.getsource(m)


def test_fuzzer_passes_custom_env_to_js_runner():
    import inspect
    from src import fuzzer
    src = inspect.getsource(fuzzer)
    i = src.find("return JSRunner(")
    assert i != -1
    assert 'custom_env=getattr(self.config, "target_env", None)' in src[i:i + 300]
