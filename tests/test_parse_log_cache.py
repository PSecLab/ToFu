"""Regression tests: parse_log on LLM replay-cache runs (2026-09-23).

parse_log only knew LLM_SELECTION_OK / LLM_SELECTION_FAILED, so every run the
cache served (it logs *_CACHE_HIT and makes no LLM call) was indexed
llm_selection=unknown with no n_selected -- on every deep24/repo24 config.

Fixtures are VERBATIM VM logs (tests/data/parse_log_real/README.md), not
hand-written: a fixture written from reading the code is how the original
never-matching keyword set shipped (CLAUDE.md).
"""
import importlib.util
import io
import json
import os
import contextlib

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA = os.path.join(ROOT, "tests", "data", "parse_log_real")


def _load(name, relpath):
    spec = importlib.util.spec_from_file_location(name, os.path.join(ROOT, relpath))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


run_eval = _load("run_eval_cache_test", "eval/run_eval.py")
gen_llm_cache = _load("gen_llm_cache_test", "eval/gen_llm_cache.py")

KEYS = ("llm_selection", "llm_cached", "llm_n_selected", "llm_n_dropped",
        "llm_seeds", "llm_seeds_provenance", "llm_n_seeds")

# expected values read off each real log by hand
CASES = {
    # every cache-hit log on the VM before llm.py logged provenance
    "cachehit_oldformat_noprov.txt": dict(
        llm_selection="ok", llm_cached=True, llm_n_selected=5, llm_n_dropped=None,
        llm_seeds="cached", llm_seeds_provenance="unknown", llm_n_seeds=10),
    "cachehit_prov_llm.txt": dict(
        llm_selection="ok", llm_cached=True, llm_n_selected=5, llm_n_dropped=None,
        llm_seeds="ok", llm_seeds_provenance="llm", llm_n_seeds=9),
    # a retro-built entry holding FALLBACK seeds must not read as LLM seeds
    "cachehit_prov_fallback.txt": dict(
        llm_selection="ok", llm_cached=True, llm_n_selected=2, llm_n_dropped=None,
        llm_seeds="fallback", llm_seeds_provenance="fallback", llm_n_seeds=9),
    "cachehit_prov_unknown.txt": dict(
        llm_selection="ok", llm_cached=True, llm_n_selected=2, llm_n_dropped=None,
        llm_seeds="cached", llm_seeds_provenance="unknown", llm_n_seeds=12),
    # live runs must parse exactly as before
    "live_llm_ok.txt": dict(
        llm_selection="ok", llm_cached=False, llm_n_selected=5, llm_n_dropped=0,
        llm_seeds="ok", llm_seeds_provenance=None, llm_n_seeds=9),
    "live_seedgen_fallback.txt": dict(
        llm_selection="ok", llm_cached=False, llm_n_selected=3, llm_n_dropped=0,
        llm_seeds="fallback", llm_seeds_provenance=None, llm_n_seeds=None),
}


def _read(name):
    with open(os.path.join(DATA, name), errors="ignore") as f:
        return f.read()


@pytest.mark.parametrize("name", sorted(CASES))
def test_parse_log_real_logs(name):
    rec = run_eval.parse_log(_read(name))
    assert {k: rec.get(k) for k in KEYS} == CASES[name]


def test_summary_counts_cached_runs_and_flags_unknown_seed_provenance():
    recs = [run_eval.parse_log(_read(n)) for n in sorted(CASES)]
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        run_eval.summarize(recs)
    out = buf.getvalue()
    assert "LLM sanitizer selection: ok=6" in out
    assert "LLM seed generation:     cached=2, fallback=2, ok=2" in out
    assert "4/6 run(s) made no LLM call" in out
    assert "2 run(s) replayed cached seeds of UNKNOWN provenance" in out
    # the all-fallback alarm must not fire when selection did succeed
    assert "LLM selection never succeeded" not in out


def test_gen_llm_cache_provenance_from_real_logs(tmp_path):
    assert gen_llm_cache.seeds_provenance(os.path.join(DATA, "live_llm_ok.txt")) == "llm"
    assert gen_llm_cache.seeds_provenance(os.path.join(DATA, "live_seedgen_fallback.txt")) == "fallback"
    # a run that itself replayed a tagged entry inherits that entry's tag
    assert gen_llm_cache.seeds_provenance(os.path.join(DATA, "cachehit_prov_fallback.txt")) == "fallback"
    assert gen_llm_cache.seeds_provenance(os.path.join(DATA, "cachehit_oldformat_noprov.txt")) == "unknown"
    assert gen_llm_cache.seeds_provenance(str(tmp_path / "missing.log")) == "unknown"


def test_backfill_is_dry_run_by_default_and_never_overwrites(tmp_path):
    cache, logs = tmp_path / "cache", tmp_path / "logs"
    cache.mkdir(); logs.mkdir()
    (logs / "a.log").write_text(_read("live_seedgen_fallback.txt"))
    (logs / "b.log").write_text(_read("live_llm_ok.txt"))
    (cache / "a.json").write_text(json.dumps({"seeds": [{}]}))
    (cache / "b.json").write_text(json.dumps({"seeds": [{}], "seeds_provenance": "fallback"}))
    (cache / "c.json").write_text(json.dumps({"selected_sanitizers": []}))

    counts = gen_llm_cache.backfill_provenance(str(cache), str(logs), write=False)
    assert counts["fallback"] == 1
    assert "seeds_provenance" not in json.loads((cache / "a.json").read_text())

    gen_llm_cache.backfill_provenance(str(cache), str(logs), write=True)
    assert json.loads((cache / "a.json").read_text())["seeds_provenance"] == "fallback"
    # an existing tag is kept even though b.log says "llm"
    assert json.loads((cache / "b.json").read_text())["seeds_provenance"] == "fallback"
