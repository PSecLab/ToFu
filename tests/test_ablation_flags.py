"""Ablation switches (eval/run_ablation.sh, 2026-09-28). Each must remove exactly one
ToFu stage, and a misspelt switch must fail loudly -- a silent no-op would run the
full-ToFu arm under an ablation's name. No network: LLMHandler is built without
__init__, as in test_seed_provenance_strict.py.
"""
import importlib.util
import json
import logging
import os
import types

import pytest

llm = pytest.importorskip("src.llm")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}}}
AVAIL = {"check_a": "", "check_unexpected_crash": "", "check_file_access": ""}
SENTINEL = [{"fallback": True}]
ENV = ("TOFU_NO_LLM", "TOFU_NO_LLM_SEEDS", "TOFU_NO_SEEDS", "TOFU_NO_LLM_SANITIZERS",
       "TOFU_ORACLE_SHADOW", "TOFU_LLM_CACHE_READONLY")


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    for k in ENV:
        monkeypatch.delenv(k, raising=False)


def _handler(tmp_path, monkeypatch, cache_entry=None):
    h = object.__new__(llm.LLMHandler)
    h.cache_dir, h.cache_key = str(tmp_path), "cfg"
    if cache_entry is not None:
        (tmp_path / "cfg.json").write_text(json.dumps(cache_entry))
    monkeypatch.setattr(h, "_load_seed_bank", lambda: {}, raising=False)
    monkeypatch.setattr(h, "_local_fallback_mapping", lambda *a, **k: SENTINEL, raising=False)
    return h


def test_no_llm_seeds_uses_fallback_even_with_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("TOFU_NO_LLM_SEEDS", "1")
    h = _handler(tmp_path, monkeypatch, {"seeds": [{"q": "llm"}], "seeds_provenance": "llm"})
    assert h.generate_seeds("t", "d", SCHEMA, selected_sanitizers=[]) == SENTINEL


def test_no_llm_seeds_keeps_cached_selection(tmp_path, monkeypatch):
    monkeypatch.setenv("TOFU_NO_LLM_SEEDS", "1")
    h = _handler(tmp_path, monkeypatch, {"selected_sanitizers": ["check_a"], "rules": {}})
    sel, _ = h.select_sanitizers("t", "d", SCHEMA, AVAIL)
    assert sel == ["check_a"]


def test_mandatory_and_all_modes(tmp_path, monkeypatch):
    h = _handler(tmp_path, monkeypatch, {"selected_sanitizers": ["check_a"], "rules": {}})
    monkeypatch.setenv("TOFU_NO_LLM_SANITIZERS", "mandatory")
    sel, rules = h.select_sanitizers("t", "d", SCHEMA, AVAIL)
    assert set(sel) == {"check_unexpected_crash", "check_file_access"} and rules == {}
    monkeypatch.setenv("TOFU_NO_LLM_SANITIZERS", "all")
    sel, _ = h.select_sanitizers("t", "d", SCHEMA, AVAIL)
    assert sel == list(AVAIL)


def test_bad_sanitizer_mode_raises(monkeypatch):
    monkeypatch.setenv("TOFU_NO_LLM_SANITIZERS", "1")
    with pytest.raises(ValueError):
        llm._no_llm_sanitizers()


def test_cache_readonly_never_writes(tmp_path, monkeypatch):
    monkeypatch.setenv("TOFU_LLM_CACHE_READONLY", "1")
    h = _handler(tmp_path, monkeypatch)
    h._cache_update(seeds=[{"q": 1}])
    assert not (tmp_path / "cfg.json").exists()


def _run_eval():
    spec = importlib.util.spec_from_file_location("run_eval_abl", os.path.join(ROOT, "eval", "run_eval.py"))
    m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    return m


def test_shadow_line_round_trips_and_is_not_a_finding(monkeypatch, caplog):
    fz = pytest.importorskip("src.fuzzer")
    f = object.__new__(fz.MCPDifferentialFuzzer)
    f.selected_sanitizer_names, f.selected_sanitizer_rules, f.target_tool_name = ["check_path_traversal"], {}, "t"
    res = types.SimpleNamespace(success=False, result="", error="boom")
    args = {"path": "../../../../etc/passwd"}
    assert f._check_string_sanitizers(args, res) == (False, [], "")       # gate on: nothing
    with caplog.at_level(logging.INFO):
        f._log_shadow_ungated(args, res)
        f._log_shadow_ungated(args, res)                                    # deduped per tool
    lines = [r.getMessage() for r in caplog.records if "ORACLE_SHADOW_UNGATED" in r.getMessage()]
    assert len(lines) == 1
    rec = _run_eval().parse_log("\n".join(lines))
    assert rec["shadow_ungated_sanitizers"] == ["check_path_traversal"]
    assert rec["finding_hits"] == 0 and rec["triggered_sanitizers"] == []


def test_two_arg_sanitizer_is_not_a_string_contract():
    fz = pytest.importorskip("src.fuzzer")
    from src import sanitizers
    assert not fz._takes_a_string(sanitizers.check_reflected_output)
    assert fz._takes_a_string(sanitizers.check_path_traversal)


def test_all_sanitizers_selected_does_not_raise():
    """allsan arm: every AVAILABLE_SANITIZERS name in the string loop on a successful
    execution must neither raise nor kill the target (2026-09-28 TypeError)."""
    fz = pytest.importorskip("src.fuzzer")
    from src import sanitizers
    f = object.__new__(fz.MCPDifferentialFuzzer)
    f.selected_sanitizer_names = list(sanitizers.AVAILABLE_SANITIZERS)
    f.selected_sanitizer_rules, f.target_tool_name = {}, "t"
    res = types.SimpleNamespace(success=True, result="ok", error=None)
    for v in ("../../etc/passwd", "http://127.0.0.1/", "a\r\nb", "x" * 5000, ""):
        f._check_string_sanitizers({"path": v, "url": v, "cmd": v}, res)
