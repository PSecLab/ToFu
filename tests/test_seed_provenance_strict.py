"""TOFU_REQUIRE_LLM_SEEDS: the per-repo deep campaign must fuzz only with seeds the
LLM generated. Cached seeds count only when tagged seeds_provenance == "llm";
anything else is regenerated live, and a failed live call raises instead of
silently falling back to the local mapping. Default behaviour is unchanged.

No network: an empty seed bank sends generate_seeds straight to its fallback
branch, so every path is exercised without calling a model.
"""
import json

import pytest

llm = pytest.importorskip("src.llm")

SENTINEL = [{"fallback": True}]
SCHEMA = {"type": "object", "properties": {"q": {"type": "string"}}}


def _handler(tmp_path, monkeypatch, cache_entry=None):
    h = object.__new__(llm.LLMHandler)          # skip __init__: no model client needed
    h.cache_dir, h.cache_key = str(tmp_path), "cfg"
    if cache_entry is not None:
        (tmp_path / "cfg.json").write_text(json.dumps(cache_entry))
    monkeypatch.setattr(h, "_load_seed_bank", lambda: {}, raising=False)
    monkeypatch.setattr(h, "_local_fallback_mapping", lambda *a, **k: SENTINEL, raising=False)
    return h


def _gen(h):
    return h.generate_seeds("t", "desc", SCHEMA, selected_sanitizers=[])


def test_default_keeps_fallback(tmp_path, monkeypatch):
    monkeypatch.delenv("TOFU_REQUIRE_LLM_SEEDS", raising=False)
    assert _gen(_handler(tmp_path, monkeypatch)) == SENTINEL


def test_default_replays_any_cached_seeds(tmp_path, monkeypatch):
    monkeypatch.delenv("TOFU_REQUIRE_LLM_SEEDS", raising=False)
    h = _handler(tmp_path, monkeypatch, {"seeds": [{"q": "a"}], "seeds_provenance": "fallback"})
    assert _gen(h) == [{"q": "a"}]


def test_strict_refuses_fallback(tmp_path, monkeypatch):
    monkeypatch.setenv("TOFU_REQUIRE_LLM_SEEDS", "1")
    with pytest.raises(llm.SeedProvenanceError):
        _gen(_handler(tmp_path, monkeypatch))


def test_strict_uses_llm_tagged_cache(tmp_path, monkeypatch):
    monkeypatch.setenv("TOFU_REQUIRE_LLM_SEEDS", "1")
    h = _handler(tmp_path, monkeypatch, {"seeds": [{"q": "llm"}], "seeds_provenance": "llm"})
    assert _gen(h) == [{"q": "llm"}]


@pytest.mark.parametrize("entry", [
    {"seeds": [{"q": "fb"}], "seeds_provenance": "fallback"},
    {"seeds": [{"q": "unproven"}]},                    # untagged = unknown provenance
])
def test_strict_regenerates_non_llm_cache(tmp_path, monkeypatch, entry):
    monkeypatch.setenv("TOFU_REQUIRE_LLM_SEEDS", "1")
    # cache is skipped -> live path -> empty bank -> must raise, never replay entry
    with pytest.raises(llm.SeedProvenanceError):
        _gen(_handler(tmp_path, monkeypatch, entry))
