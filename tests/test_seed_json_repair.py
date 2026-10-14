"""Tolerant parsing of LLM seed replies (seed generation only, repair=True).

LLM-written adversarial seeds routinely contain invalid JSON escapes (Windows
traversal paths typed with single backslashes) and raw control characters (NUL
payloads). Seen on the second machine: roo-code-memory-bank append_memory_bank_entry
failed 4/4 attempts with 'Unterminated string' at the same offset. Repair keeps the
model's own content; the selection parser is unchanged (repair defaults to False).
"""
import pytest

llm = pytest.importorskip("src.llm")
X = llm._extract_json


def test_invalid_escapes_repaired():
    info = {}
    assert X(r'[{"path": "..\..\windows\win.ini"}]', expect=list, repair=True, info=info) \
        == [{"path": "..\\..\\windows\\win.ini"}]
    assert info["repaired"].startswith("escapes")


def test_valid_escape_pairs_kept():
    assert X('[{"p": "a\\\\b\\w"}]', expect=list, repair=True) == [{"p": "a\\b\\w"}]


def test_control_characters_accepted():
    info = {}
    assert X('[{"q": "a\x00b"}]', expect=list, repair=True, info=info) == [{"q": "a\x00b"}]
    assert info["repaired"] == "control_chars"


def test_salvage_keeps_parseable_objects():
    info = {}
    out = X('Here: [{"q": "ok"}, {"path": "C:\\"}, {"q": "fine"}] done', expect=list, repair=True, info=info)
    assert {"q": "ok"} in out and all(isinstance(x, dict) for x in out)


def test_default_behaviour_unchanged():
    with pytest.raises(ValueError):
        X(r'[{"path": "..\x"}]', expect=list)          # repair defaults to False


def test_clean_json_not_flagged():
    info = {}
    assert X('[{"a": 1}]', expect=list, repair=True, info=info) == [{"a": 1}]
    assert "repaired" not in info
