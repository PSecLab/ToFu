import pytest
from mcp_fuzzer.runners import PythonRunner, JSRunner, RunnerResult


def dummy_tool(a: int, b: str):
    if a == 0:
        raise ValueError("a cannot be zero")
    return f"{b} -> {a}"


def test_python_runner(tmp_path):
    # Create a temporary python module to run tests against
    dummy_code = """
def dummy_tool(a: int, b: str):
    if a == 0:
        raise ValueError("a cannot be zero")
    return f"{b} -> {a}"
"""
    module_file = tmp_path / "dummy_module.py"
    module_file.write_text(dummy_code)

    # Instantiate PythonRunner targeting our dummy module file
    runner = PythonRunner(command="python", args=[str(module_file)], target_tool="dummy_tool")
    runner.start()

    # Test execution success
    res_success = runner.execute({"a": 10, "b": "hello"})
    assert res_success.success is True
    assert len(res_success.coverage) > 0
    assert any("dummy_module.py" in cov for cov in res_success.coverage)

    # Test execution failure
    res_fail = runner.execute({"a": 0, "b": "hello"})
    assert res_fail.success is False
    assert "ValueError" in res_fail.error


def test_js_runner():
    # Test JSRunner mock interface
    runner = JSRunner(command="node", args=["index.js"], target_tool="some_tool")
    runner.start()
    res = runner.execute({"arg": "val"})
    assert res.success is True
    assert "server.js:42" in res.coverage
    runner.stop()


def test_check_invalid_json():
    from mcp_fuzzer.sanitizers import check_invalid_json
    # Test valid JSON string (should return False - not an injection/invalid structure)
    assert check_invalid_json('{"key": "value"}') is False
    assert check_invalid_json('[1, 2, 3]') is False

    # Test invalid JSON string resembling JSON (should return True - flagged as malformed JSON)
    assert check_invalid_json('{"key": }') is True
    assert check_invalid_json('{"key": "unclosed') is True
    assert check_invalid_json('[1, 2,') is True

    # Test regular non-JSON text (should return False)
    assert check_invalid_json('hello world') is False
    assert check_invalid_json('12345') is False

