"""check_introspection_ssrf must require the contacted host to come from the fuzzed
input (attacker-controlled), else it is the tool's own default backend, not SSRF.
2026-09-26: 140 backend-dial false positives rested only on this tracer."""
import importlib.util, os
spec = importlib.util.spec_from_file_location(
    "intro", os.path.join(os.path.dirname(__file__), "..", "src", "sanitizers", "introspection.py"))
intro = importlib.util.module_from_spec(spec); spec.loader.exec_module(intro)
ssrf = intro.check_introspection_ssrf
LOOPBACK = [{"host": "127.0.0.1", "port": 8500}]

def test_host_from_input_fires():
    assert ssrf(LOOPBACK, {"url": "http://127.0.0.1:8500/x"})[0]

def test_backend_dial_suppressed():
    assert not ssrf(LOOPBACK, {"query": "hello", "limit": 5})[0]
    assert not ssrf([{"host": "127.0.0.1", "port": 7700}], {"q": "term"})[0]      # meilisearch default
    assert not ssrf([{"host": "169.254.169.254", "port": 80}], {"bucket": "b"})[0]  # boto3 IMDS

def test_no_tool_input_keeps_old_behaviour():
    assert ssrf(LOOPBACK)[0]

def test_public_host_never_flags():
    assert not ssrf([{"host": "api.github.com", "port": 443}], {"url": "http://127.0.0.1"})[0]
