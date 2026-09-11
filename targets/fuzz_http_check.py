import os
import sys
import logging

# Add workspace root to sys.path so src imports work properly
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    python_path = sys.executable
    server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "tools-main",
            "python",
            "http_check.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "tools-main")
    )

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
        dependencies_to_instrument=["http_check", "urllib", "requests", "ipaddress"],
        unexpected_crashes=(
            "TypeError",
            "KeyError",
            "IndexError",
            "AttributeError",
            "UnboundLocalError",
            "AssertionError"
        )
    )


    # Predefined seeds targeting http_check functionality
    predefined_seeds = [
        {"url": "https://example.com"},
        {"url": "http://127.0.0.1"},
        {"url": "http://localhost:8000"},
        {"url": "file:///etc/passwd"},
        {"url": "https://httpbin.org/get"}
    ]

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_http_check")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, "corpus_http_check")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="check_url_features",
        corpus_dir=tool_corpus_dir,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        config=config,
        override_rules={
            "check_strict_url_security_contract": {},
            "check_file_access": {},
            "check_introspection_path_traversal": {},
            "check_untrusted_deserialization": {},
            "check_introspection_command_injection": {},
            "check_introspection_sql_injection": {},
            "check_unrestricted_file_upload": {},
            "check_introspection_code_injection": {},
            "check_introspection_ssrf": {},
            "check_introspection_temp_file_leak": {},
            "check_introspection_log_injection": {},
            "check_introspection_sensitive_data_logging": {},
            "check_introspection_ssl_verification": {},
            "check_introspection_sensitive_file_access": {},
            "check_introspection_unrestricted_ip_binding": {},
            "check_introspection_redos": {},
            "check_introspection_blocking_event_loop_call": {},
            "check_introspection_hardcoded_credentials": {},
            "check_introspection_weak_hash": {},
            "check_introspection_weak_prng": {},
            "check_introspection_nonce_reuse": {},
            "check_introspection_unverified_code_download": {},
            "check_introspection_xxe": {},
            "check_introspection_data_amplification": {},
            "check_introspection_argument_injection": {},
            "check_introspection_csv_formula_injection": {},
            "check_introspection_symlink_following": {},
            "check_introspection_insecure_temp_permissions": {},
            "check_introspection_sensitive_error_leak": {},
            "check_introspection_reachable_assertion": {},
            "check_introspection_cleartext_sensitive_storage": {},
            "check_introspection_cleartext_sensitive_transmission": {},
            "check_introspection_failed_init_non_exit": {},
            "check_introspection_incomplete_cleanup": {},
            "check_introspection_unchecked_loop_condition": {},
            "check_introspection_memory_access_violation": {},
            "check_introspection_divide_by_zero": {},
            "check_introspection_insecure_file_permissions": {},
            "check_introspection_deadlock": {},
            "check_introspection_file_descriptor_leak": {},
            "check_introspection_prototype_pollution": {},
            "check_introspection_external_config_control": {},
            "check_introspection_format_string": {},
            "check_introspection_type_confusion": {},
            "check_introspection_cross_session_data_leak": {},
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds
    )

    import argparse
    parser = argparse.ArgumentParser(description="Fuzz http_check")
    parser.add_argument("--time", type=int, default=300, help="Duration in seconds (default: 300)")
    args = parser.parse_args()

    fuzzer.run(time_per_iteration=args.time)

if __name__ == "__main__":
    main()
