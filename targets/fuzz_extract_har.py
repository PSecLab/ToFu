import os
import sys
import logging

# Add workspace root to sys.path
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
            "extract_har.py"
        )
    )

    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "tools-main")
    )

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
        dependencies_to_instrument=["extract_har", "zipfile", "json", "urllib"],
        unexpected_crashes=(
            "TypeError",
            "KeyError",
            "IndexError",
            "AttributeError",
            "UnboundLocalError",
            "AssertionError"
        )
    )


    # Predefined seeds targeting extract_har functionality
    predefined_seeds = [
        {"harzip": "sample.zip", "mimetypes": ["application/json"], "output": sandbox_dir},
        {"harzip": "../../etc/passwd", "mimetypes": ["text/html"], "output": sandbox_dir},
        {"harzip": "sample.zip", "mimetypes": ["image/svg+xml"], "output": os.path.join(sandbox_dir, "out")},
        {"harzip": "sample.zip", "mimetypes": ["text/css"], "paths": True, "pretty_json": True, "output": sandbox_dir}
    ]

    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus_extract_har")
    )
    tool_corpus_dir = os.path.join(corpus_base_dir, "corpus_extract_har")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="extract_har",
        corpus_dir=tool_corpus_dir,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        file_backed_params={
            "harzip": {
                "extension": ".zip",
                "prefix": "fuzz_har_input_"
            }
        },
        config=config,
        override_rules={
            "check_strict_har_security_contract": {},
            "check_harzip_integrity": {},
            "check_har_path_traversal": {},
            "check_har_url_path_security": {},
            "check_har_mimetype_security": {},
            "check_file_access": {},
            "check_introspection_path_traversal": {},
            "check_directory_jailbreak_write": {},
            "check_introspection_symlink_following": {},
            "check_introspection_data_amplification": {},
            "check_introspection_insecure_file_permissions": {},
            "check_introspection_temp_file_leak": {},
            "check_introspection_incomplete_cleanup": {},
            "check_unrestricted_file_upload": {},
            "check_invalid_json": {},
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds
    )

    import argparse
    parser = argparse.ArgumentParser(description="Fuzz extract_har")
    parser.add_argument("--time", type=int, default=300, help="Duration in seconds (default: 300)")
    args = parser.parse_args()

    fuzzer.run(time_per_iteration=args.time)

if __name__ == "__main__":
    main()
