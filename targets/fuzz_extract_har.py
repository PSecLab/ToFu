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

    logger.info("Initializing fuzzer for tools-main (extract_har.py) for 10 minutes...")

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool="extract_har",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={"harzip": "sample.zip"},
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

    # Run for 15 minutes (900 seconds) as requested
    fuzzer.run(time_per_iteration=900)

if __name__ == "__main__":
    main()
