import os
import sys

# Add workspace root to the Python import path to resolve mcp_fuzzer
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

import logging
from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    server_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "DesktopCommanderMCP",
            "dist",
            "index.js"
        )
    )

    config = FuzzerConfig(
        timeout_limit=10.0,
        unexpected_crashes=(
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "URIError",
            "unhandledRejection",
            "uncaughtException",
            "AssertionError"
        )
    )

    # Configure the fuzzer to target write_file of DesktopCommanderMCP
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[server_path],
        target_tool="write_file",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_directory_jailbreak_write": {},
            "check_path_traversal": {}
        },
        predefined_seeds=[
            {
                "path": "/tmp/fuzz_test_output.txt",
                "content": "Sample content for write test",
                "mode": "rewrite"
            },
            {
                "path": "../../../tmp/fuzz_escape.txt",
                "content": "Escape attempt content",
                "mode": "rewrite"
            }
        ]
    )

    # Run the fuzzing session
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()
