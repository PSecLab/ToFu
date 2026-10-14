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

    # Define a restricted dedicated workspace directory for DesktopCommanderMCP
    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "DesktopCommanderMCP")
    )

    config = FuzzerConfig(
        timeout_limit=10.0,
        allowed_workspace_dir=sandbox_dir,
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

    # Configure the fuzzer to target read_file of DesktopCommanderMCP with Introspection Path Traversal
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[server_path],
        target_tool="read_file",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "ollama"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_introspection_path_traversal": {},
            "check_file_access": {},
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "path": "package.json",
                "isUrl": False,
                "offset": 0,
                "length": 10
            },
            {
                "path": "../../../etc/passwd",
                "isUrl": False,
                "offset": 0,
                "length": 10
            }
        ]
    )

    # Run the fuzzing session
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
