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
        timeout_limit=15.0,
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

    # Target start_search tool for ReDoS, Path Traversal, and Resource Exhaustion
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[server_path],
        target_tool="start_search",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_path_traversal": {},
            "check_wildcard_abuse_dos": {}
        },
        predefined_seeds=[
            {
                "path": ".",
                "pattern": "package",
                "searchType": "files",
                "ignoreCase": True,
                "maxResults": 50,
                "literalSearch": True
            },
            {
                "path": "../../../",
                "pattern": "(a+)+$",
                "searchType": "content",
                "ignoreCase": True,
                "maxResults": 100,
                "literalSearch": False
            }
        ]
    )

    # Run the fuzzing session for 30 minutes (1800 seconds)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
