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
    # Path to the compiled chrome-devtools-mcp server entrypoint
    server_path = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "chrome-devtools-mcp",
            "build",
            "src",
            "bin",
            "chrome-devtools-mcp.js"
        )
    )

    config = FuzzerConfig(
        timeout_limit=5.0,
        unexpected_crashes=(
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "URIError"
        )
    )

    # We do NOT specify "filePath" in file_backed_params.
    # This forces the fuzzer to mutate the filePath string argument directly (e.g. paths, URLs, traversal).
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[
            server_path,
            "--memoryDebugging=true",
            "--no-usage-statistics"
        ],
        target_tool="get_heapsnapshot_details",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_local_file_uri": {},
            "check_unsafe_url_ssrf": {}
        },
        predefined_seeds=[
            {
                "filePath": "/nonexistent/path/to/test.heapsnapshot",
                "filterName": "objectsRetainedByDetachedDomNodes",
                "pageIdx": 0,
                "pageSize": 50
            },
            {
                "filePath": "http://127.0.0.1:8080/exploit.heapsnapshot",
                "filterName": "objectsRetainedByDetachedDomNodes",
                "pageIdx": 0,
                "pageSize": 50
            }
        ]
    )

    # Run the fuzzing iteration
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()
