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
        timeout_limit=15.0,
        unexpected_crashes=(
            "TypeError",
            "RangeError",
            "ReferenceError",
            "SyntaxError",
            "URIError",
            "unhandledRejection",
            "uncaughtException"
        )
    )

    # Configure the fuzzer to target compare_heapsnapshots
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[
            server_path,
            "--memoryDebugging=true",
            "--no-usage-statistics"
        ],
        target_tool="compare_heapsnapshots",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={
            "baseFilePath": {
                "extension": ".heapsnapshot"
            },
            "currentFilePath": {
                "extension": ".heapsnapshot"
            }
        },
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=[
            {
                "baseFilePath": "predefined_seed:sample.heapsnapshot",
                "currentFilePath": "predefined_seed:sample.heapsnapshot",
                "classIndex": 0
            }
        ]
    )

    # Run the fuzzing iteration
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()
