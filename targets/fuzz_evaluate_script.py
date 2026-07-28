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

    # We catch critical Node runtime issues and exceptions
    config = FuzzerConfig(
        timeout_limit=45.0,
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

    # Target evaluate_script tool for sandbox bypass / path traversal
    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[
            server_path,
            "--no-usage-statistics",
            "--browserUrl=http://127.0.0.1:9222"
        ],

        target_tool="evaluate_script",
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={}, 
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {},
            "check_path_traversal": {},
            "check_directory_jailbreak_write": {},
            "check_local_file_uri": {}
        },

        predefined_seeds=[
            # Seed 1: Basic JS function returning titile, saving to standard temp file name
            {
                "function": "() => document.title",
                "filePath": "output.json",
                "dialogAction": "accept"
            },
            # Seed 2: Attempting SSRF / fetch via evaluated script
            {
                "function": "async () => { return await fetch('http://127.0.0.1:8080/').then(r => r.text()); }",
                "filePath": "net_output.json",
                "dialogAction": "accept"
            },
            # Seed 3: Path traversal attempt via filePath argument
            {
                "function": "() => ({ status: 'pwned' })",
                "filePath": "../../../../../etc/passwd",
                "dialogAction": "accept"
            },
            # Seed 4: Prototype pollution/access escape attempt in function context
            {
                "function": "() => { return Object.getPrototypeOf(this); }",
                "filePath": "proto.json",
                "dialogAction": "accept"
            }
        ]
    )

    # Run the fuzzing session for 45 minutes (2700 seconds)
    fuzzer.run(time_per_iteration=2700)


if __name__ == "__main__":
    main()
