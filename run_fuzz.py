import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    # Configure fuzzer to target the Python FastMCP server in fuzz_http_check.py
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,
        args=[
            os.path.join(os.path.dirname(__file__), "fuzz_http_check.py")
        ],
        target_tool="check_http_url", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z")
    )
    
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()