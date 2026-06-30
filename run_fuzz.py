import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    # Example if your MCP Python server is executable via a script
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,  # Uses the current Python interpreter
        args=["fuzz_json_extractor.py"], # ["path/to/server.py"]
        target_tool="extract_json", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z")
    )
    
    # max_iterations is ignored because Atheris runs on the main process with its own time limit (time_per_iteration)
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()