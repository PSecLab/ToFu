import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,
        args=[
            os.path.join(os.path.dirname(__file__), "fuzz_markitdown_files.py")
        ],
        target_tool="convert_file_content", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        override_rules={
            "check_local_file_uri": {"on_trigger": "allow_success_always"},
            "check_path_traversal": {"on_trigger": "allow_success_always"},
            "check_unsafe_url_ssrf": {"on_trigger": "allow_success_always"}
        }
    )
    
    fuzzer.run(time_per_iteration=300)

if __name__ == "__main__":
    main()
