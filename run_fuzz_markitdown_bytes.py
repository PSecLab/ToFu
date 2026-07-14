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
            os.path.join(os.path.dirname(__file__), "fuzz_markitdown.py")
        ],
        target_tool="convert_to_markdown", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        override_rules={
            "check_temp_file_leak": {"on_trigger": "allow_success_always"},
            "check_resource_exhaustion": {"on_trigger": "allow_success_always"},
            "check_xml_xxe": {"on_trigger": "allow_success_always"},
            "check_xml_bomb": {"on_trigger": "allow_success_always"}
        }
    )
    
    # Run for 10 minutes to allow Atheris to find interesting inputs/paths
    fuzzer.run(time_per_iteration=600)

if __name__ == "__main__":
    main()
