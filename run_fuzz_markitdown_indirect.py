import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    # Configure fuzzer to target the Python FastMCP server in markitdown-mcp package
    # with the 'uri' parameter backed by a temporary file containing fuzzed bytes.
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,
        args=[
            os.path.join(os.path.dirname(__file__), "markitdown", "packages", "markitdown-mcp", "src", "markitdown_mcp", "__main__.py")
        ],
        target_tool="convert_to_markdown", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        override_rules={
            "check_local_file_uri": {"on_trigger": "allow_success_always"},
            "check_path_traversal": {"on_trigger": "allow_success_always"},
            "check_unsafe_url_ssrf": {"on_trigger": "allow_success_always"},
            "check_html_xss": {"on_trigger": "allow_success_always"},
            "check_temp_file_leak": {"on_trigger": "allow_success_always"},
            "check_resource_exhaustion": {"on_trigger": "allow_success_always"}
        },
        file_backed_params={
            "uri": {
                "scheme": "file://",
                "extensions": [".txt", ".html", ".xml", ".json", ".ipynb", ".pdf", ".docx", ".xlsx", ".pptx", ".zip", ".epub"]
            }
        }
    )
    
    fuzzer.run(time_per_iteration=3600)

if __name__ == "__main__":
    main()
