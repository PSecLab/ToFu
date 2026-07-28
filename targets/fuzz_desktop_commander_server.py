import os
import sys
import logging
import random
import asyncio

# Add workspace root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig
from mcp_fuzzer.client import MCPInspector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    desktop_server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "DesktopCommanderMCP",
            "dist",
            "index.js"
        )
    )

    inspector = MCPInspector("node", [desktop_server_script])
    loop = asyncio.new_event_loop()
    try:
        tools = loop.run_until_complete(inspector.fetch_all_tools())
    except Exception as e:
        logger.error(f"Failed to inspect DesktopCommanderMCP tools: {e}")
        tools = [
            "read_file", "write_file", "list_directory", "create_directory", 
            "start_search", "get_file_info", "edit_block", "start_process", 
            "read_process_output", "interact_with_process", "kill_process"
        ]

    logger.info(f"Discovered {len(tools)} DesktopCommanderMCP tools: {tools}")

    config = FuzzerConfig(
        timeout_limit=30.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {
            "path": "/tmp/test.txt",
            "content": "Sample desktop commander text",
            "pattern": "Sample"
        },
        {
            "command": "echo 'fuzzing desktop commander'",
            "path": "../../../etc/passwd"
        }
    ]

    initial_tool = "read_file" if "read_file" in tools else tools[0]
    logger.info(f"Initializing 30-minute DesktopCommanderMCP Fuzzer with primary tool target: {initial_tool}")

    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[desktop_server_script],
        target_tool=initial_tool,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={},
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds
    )

    # Run 30-minute campaign (1800 seconds)
    fuzzer.run(time_per_iteration=1800)

if __name__ == "__main__":
    main()
