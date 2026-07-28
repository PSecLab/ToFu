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
    python_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), ".venv", "bin", "python")
    )
    chrome_server_script = os.path.abspath(
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

    inspector = MCPInspector("node", [chrome_server_script])
    loop = asyncio.new_event_loop()
    try:
        tools = loop.run_until_complete(inspector.fetch_all_tools())
    except Exception as e:
        logger.error(f"Failed to inspect chrome-devtools-mcp tools: {e}")
        tools = [
            "navigate_page", "evaluate_script", "click", "fill", 
            "take_screenshot", "take_snapshot", "take_heapsnapshot", 
            "list_network_requests", "list_console_messages"
        ]

    logger.info(f"Discovered {len(tools)} chrome-devtools-mcp tools: {tools}")

    config = FuzzerConfig(
        timeout_limit=30.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {
            "url": "data:text/html,<html><body><button id='btn'>Click</button></body></html>",
            "script": "document.title",
            "selector": "button"
        },
        {
            "url": "data:text/html,<html><body><input type='text' id='inp'/></body></html>",
            "script": "console.log('fuzz')",
            "selector": "input",
            "value": "' OR '1'='1"
        }
    ]

    initial_tool = "evaluate_script" if "evaluate_script" in tools else tools[0]
    logger.info(f"Initializing 30-minute Chrome DevTools MCP Fuzzer with primary tool target: {initial_tool}")

    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[chrome_server_script],
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
