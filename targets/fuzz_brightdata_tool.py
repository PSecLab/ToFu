import os
import sys
import logging
import asyncio

# Add workspace root to sys.path
sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from mcp_fuzzer import MCPDifferentialFuzzer
from mcp_fuzzer.config import FuzzerConfig
from mcp_fuzzer.client import MCPInspector
from mcp import StdioServerParameters

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def main():
    server_script = os.path.abspath(
        os.path.join(
            os.path.dirname(os.path.dirname(__file__)),
            "third_party",
            "brightdata-mcp",
            "server.js"
        )
    )

    env = {
        "API_TOKEN": "dummy_fuzz_token_12345",
        "PRO_MODE": "true",
        "WEB_UNLOCKER_ZONE": "dummy_zone",
        "BROWSER_ZONE": "dummy_zone",
        "PATH": os.environ.get("PATH", "")
    }

    inspector = MCPInspector("node", [server_script], env=env)

    loop = asyncio.new_event_loop()
    try:
        tools = loop.run_until_complete(inspector.fetch_all_tools())
    except Exception as e:
        logger.error(f"Failed to inspect brightdata-mcp tools: {e}")
        tools = []

    logger.info(f"Discovered {len(tools)} brightdata-mcp tools: {tools}")

    config = FuzzerConfig(
        timeout_limit=30.0,
        unexpected_crashes=(
            "TypeError", "ValueError", "KeyError", "IndexError", 
            "AttributeError", "UnboundLocalError", "AssertionError"
        )
    )

    predefined_seeds = [
        {
            "query": "brightdata mcp fuzzing",
            "url": "https://example.com",
            "engine": "google"
        },
        {
            "query": "' OR '1'='1",
            "url": "file:///etc/passwd",
            "engine": "bing"
        }
    ]

    target_tool = os.environ.get("FUZZ_TARGET_TOOL", "search_engine")
    if target_tool not in tools and tools:
        logger.warning(f"Target tool '{target_tool}' not found in tools list. Using first discovered tool '{tools[0]}'.")
        target_tool = tools[0]

    dict_path = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "dictionaries", "brightdata.dict")
    )
    logger.info(f"Initializing 30-minute Bright Data MCP Fuzzer for target tool '{target_tool}' with dict: {dict_path}")

    def runner_factory(tool):
        from mcp_fuzzer.runners import JSRunner
        return JSRunner("node", [server_script], tool, custom_env=env)

    fuzzer = MCPDifferentialFuzzer(
        command="node",
        args=[server_script],
        target_tool=target_tool,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        file_backed_params={},
        config=config,
        override_rules={
            "check_unexpected_crash": {},
            "check_resource_exhaustion": {}
        },
        predefined_seeds=predefined_seeds,
        metadata_provider=inspector,
        runner_factory=runner_factory
    )

    # Run 1-hour campaign (3600 seconds)
    fuzzer.run(time_per_iteration=3600)

if __name__ == "__main__":
    main()
