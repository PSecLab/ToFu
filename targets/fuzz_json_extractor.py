import sys
import os
from mcp.server.fastmcp import FastMCP

# Add tools-main/python to import path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "tools-main", "python"))
from json_extractor import extract_json_objects

mcp = FastMCP("JSON Extractor MCP Server")

@mcp.tool()
def extract_json(text: str) -> str:
    """
    Extracts valid JSON objects from raw text using a state machine parser.
    """
    try:
        results = extract_json_objects(text)
        return str(results)
    except Exception as e:
        # If an unhandled exception occurs, it will be raised here
        raise e

if __name__ == "__main__":
    mcp.run()
