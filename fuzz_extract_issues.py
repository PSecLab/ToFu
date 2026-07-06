import sys
import os
from mcp.server.fastmcp import FastMCP

# Add tools-main/python to path
sys.path.append(os.path.join(os.path.dirname(__file__), "tools-main", "python"))
from extract_issues import extract_issue_numbers

mcp = FastMCP("Extract Issues MCP Server")

@mcp.tool()
def extract_issues(range_spec: str) -> str:
    """
    Extracts unique issue numbers from commit messages for a given git range (e.g. '1.0..HEAD').
    """
    try:
        return extract_issue_numbers(range_spec)
    except Exception as e:
        raise e

if __name__ == "__main__":
    mcp.run()
