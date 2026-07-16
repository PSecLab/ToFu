import sys
import os
from mcp.server.fastmcp import FastMCP

# Add tools-main/python to path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "tools-main", "python"))
from http_check import check_url_features

mcp = FastMCP("HTTP Check MCP Server")

@mcp.tool()
def check_http_url(url: str) -> str:
    """
    Checks features of a URL (Gzip, ETag, Last-Modified) using standard urllib.
    """
    try:
        check_url_features(url)
        return "Check completed successfully"
    except Exception as e:
        raise e

if __name__ == "__main__":
    mcp.run()
