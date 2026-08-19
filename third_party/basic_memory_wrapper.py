import os
import sys

# Ensure basic-memory src is in sys.path
basic_memory_src = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "basic-memory", "src")
)
if basic_memory_src not in sys.path:
    sys.path.insert(0, basic_memory_src)

# Import basic-memory MCP tools, prompts, resources to register all tools with FastMCP
import basic_memory.mcp.tools  # noqa: F401
import basic_memory.mcp.prompts  # noqa: F401
import basic_memory.mcp.resources  # noqa: F401

from basic_memory.mcp.server import mcp

if __name__ == "__main__":
    mcp.run(transport="stdio")
