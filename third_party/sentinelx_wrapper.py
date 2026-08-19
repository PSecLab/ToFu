import os
import sys
import asyncio
from typing import Any, Dict

# Ensure sentinelx-cloud-core src is in sys.path
sentinelx_src = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "sentinelx-cloud-core", "src")
)
if sentinelx_src not in sys.path:
    sys.path.insert(0, sentinelx_src)

from fastmcp import FastMCP
from sentinelx_core.handlers import build_registry

mcp = FastMCP("sentinelx")
registry = build_registry()

# Dynamically register each handler as an MCP tool sentinelx_<op_name>
for op_name, handler_fn in registry.items():
    tool_name = f"sentinelx_{op_name}"
    
    def make_tool_fn(fn, name):
        async def tool_fn(payload: Dict[str, Any] = None) -> Dict[str, Any]:
            if payload is None:
                payload = {}
            try:
                res = await fn(payload)
                return res
            except Exception as e:
                return {"error": str(e), "type": type(e).__name__}
        tool_fn.__name__ = name
        tool_fn.__doc__ = f"SentinelX operation handler for op: {op_name}"
        return tool_fn

    mcp.tool(name=tool_name)(make_tool_fn(handler_fn, tool_name))

if __name__ == "__main__":
    mcp.run(transport="stdio")
