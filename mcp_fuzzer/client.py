from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

class MCPInspector:
    def __init__(self, command: str, args: list):
        self.server_params = StdioServerParameters(command=command, args=args)

    async def fetch_all_tools(self) -> list:
        """Récupère la liste complète des outils disponibles sur le serveur."""
        async with stdio_client(self.server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                mcp_tools = await session.list_tools()
                return [t.name for t in mcp_tools.tools]

    async def fetch_tool_metadata(self, tool_name: str) -> tuple:
        """Se connecte brièvement au serveur pour extraire les métadonnées d'un outil."""
        async with stdio_client(self.server_params) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                mcp_tools = await session.list_tools()
                target = next((t for t in mcp_tools.tools if t.name == tool_name), None)
                if not target:
                    raise ValueError(f"Tool '{tool_name}' not found on this MCP server.")
                return target.name, target.description, target.inputSchema
