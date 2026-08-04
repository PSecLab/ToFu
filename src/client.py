from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

import json
import subprocess
import os

class MCPInspector:
    def __init__(self, command: str, args: list, env: dict = None):
        self.command = command
        self.args = args
        self.env = env or os.environ.copy()

    def _query_server(self, target_tool: str = None):
        cmd = [self.command] + self.args
        env = os.environ.copy()
        env.update(self.env)
        
        proc = subprocess.Popen(
            cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            env=env
        )

        try:
            # 1. Send initialize
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {},
                    "clientInfo": {"name": "fuzzer_inspector", "version": "1.0"}
                }
            }) + "\n")
            proc.stdin.flush()
            proc.stdout.readline()

            # 2. Send initialized notification
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0",
                "method": "notifications/initialized"
            }) + "\n")
            proc.stdin.flush()

            # 3. Request tools/list
            proc.stdin.write(json.dumps({
                "jsonrpc": "2.0",
                "id": 2,
                "method": "tools/list"
            }) + "\n")
            proc.stdin.flush()

            # Read lines until matching response id=2 is received
            while True:
                resp_line = proc.stdout.readline()
                if not resp_line:
                    break
                try:
                    data = json.loads(resp_line)
                    if data.get("id") == 2 and "result" in data:
                        tools = data.get("result", {}).get("tools", [])
                        return tools
                except Exception:
                    continue
            return []
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=1.0)
            except Exception:
                pass

    async def fetch_all_tools(self) -> list:
        """Fetches the complete list of available tools from the server."""
        tools = self._query_server()
        return [t.get("name") for t in tools if t.get("name")]

    async def fetch_tool_metadata(self, tool_name: str) -> tuple:
        """Briefly connects to the server to extract tool metadata (name, description, schema)."""
        tools = self._query_server(tool_name)
        target = next((t for t in tools if t.get("name") == tool_name), None)
        if not target:
            raise ValueError(f"Tool '{tool_name}' not found on this MCP server.")
        return target.get("name"), target.get("description", ""), target.get("inputSchema", {})
