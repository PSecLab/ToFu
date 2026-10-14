""" 
   Authors: Brandon Radosevich and John Halloran (johnhalloran321@gmail.com)
   Copyright (C) Brandon Radosevich and John Halloran
   Licensed under the Mozilla Public License Version 2.0
"""

from pyfiglet import figlet_format
from rich.console import Console
from argparse import ArgumentParser
from os import getenv
from agno.tools.mcp import MCPTools
from mcp import StdioServerParameters
from textwrap import dedent

# Needed for MCP Connection for Tooling
from mcp.client.session import ClientSession
from mcp.client.sse import sse_client

from agno.knowledge.website import WebsiteKnowledgeBase
from agno.vectordb.pgvector import PgVector
from agno.tools.duckduckgo import DuckDuckGoTools
from agno.tools.arxiv import ArxivTools
from agno.tools.hackernews import HackerNewsTools
from agno.agent import Agent
from agno.team.team import Team

from typing import List

from sys import exit
import asyncio
import json
import contextlib

console = Console()
VERSION = "0.0.1"

MCP_URLS = [
    "https://www.anthropic.com/news/model-context-protocol",
    "https://docs.anthropic.com/en/docs/agents-and-tools/mcp",
    "https://github.com/modelcontextprotocol",
    "https://attack.mitre.org/",
    "https://github.com/redcanaryco/atomic-red-team",
]

async def get_tools(url : str) -> str:
    """
    Get Available Tools from the MCP Server
    Args: 
        url (str): url of MCP server
    """
    try:
        async with sse_client(url) as streams:
            async with ClientSession(streams[0],streams[1]) as session:
                await session.initialize()
                tools =await session.list_tools()
                items = getattr(tools, "tools", [])
                print(items)
                return str(items)
    except Exception as e:
        return str(e)

def select_embedder():
    """
    Select embedder based on environment variables
    """
    if getenv("AZURE_OPENAI_API_KEY"):
        try:
            from agno.embedder.azure_openai import AzureOpenAIEmbedder
            return AzureOpenAIEmbedder(
                id=getenv("OPENAI_EMBEDDING_MODEL","text-embedding-3-large"),
                api_key=getenv("AZURE_OPENAI_API_KEY"),
                azure_endpoint=getenv("AZURE_OPENAI_ENDPOINT"),
                api_version=getenv("AZURE_OPENAI_CHAT_DEPLOYMENT_VERSION"),
            )
        except ImportError:
            console.print
    else:
        try:
            from agno.embedder.openai import OpenAIEmbedder
            return OpenAIEmbedder(
                id=getenv("OPENAI_EMBEDDING_MODEL","text-embedding-3-large"),
                api_key=getenv("OPENAI_API_KEY"),
            )
        except ImportError:
            console.print(":x: openai package not installed")
            exit(1)
        
def select_llm():
    """
    Looks at environment configs to determine what LLM to use. 
    """
    if getenv("AZURE_OPENAI_API_KEY"):
        try:
            from agno.models.azure import AzureOpenAI 
        except ImportError:
            console.print(":x: Import Error with Azure, please pip install azure-ai-inference")
        model="gpt-4o"
    
        llm = AzureOpenAI(
            id=getenv("AZURE_OPENAI_MODEL", "gpt-4o"),
            azure_endpoint=getenv("AZURE_OPENAI_ENDPOINT"),
            azure_deployment=model,
            api_key=getenv("AZURE_OPENAI_API_KEY"),
            api_version=getenv("AZURE_OPENAI_CHAT_DEPLOYMENT_VERSION"),
        )
        print(llm)
        return llm
    elif getenv("OLLAMA_MODEL"):
        model_id = getenv("OLLAMA_MODEL")
        from agno.models.ollama import Ollama
        return Ollama(id=model_id)
    else: 
        try:
            from agno.models.openai import OpenAIChat
            return OpenAIChat(
                id=getenv("OPENAI_MODEL","gpt-4o") 
            )
        except ImportError:
            console.print(":x: Please pip install openai")
        return None

async def call_tool(url :str, toolName : str, args : dict) -> str:
        """
        Call Tools From MCP Server
        Args: 
            url: (str): Url of MCP Server
            toolName (str): Name of tool to call
            args: (dict): The dictionary of arguments for the tool
        """
        try:
            async with sse_client(url) as streams:
                async with ClientSession(streams[0],streams[1]) as session:
                    await session.initialize()
                    resp = await session.call_tool(toolName, args)
                    return str(resp)
        except Exception as e:
            return f"An exception occurred: {e}"

MCP_TOOLS =[get_tools,call_tool]

# MCP parameters for the Filesystem server accessed via `npx`
def parse_mcp_config(config: dict) -> List[StdioServerParameters]:
    """Parse MCP server config and return list of StdioServerParameters"""
    if not config.get("mcpServers"):
        raise ValueError("Config must contain mcpServers configuration")
    
    server_params = []
    for server_name, server_config in config["mcpServers"].items():
        server_params.append(StdioServerParameters(
            command=server_config.get("command", "npx"),
            args=server_config.get("args", []),
            env=server_config.get("env", {})
        ))
    
    return server_params

def load_config_from_file(file_path):
    """
    Load MCP server configuration from a JSON file
    
    Args:
        file_path (str): Path to the JSON configuration file
        
    Returns:
        dict: Parsed JSON configuration
    """
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except json.JSONDecodeError:
        console.print(f"[red]Error: Invalid JSON format in {file_path}[/red]")
        exit(1)
    except FileNotFoundError:
        console.print(f"[red]Error: File {file_path} not found[/red]")
        exit(1)
    except Exception as e:
        console.print(f"[red]Error reading config file: {e}[/red]")
        exit(1)

def get_default_config():
    """
    Return the default MCP server configuration
    
    Returns:
        dict: Default configuration
    """
    config_str = """{
        "mcpServers": {
            "chroma": {
            "command": "uvx",
            "args": [
                "chroma-mcp",
                "--client-type",
                "persistent",
                "--data-dir",
                "/Users/brandonradosevich/work/mcp/files"
            ]
            },
            "filesystem": {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-filesystem",
                "/Users/brandonradosevich/"
            ]
            },
            "everything": {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-everything"
            ],
            "env": {
                "AWS_ACCESS_KEY_ID": "YOUR_ACCESS_KEY_HERE",
                "AWS_SECRET_ACCESS_KEY": "YOUR_SECRET_ACCESS_KEY_HERE",
                "AWS_REGION": "YOUR_AWS_REGION_HERE",
                "OPENAI_API_KEY": "sk-randomtoken",
                "HF_TOKEN": "hf_randomtoken"
            }
            },
            "slack": {
            "command": "npx",
            "args": [
                "-y",
                "@modelcontextprotocol/server-slack"
            ],
            "env": {
                "SLACK_BOT_TOKEN": "slack-randomstring",
                "SLACK_TEAM_ID": "RANDOM"
                }
                }
            
                }
    }"""
    return json.loads(config_str)

async def run_stdio_mcp_server(server_params: List[StdioServerParameters], server_url: str = "http://localhost:8000/sse") -> str:
    """
    Run commands with stdio and return the output for multiple MCP servers.
    
    Args:
        server_params: List of StdioServerParameters for connecting to the MCP servers
        server_url: URL of the MCP server to scan
    """
    # Create the async context managers for all MCP tools
    async with contextlib.AsyncExitStack() as stack:
        # Initialize all MCP tools in parallel
        mcp_tools = []
        for params in server_params:
            tool = await stack.enter_async_context(MCPTools(server_params=params))
            mcp_tools.append(tool)
        
        # Create a single agent with access to all MCP tools
        agent = Agent(
            model=select_llm(),
            tools=mcp_tools,  # Pass all tools to the agent
            instructions=dedent("""\
                    You are a security auditor, looking for vulnerabilities in the MCP Server.
                    Ensure that you are thinking like a hacker, with the goal of gaining access, lateral movement, getting callbacks using netcat, dumping credentials such as ssh keys, adding credentials like public ssh keys to authorized keys etc.
                    You are given a list of tools, prompts, and resources that are available on the MCP Server.
                    You are given a list of directories that you can access on the MCP Server.
                    You are given a list of files that you can access on the MCP Server.
                    You are given a list of commands that you can use to access the MCP Server.
                    You are given a list of prompts that you can use to access the MCP Server.
                    You are given a list of resources that you can use to access the MCP Server.
                    Please try to keep commands and tools to smaller directories, to not explode the token limit
            """),
            markdown=True,
            goal=dedent("""\
              You are looking for vulnerabilities in the MCP Server.
                    Given only the list of tools, prompts, and resources, provide easy to understand examples of each vulnerability, and how you would exploit them with basic shell and unix tools.
                    Provide easy to understand examples of each vulnerability, and how to exploit them with basic shell and unix tools.
                    Provide a command-line example for each vulnerability.
                    Provide a remediation command for each vulnerability.
                    Provide a source citation for each vulnerability.
                    Provide a source citation for each remediation command.
                    Provide a source citation for each command-line example.
            """),
            show_tool_calls=True,
            telemetry=False,
            debug_mode=True,
            resolve_context=True,
        )
        
        analysis_hacking_agent = Agent(
            model=select_llm(),
            tools=[DuckDuckGoTools(),ArxivTools(),HackerNewsTools()],
            markdown=True, 
            instructions=dedent("""\
    You are a security auditor, looking for vulnerabilities in the MCP Server {i+1}.
                    For each (tool, prompt, resource) determine how you would exploit them with basic shell and unix tools.
                    Provide a command-line example for each vulnerability.
                    Provide a remediation command for each vulnerability.
                    Provide a source citation for each vulnerability.
                    Provide a source citation for each remediation command.
                    Provide a source citation for each command-line example.
                    Utilize DuckDuckGo, Arxiv, and Hacker News to research the vulnerabilities and provide source citations.
            """),
            goal=dedent("""\
                    For each (tool, prompt, resource) determine how you would exploit them with basic shell and unix tools.
                    Provide a command-line example for each vulnerability.
                    Provide a remediation command for each vulnerability.
                    Provide a source citation for each vulnerability.
                    Provide a source citation for each remediation command.
                    Provide a source citation for each command-line example.
                    List the (tool, prompt, resource) that you are using to exploit the vulnerability.
            """),
            show_tool_calls=True,
            telemetry=False,
            debug_mode=True,
            resolve_context=True,
        )
        
        # Create a single team to analyze all servers together
        mcp_security_team = Team(
            members=[agent, analysis_hacking_agent],
            instructions=[
                    f"You are a security auditor, looking for vulnerabilities in the MCP Server implementation.",
                    "The vulnerabilities should be directly based on the how the MCP Server utilizes its implemented (tools, prompts, and resources), and then you should consider how a hacker might abuse these tools to gain access, dump credentials, add backdoors to startup scripts, add their own ssh keys in etc.",
                    "Ensure that you are thinking like a hacker, with the goal of gaining access, lateral movement, getting callbacks using netcat, dumping credentials such as ssh keys, adding credentials like public ssh keys to authorized keys etc.",
                    "You are given a list of tools, prompts, and resources that are available on the MCP Server.",
                    "You are given a list of directories that you can access on the MCP Server.",
                    "For each attack show a concrete of example, like modifying bashrc, adding a public key to authorized_keys, adding a backdoor to a startup script, etc."
            ],
            description="Multi-Server MCP Security Team",
            mode="collaborate",
            success_criteria="The team has done an exhaustive search and identified all vulnerabilities arising from the MCP Server(s) interactions, an example of how the attacker would use that tool, resource, prompt for some nefarious reason, and provided remediation steps.",
            markdown=True,
            add_datetime_to_instructions=True,
            enable_agentic_context=True,
            enable_team_history=True,
            telemetry=False,
            debug_mode=True,
        )
        
        # Run the analysis
        console.print("\n[bold blue]Starting multi-server MCP vulnerability analysis[/bold blue]")
        prompt = "Use each member of the team to analyze the MCP Server, and then provide a report of the findings."
        data = await mcp_security_team.aprint_response(prompt, stream=True,markdown=True)
        print(data)
        console.print("[bold green]Completed multi-server analysis[/bold green]\n")

def get_kb():
    """from typing import Iterator

    docker run -d \
    -e POSTGRES_DB=ai \
    -e POSTGRES_USER=ai \
    -e POSTGRES_PASSWORD=ai \
    -e PGDATA=/var/lib/postgresql/data/pgdata \
    -v pgvolume:/var/lib/postgresql/data \
    -p 5532:5432 \
    --name pgvector \
    agnohq/pgvector:16
    """

    return WebsiteKnowledgeBase(
        urls=MCP_URLS,
        # Number of links to follow from the seed URLs
        max_links=30,
        # Table name: ai.website_documents
        vector_db=PgVector(
            table_name="website_documents",
            db_url="postgresql+psycopg://ai:ai@localhost:5532/ai",
            embedder=select_embedder()
        ),
    )


def print_banner():
    banner = figlet_format('MCP-XPLORER',"big")
    console.print(banner, justify="center")
    console.print(f"Version: {VERSION}",justify="center")

def parse_arguments():
    parser = ArgumentParser(description="MCPXPLORER - MCP Server Vulnerability Scanner")
    parser.add_argument("--server", default="http://localhost:8000/sse", 
                        help="URL of the MCP server to scan (e.g., http://localhost:8000/sse)")
    parser.add_argument("--port", type=int, 
                        help="Port for the MCP server (e.g., 8000). This will be combined with http://localhost:<port>/sse")
    parser.add_argument("--config", 
                        help="Path to a JSON configuration file for the MCP server")
    parser.add_argument("--servers", nargs="+",
                        help="List of MCP servers to scan (e.g., filesystem chroma slack)")
    parser.add_argument("--use_kb", action="store_true", default=False, 
                        help="Enable knowledge base integration")
    parser.add_argument("--recreate_kb", action="store_true", default=False, 
                        help="Enable knowledge base integration")
    parser.add_argument("--verbose", action="store_true", default=False,
                        help="Enable Verbosity for debugging and observability")
    args = parser.parse_args()
    
    # If port is specified, override the server URL
    if args.port:
        args.server = f"http://localhost:{args.port}/sse"
        console.print(f"Using server URL: {args.server}")
    
    return args



async def main():
    print_banner()
    args = parse_arguments()
    kb = None

    if args.use_kb:
        kb=get_kb()
        kb.load(recreate=args.recreate_kb)
    
    # Load configuration
    if args.config:
        console.print(f"Loading configuration from {args.config}")
        config_dict = load_config_from_file(args.config)
    else:
        console.print("Using default configuration")
        config_dict = get_default_config()
    
    # Filter servers if specified
    if args.servers:
        filtered_servers = {k: v for k, v in config_dict["mcpServers"].items() if k in args.servers}
        if not filtered_servers:
            console.print("[red]Error: No matching servers found in configuration[/red]")
            exit(1)
        config_dict["mcpServers"] = filtered_servers
    
    # Pass the dictionary to parse_mcp_config
    server_params = parse_mcp_config(config_dict)
    
    if not server_params:
        console.print("[red]Error: No MCP servers configured[/red]")
        exit(1)
    
    console.print(f"Scanning {len(server_params)} MCP servers...")
    
    # Pass args.server to run_stdio_mcp_server
    await run_stdio_mcp_server(server_params, args.server)

if __name__ == "__main__":
    asyncio.run(
        main()
    )