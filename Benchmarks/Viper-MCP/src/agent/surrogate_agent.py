"""LangChain-based MCP fuzzing agent"""
import json
import logging
import os
import tempfile
import asyncio
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from .base import BaseAgent
from src.llm.usage import append_usage_log, extract_langchain_usage
from src.utils.instrumentation import inject_python_hook_env, inject_node_hook_env  # PATCH (ToFu): node hook

logger = logging.getLogger("viper_mcp.agent")

try:
    from langchain_mcp_adapters.client import MultiServerMCPClient
    from langchain_openai import ChatOpenAI
    from langchain_anthropic import ChatAnthropic
    from langchain_google_genai import ChatGoogleGenerativeAI
    from langchain_core.language_models import BaseChatModel
    from langchain_core.tools import BaseTool
    from langchain_core.prompts import ChatPromptTemplate, MessagesPlaceholder
    LANGCHAIN_MCP_AVAILABLE = True
except ImportError as e:
    LANGCHAIN_MCP_AVAILABLE = False
    MultiServerMCPClient = None
    BaseChatModel = None
    BaseTool = None
    logger.warning(f"LangChain MCP adapters not available: {e}. Install with: pip install langchain-mcp-adapters langchain-openai langchain-anthropic langchain-google-genai")


def _extract_refusal_info(response: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if "error" in response:
        err = response["error"]
        msg = err.get("message", str(err)) if isinstance(err, dict) else str(err)
        code = err.get("code") if isinstance(err, dict) else None
        if code in [-32600, -32602, -32603] or "refused" in msg.lower():
            return {"code": code, "message": msg, "type": "refusal"}
    return None


def _stringify_tool_field(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, list):
        pieces = []
        for item in value:
            if isinstance(item, dict):
                if "text" in item:
                    pieces.append(str(item.get("text", "")))
                else:
                    pieces.append(json.dumps(item, ensure_ascii=False))
            else:
                pieces.append(str(item))
        return "\n".join(piece.strip() for piece in pieces if str(piece).strip()).strip()
    if isinstance(value, dict):
        if "text" in value:
            return str(value.get("text", "")).strip()
        return json.dumps(value, ensure_ascii=False)
    return str(value).strip()


def _extract_tool_result_details(result: Any) -> Dict[str, Any]:
    """
    Normalize MCP tool return payload for both LLM consumption and interaction logging.
    Returns text/is_error plus optional stdout/stderr fields when present.
    """
    details = {
        "text": "",
        "is_error": False,
        "stdout": "",
        "stderr": "",
    }
    try:
        if isinstance(result, list) and result:
            first = result[0]
            if isinstance(first, dict) and "text" in first:
                text = str(first.get("text", ""))
                try:
                    inner = json.loads(text)
                    if isinstance(inner, dict):
                        details["is_error"] = bool(inner.get("isError", False))
                        details["stdout"] = _stringify_tool_field(inner.get("stdout"))
                        details["stderr"] = _stringify_tool_field(inner.get("stderr"))
                        content_text = _stringify_tool_field(inner.get("content"))
                        result_text = _stringify_tool_field(inner.get("result"))
                        error_text = _stringify_tool_field(inner.get("error"))
                        details["text"] = (
                            content_text
                            or result_text
                            or error_text
                            or details["stdout"]
                            or details["stderr"]
                            or text
                        )
                        return details
                except Exception:
                    pass
                details["text"] = text
                return details

        if isinstance(result, dict):
            if "isError" in result:
                details["is_error"] = bool(result.get("isError", False))
            details["stdout"] = _stringify_tool_field(result.get("stdout"))
            details["stderr"] = _stringify_tool_field(result.get("stderr"))
            content_text = _stringify_tool_field(result.get("content"))
            result_text = _stringify_tool_field(result.get("result"))
            error_text = _stringify_tool_field(result.get("error"))
            details["text"] = (
                content_text
                or result_text
                or error_text
                or details["stdout"]
                or details["stderr"]
                or json.dumps(result, ensure_ascii=False)
            )
            return details
    except Exception:
        pass
    details["text"] = str(result)
    return details


def _compact_tool_content(tool_name: str, content: str, limit: int = 4000) -> str:
    text = (content or "").strip()
    if len(text) <= limit:
        return text
    head = text[: limit // 2]
    tail = text[-limit // 4 :]
    omitted = len(text) - len(head) - len(tail)
    return (
        f"[tool:{tool_name}] output truncated, omitted {omitted} characters.\n"
        f"{head}\n...\n{tail}"
    )


def _has_meaningful_feedback(output: Any, tool_errors: List[Dict[str, Any]]) -> bool:
    output_text = str(output or "").strip()
    if output_text:
        return True
    for item in tool_errors:
        message = str(item.get("message", "") or "").strip()
        if message:
            return True
    return False


class LangChainAgent(BaseAgent):

    def __init__(
        self,
        mcp_client: Any,  
        llm: Any,  
        instruction: str = (
            "You are a helpful AI assistant. Use the available tools to help users with their requests. "
            "When users ask you to perform tasks, use the appropriate tools and provide clear, informative responses. "
            "You may call tools for multiple steps when needed; continue until the task is complete."
        ),
        agent_type: str = "openai-tools", 
        tool_filter: Optional[List[str]] = None,
        interaction_log_path: Optional[str] = None,
        max_tool_iterations: int = 4,
        usage_log_path: Optional[str] = None,
        usage_role: str = "agent",
        usage_provider: str = "",
        usage_model: str = "",
    ):
        if not LANGCHAIN_MCP_AVAILABLE:
            raise ImportError(
                "LangChain MCP adapters not available. "
                "Install with: pip install langchain-mcp-adapters langchain-openai langchain-anthropic langchain-google-genai"
            )
        
        self.mcp_client = mcp_client
        self.llm = llm
        self.instruction = instruction
        self.agent_type = agent_type
        self._tool_filter = tool_filter
        self._tools: List[Any] = []  
        self._bound_llm: Optional[Any] = None  
        self._interaction_log_path = interaction_log_path or os.path.join(
            tempfile.gettempdir(), "viper_mcp_interactions.jsonl"
        )
        self._max_tool_iterations = max(1, int(max_tool_iterations))
        self._usage_log_path = usage_log_path or os.environ.get("MCP_FUZZER_LLM_USAGE_LOG", "")
        self._usage_role = usage_role
        self._usage_provider = usage_provider or ""
        self._usage_model = usage_model or ""
        logger.info("LangChainAgent initialized, MCP interaction log: %s", self._interaction_log_path)

    def _append_llm_usage(self, usage: Dict[str, int], *, component: str = "agent") -> None:
        append_usage_log(
            self._usage_log_path,
            {
                "provider": self._usage_provider,
                "model": self._usage_model,
                "role": self._usage_role,
                "component": component,
                "input_tokens": usage.get("input_tokens", 0),
                "output_tokens": usage.get("output_tokens", 0),
                "total_tokens": usage.get("total_tokens", 0),
            },
        )

    async def initialize(self):
        """Load tools from MCP server and bind them to LLM."""
        if not self._tools:
            # Load tools from MCP server
            logger.info("Loading tools from MCP server...")
            all_tools = await self.mcp_client.get_tools()
            logger.info(f"Loaded {len(all_tools)} tools from MCP server")
            
            # Deduplicate tools by name (some MCP servers expose duplicate names)
            seen: set = set()
            unique_tools = []
            for tool in all_tools:
                if tool.name not in seen:
                    seen.add(tool.name)
                    unique_tools.append(tool)
            if len(unique_tools) < len(all_tools):
                logger.warning(
                    "Removed %d duplicate tool name(s): %s",
                    len(all_tools) - len(unique_tools),
                    sorted(set(t.name for t in all_tools) - set(t.name for t in unique_tools)),
                )
            all_tools = unique_tools

            # Apply tool filter if specified
            if self._tool_filter:
                tool_names = set(self._tool_filter)
                self._tools = [tool for tool in all_tools if tool.name in tool_names]
                logger.info(f"Filtered to {len(self._tools)} tools: {self._tool_filter}")
            else:
                self._tools = all_tools
            
            if not self._tools:
                logger.warning("No tools available after filtering")
            
            if self._tools:
                self._bound_llm = self.llm.bind_tools(self._tools)
                logger.info(f"Bound {len(self._tools)} tools to LLM")
            else:
                self._bound_llm = self.llm
            
            logger.info("LangChain agent initialized")

    def _append_interaction(self, obj: Dict[str, Any]) -> None:
        """Append one MCP server interaction record to the JSONL log."""
        if not self._interaction_log_path:
            return
        try:
            Path(self._interaction_log_path).parent.mkdir(parents=True, exist_ok=True)
            with open(self._interaction_log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(obj, ensure_ascii=False) + "\n")
        except Exception as e:
            logger.warning("Failed to append MCP interaction log: %s", e)

    @property
    def tools_cache(self) -> List[Dict[str, Any]]:
        """Tool list for compatibility with prompt generator."""
        if not self._tools:
            return []
        return [
            {
                "name": tool.name,
                "description": tool.description or "",
            }
            for tool in self._tools
        ]

    async def execute_prompt(self, prompt: str) -> Dict[str, Any]:
        """Run prompt through LangChain LLM with tool calling."""
        try:
            # Ensure agent is initialized
            if not self._bound_llm:
                await self.initialize()
            
            from langchain_core.messages import HumanMessage, SystemMessage
            messages = []
            if self.instruction:
                messages.append(SystemMessage(content=self.instruction))
            messages.append(HumanMessage(content=prompt))
            
            from langchain_core.messages import ToolMessage
            output = ""
            tool_errors = []

            for step in range(self._max_tool_iterations):
                response = await self._bound_llm.ainvoke(messages)
                self._append_llm_usage(extract_langchain_usage(response), component="agent_step")
                tool_calls = response.tool_calls if hasattr(response, "tool_calls") and response.tool_calls else []
                if not tool_calls:
                    output = response.content if hasattr(response, "content") else str(response)
                    break

                messages.append(response)
                for i, tool_call in enumerate(tool_calls):
                    tool_name = tool_call.get("name")
                    tool_args = tool_call.get("args", {})
                    logger.info(
                        "Agent tool call step=%d tool=%s args=%s",
                        step,
                        tool_name,
                        json.dumps(tool_args, ensure_ascii=False)[:500],
                    )

                    tool = None
                    for t in self._tools:
                        if t.name == tool_name:
                            tool = t
                            break

                    if tool:
                        self._append_interaction({
                            "event": "request",
                            "tool": tool_name,
                            "args": tool_args,
                            "step": step,
                        })
                        try:
                            if hasattr(tool, "ainvoke"):
                                result = await tool.ainvoke(tool_args)
                            else:
                                result = tool.invoke(tool_args)
                            result_details = _extract_tool_result_details(result)
                            normalized_text = result_details["text"]
                            is_tool_error = result_details["is_error"]
                            if is_tool_error:
                                tool_errors.append({
                                    "tool": tool_name,
                                    "message": normalized_text[:1000],
                                    "step": step,
                                })
                            self._append_interaction({
                                "event": "response",
                                "tool": tool_name,
                                "result": normalized_text,
                                "is_error": is_tool_error,
                                "stdout": result_details.get("stdout", ""),
                                "stderr": result_details.get("stderr", ""),
                                "step": step,
                            })
                            logger.info(
                                "Agent tool result step=%d tool=%s is_error=%s excerpt=%s",
                                step,
                                tool_name,
                                is_tool_error,
                                normalized_text[:300],
                            )
                            tool_content = _compact_tool_content(tool_name, normalized_text)
                        except Exception as e:
                            logger.error(f"Tool {tool_name} execution failed: {e}")
                            tool_content = f"Error: {str(e)}"
                            tool_errors.append({
                                "tool": tool_name,
                                "message": str(e),
                                "step": step,
                            })
                            self._append_interaction({
                                "event": "response",
                                "tool": tool_name,
                                "error": str(e),
                                "stdout": "",
                                "stderr": str(e),
                                "step": step,
                            })
                            logger.info(
                                "Agent tool result step=%d tool=%s is_error=true excerpt=%s",
                                step,
                                tool_name,
                                str(e)[:300],
                            )
                    else:
                        logger.warning(f"Tool {tool_name} not found")
                        tool_content = f"Tool {tool_name} not found"
                        tool_errors.append({
                            "tool": tool_name,
                            "message": f"Tool {tool_name} not found",
                            "step": step,
                        })
                        self._append_interaction({
                            "event": "response",
                            "tool": tool_name,
                            "error": f"Tool {tool_name} not found",
                            "stdout": "",
                            "stderr": f"Tool {tool_name} not found",
                            "step": step,
                        })
                        logger.info(
                            "Agent tool result step=%d tool=%s is_error=true excerpt=%s",
                            step,
                            tool_name,
                            f"Tool {tool_name} not found",
                        )

                    tool_call_id = tool_calls[i].get("id") if i < len(tool_calls) else f"call_{i}"
                    messages.append(ToolMessage(content=str(tool_content), tool_call_id=tool_call_id))

                if len(messages) > 12:
                    messages = messages[:2] + messages[-10:]

            if not output:
                final_response = await self._bound_llm.ainvoke(messages)
                self._append_llm_usage(extract_langchain_usage(final_response), component="agent_final")
                output = final_response.content if hasattr(final_response, "content") else str(final_response)
            success = _has_meaningful_feedback(output, tool_errors)
            logger.info(
                "Agent prompt completed success=%s tool_error_count=%d has_output=%s",
                success,
                len(tool_errors),
                bool(str(output or "").strip()),
            )
            return {
                "success": success,
                "response": {
                    "content": [{"type": "text", "text": str(output)}],
                    "tool_errors": tool_errors,
                },
                "error": "; ".join(err["message"] for err in tool_errors[:3]) if tool_errors else "",
                "refusal_info": _extract_refusal_info({"error": {"message": "; ".join(err["message"] for err in tool_errors[:3])}}) if tool_errors else None,
            }
        except Exception as e:
            logger.error("LangChain agent execution failed: %s", e, exc_info=True)
            return {
                "success": False,
                "error": str(e),
                "refusal_info": _extract_refusal_info({"error": {"message": str(e)}}),
            }

    async def close(self):
        """Close MCP connections."""
        try:
            if self.mcp_client:
                if hasattr(self.mcp_client, "aclose"):
                    await self.mcp_client.aclose()
        except Exception as e:
            logger.warning(f"Error closing MCP client: {e}")
        logger.info("LangChain agent closed")


def create_langchain_agent_from_config(config) -> LangChainAgent:
    """
    Create LangChainAgent from config.yaml.
    
    Builds MultiServerMCPClient with stdio or HTTP transport and creates
    LangChain agent with specified LLM provider.
    """
    if not LANGCHAIN_MCP_AVAILABLE:
        raise ImportError(
            "LangChain MCP adapters not available. "
            "Install with: pip install langchain-mcp-adapters langchain-openai langchain-anthropic langchain-google-genai"
        )
    
    mcp_cfg = config.mcp_server
    transport = mcp_cfg.get("transport", "stdio")
    agent_cfg = config.agent_llm
    provider = agent_cfg.get("provider", "openai").lower()
    
    project_root = Path(__file__).resolve().parents[2]
    repo_cfg = mcp_cfg.get("repo_path", "")
    repo_path = (
        (project_root / repo_cfg).resolve()
        if repo_cfg and not Path(repo_cfg).is_absolute()
        else Path(repo_cfg).resolve() if repo_cfg else None
    )

    startup = mcp_cfg.get("startup_command")
    if not startup:
        # ── Auto-detect startup command ──────────────────────────
        if repo_path and repo_path.is_dir():
            logger.info("startup_command not set; running auto-detection for %s", repo_path)
            try:
                from src.utils.auto_detector import MCPServerAutoDetector
                detector = MCPServerAutoDetector(project_root=project_root)
                detected = detector.detect(repo_path)
                if detected:
                    startup = detected.startup_command
                    logger.info("Auto-detected startup_command: %s", startup)
                    if detected.build_command and detected.entry_point and not detected.entry_point.exists():
                        logger.info("Building repo first: %s", detected.build_command)
                        subprocess.run(
                            detected.build_command, cwd=str(repo_path),
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                        )
                else:
                    raise ValueError(
                        f"Auto-detection failed for repo_path '{repo_path}'. "
                        "Please set startup_command manually in config.yaml."
                    )
            except ImportError:
                raise ValueError(
                    "startup_command is required in config.yaml mcp_server section "
                    "(auto_detector not available)"
                )
        else:
            raise ValueError(
                "startup_command is required in config.yaml mcp_server section "
                "(set repo_path to enable auto-detection)"
            )

    # Parse startup command
    cmd_list = startup if isinstance(startup, list) else startup.split()
    command = cmd_list[0]
    args = list(cmd_list[1:])
    
    tool_filter = mcp_cfg.get("tool_filter")
    # JSONL path for MCP interaction logging; fall back to a temporary file.
    interaction_log_path = mcp_cfg.get("interaction_log_path") or os.environ.get("MCP_FUZZER_INTERACTION_LOG")
    max_tool_iterations = mcp_cfg.get("max_tool_iterations", 4)

    # Build environment
    results_dir = Path(__file__).parent.parent.parent / "results"
    default_log_path = results_dir / "oracle.json"
    configured_oracle_path = (
        mcp_cfg.get("oracle_path")
        or config.output.get("oracle_path")
        or config.fuzz.get("oracle_path")
    )
    env = {
        "MCP_FUZZER_ORACLE_LOG": os.environ.get(
            "MCP_FUZZER_ORACLE_LOG",
            str(Path(configured_oracle_path).resolve()) if configured_oracle_path else str(default_log_path),
        ),
    }
    configured_env = mcp_cfg.get("env") or mcp_cfg.get("environment") or {}
    if isinstance(configured_env, dict):
        env.update({str(k): str(v) for k, v in configured_env.items()})
    env = inject_python_hook_env(cmd_list, env, project_root)
    env = inject_node_hook_env(cmd_list, env, project_root)  # PATCH (ToFu)

    # Create MCP client configuration
    mcp_servers = {}
    server_name = "mcp_server"
    
    if transport == "stdio":
        server_config = {
            "command": command,
            "args": args,
            "transport": "stdio",
            "env": env,
        }
        if repo_path and repo_path.is_dir():
            server_config["cwd"] = str(repo_path)
        mcp_servers[server_name] = server_config
    elif transport in ["sse", "streamable-http", "http"]:
        url = mcp_cfg.get("url") or f"http://{mcp_cfg.get('host', 'localhost')}:{mcp_cfg.get('port', 8000)}/mcp"
        headers = mcp_cfg.get("headers", {})
        mcp_servers[server_name] = {
            "url": url,
            "transport": "http",
            "headers": headers,
        }
    else:
        raise ValueError(f"Unsupported transport: {transport}")

    mcp_client = MultiServerMCPClient(mcp_servers)
    
    model_name = agent_cfg.get("model", "")
    base_url = agent_cfg.get("base_url")
    temperature = agent_cfg.get("temperature", 0.7)
    api_key = agent_cfg.get("api_key")
    
    if provider == "openai":
        if not api_key:
            api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            raise ValueError("OpenAI API key not found. Set OPENAI_API_KEY environment variable or configure in config.yaml")
        llm = ChatOpenAI(
            model=model_name or "gpt-4",
            api_key=api_key,
            base_url=base_url,
            temperature=temperature,
        )
        agent_type = "openai-tools"
    elif provider == "deepseek":
        if not api_key:
            api_key = os.environ.get("DEEPSEEK_API_KEY")
        if not api_key:
            raise ValueError("DeepSeek API key not found. Set DEEPSEEK_API_KEY environment variable or configure in config.yaml")
        deepseek_base_url = base_url or "https://api.deepseek.com/"
        llm = ChatOpenAI(
            model=model_name or "deepseek-chat",
            api_key=api_key,
            base_url=deepseek_base_url,
            temperature=temperature,
        )
        agent_type = "openai-tools"
    elif provider == "anthropic":
        if not api_key:
            api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            raise ValueError("Anthropic API key not found. Set ANTHROPIC_API_KEY environment variable or configure in config.yaml")
        llm = ChatAnthropic(
            model=model_name or "claude-3-5-sonnet-20241022",
            api_key=api_key,
            temperature=temperature,
        )
        agent_type = "react"  
    elif provider == "google" or provider == "gemini":
        if not api_key:
            api_key = os.environ.get("GOOGLE_API_KEY") or os.environ.get("GOOGLE_GENAI_API_KEY")
        if not api_key:
            raise ValueError("Google API key not found. Set GOOGLE_API_KEY environment variable or configure in config.yaml")
        llm = ChatGoogleGenerativeAI(
            model=model_name or "gemini-pro",
            google_api_key=api_key,
            temperature=temperature,
        )
        agent_type = "react"  
    else:
        raise ValueError(f"Unsupported LLM provider: {provider}. Supported: openai, anthropic, google/gemini, deepseek")
    
    instruction = agent_cfg.get("instruction", "")
    
    return LangChainAgent(
        mcp_client=mcp_client,
        llm=llm,
        instruction=instruction,
        agent_type=agent_type,
        tool_filter=tool_filter,
        interaction_log_path=interaction_log_path,
        max_tool_iterations=max_tool_iterations,
        usage_log_path=agent_cfg.get("usage_log_path"),
        usage_role=str(agent_cfg.get("usage_role") or "agent"),
        usage_provider=provider,
        usage_model=model_name or "",
    )
