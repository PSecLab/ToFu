import sys
import os
import importlib.util
import inspect
import time
from typing import Callable, Dict, Any
from .base import BaseRunner, RunnerResult

class PythonRunner(BaseRunner):
    def __init__(self, command: str, args: list, target_tool: str):
        super().__init__(command, args, target_tool)
        self.target_func: Callable = None
        self.module_name = ""
        self.fastmcp_instance = None
        self.mcp_server = None
        self.enable_trace = True

    def start(self):
        """Locates and imports the python module to find the tool function."""
        # Find python file in args
        py_file = None
        for arg in self.args:
            if arg.endswith(".py"):
                py_file = os.path.abspath(arg)
                break

        if not py_file:
            # Fallback if no .py file in args, try to import the command or args directly
            if "-m" in self.args:
                idx = self.args.index("-m")
                if idx + 1 < len(self.args):
                    self.module_name = self.args[idx + 1]
                    try:
                        module = importlib.import_module(self.module_name)
                    except ImportError:
                        module = importlib.import_module(f"{self.module_name}.__main__")
            elif self.args:
                self.module_name = self.args[-1]
                module = importlib.import_module(self.module_name)
            else:
                self.module_name = self.command
                module = importlib.import_module(self.module_name)
        else:
            # Load the file as a module
            base_name = os.path.splitext(os.path.basename(py_file))[0]
            py_dir = os.path.dirname(py_file)
            if py_dir not in sys.path:
                sys.path.insert(0, py_dir)
            self.module_name = "mcp_target_module" if base_name == "__main__" else base_name
            spec = importlib.util.spec_from_file_location(self.module_name, py_file)
            if spec is None or spec.loader is None:
                raise ImportError(f"Could not load spec for {py_file}")
            module = importlib.util.module_from_spec(spec)
            module.__name__ = self.module_name
            sys.modules[self.module_name] = module
            try:
                spec.loader.exec_module(module)
            except Exception as e:
                raise ImportError(f"Error executing module {py_file}: {e}")

        # Find the target tool function and server instances
        self.target_func = None
        self.fastmcp_instance = None
        self.mcp_server = None
        
        # 1. Check if module has a build_server factory function
        if not self.fastmcp_instance and hasattr(module, "build_server") and callable(getattr(module, "build_server")):
            try:
                try:
                    self.fastmcp_instance = module.build_server(prewarm=False)
                except TypeError:
                    self.fastmcp_instance = module.build_server()
                self.mcp_server = getattr(self.fastmcp_instance, "_mcp_server", None)
            except Exception as e:
                print(f"[PythonRunner] build_server failed: {e}", file=sys.stderr)

        # 2. Search in FastMCP and Server instances registered in the module
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if attr.__class__.__name__ == "FastMCP":
                self.fastmcp_instance = attr
                self.mcp_server = attr._mcp_server
            elif attr.__class__.__name__ == "Server" and attr.__class__.__module__.startswith("mcp."):
                self.mcp_server = attr

        if self.fastmcp_instance:
            # Look up tool inside FastMCP local_provider / _tool_manager / _tools / _toolspecs / list_tools
            candidates = []
            if hasattr(self.fastmcp_instance, "local_provider") and hasattr(self.fastmcp_instance.local_provider, "_tools"):
                candidates.append(self.fastmcp_instance.local_provider._tools)
            tool_mgr = getattr(self.fastmcp_instance, "_tool_manager", None) or self.fastmcp_instance
            candidates.extend([getattr(tool_mgr, "_tools", {}), getattr(tool_mgr, "_tool_specs", {})])

            for tools_obj in candidates:
                if not tools_obj:
                    continue
                if isinstance(tools_obj, dict):
                    for tool_name, tool in tools_obj.items():
                        if tool_name == self.target_tool or getattr(tool, "name", None) == self.target_tool:
                            self.target_func = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
                            break
                elif isinstance(tools_obj, (list, set, tuple)):
                    for tool in tools_obj:
                        if getattr(tool, "name", None) == self.target_tool or getattr(tool, "__name__", None) == self.target_tool:
                            self.target_func = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
                            break
                if self.target_func:
                    break

            if not self.target_func and hasattr(self.fastmcp_instance, "list_tools"):
                try:
                    import asyncio
                    loop = asyncio.new_event_loop()
                    tools_list = loop.run_until_complete(self.fastmcp_instance.list_tools())
                    for tool in tools_list:
                        if getattr(tool, "name", None) == self.target_tool:
                            self.target_func = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
                            break
                except Exception:
                    pass

        # 3. Fallback to global function or FastMCP tool manager search
        if not self.target_func:
            if hasattr(module, self.target_tool):
                candidate = getattr(module, self.target_tool)
                if callable(candidate):
                    self.target_func = candidate
            if hasattr(module, "register_all") and callable(getattr(module, "register_all")):
                try:
                    import asyncio
                    from unittest.mock import MagicMock
                    from fastmcp import FastMCP
                    dummy_mcp = FastMCP("dummy")
                    dummy_engine = MagicMock()
                    module.register_all(dummy_mcp, dummy_engine)
                    
                    loop = asyncio.new_event_loop()
                    tools_list = loop.run_until_complete(dummy_mcp.list_tools())
                    for tool in tools_list:
                        if getattr(tool, "name", None) == self.target_tool:
                            self.target_func = getattr(tool, "fn", None) or getattr(tool, "func", None) or tool
                            break
                except Exception as e:
                    pass

        if not self.target_func:
            raise AttributeError(f"Could not find callable tool/function '{self.target_tool}' in module '{self.module_name}'")

    def execute(self, arguments: dict) -> RunnerResult:
        if not self.target_func:
            return RunnerResult(success=False, coverage=set(), error="Runner not started or function not found")

        covered_lines = set()
        
        def trace_lines(frame, event, arg):
            if event == 'line':
                code = frame.f_code
                filename = code.co_filename
                
                # Trace target module, local third_party files, or site-packages dependencies
                is_target = self.module_name in filename
                is_dependency = "site-packages" in filename or "third_party" in filename
                
                if (is_target or is_dependency) and not any(x in filename for x in ["<", "importlib", "encodings", "linecache", "anyio", "mcp"]):
                    covered_lines.add(f"{filename}:{frame.f_lineno}")
            return trace_lines

        success = True
        error_msg = None
        start_time = time.perf_counter()

        val = None
        from ..sanitizers.introspection import FileAccessTracer
        tracer = FileAccessTracer()
        
        # Save previous trace function
        old_trace = sys.gettrace()
        if self.enable_trace:
            sys.settrace(trace_lines)
        try:
            with tracer:
                if self.mcp_server:
                    # Use JSON-RPC stdio emulator in-process to run the full server pipeline
                    import anyio
                    import mcp.types as types
                    from mcp.shared.message import SessionMessage

                    async def run_test():
                        read_stream_writer, read_stream = anyio.create_memory_object_stream(10)
                        write_stream, write_stream_reader = anyio.create_memory_object_stream(10)

                        async with anyio.create_task_group() as tg:
                            tg.start_soon(
                                self.mcp_server.run,
                                read_stream,
                                write_stream,
                                self.mcp_server.create_initialization_options()
                            )

                            # 1. Initialize Handshake
                            init_req = types.JSONRPCMessage.model_validate({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "fuzzer", "version": "1.0"}
                                }
                            })
                            await read_stream_writer.send(SessionMessage(init_req))
                            await write_stream_reader.receive()

                            # 2. Initialized Notification
                            initialized_notif = types.JSONRPCMessage.model_validate({
                                "jsonrpc": "2.0",
                                "method": "notifications/initialized"
                            })
                            await read_stream_writer.send(SessionMessage(initialized_notif))

                            # 3. Call Tool Request
                            call_req = types.JSONRPCMessage.model_validate({
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/call",
                                "params": {
                                    "name": self.target_tool,
                                    "arguments": arguments
                                }
                            })
                            await read_stream_writer.send(SessionMessage(call_req))
                            call_resp = await write_stream_reader.receive()

                            # Clean up server by closing the streams
                            await read_stream_writer.aclose()
                            await write_stream.aclose()

                            return call_resp

                    rpc_resp = anyio.run(run_test)
                    if hasattr(rpc_resp, 'message'):
                        msg = rpc_resp.message
                        if hasattr(msg, "root"):
                            msg = msg.root
                        if isinstance(msg, types.JSONRPCError):
                            success = False
                            error_msg = msg.error.message
                            print(f"[PythonRunner] MCP Server JSON-RPC Error: {error_msg}", file=sys.stderr)
                        elif isinstance(msg, types.JSONRPCResponse):
                            res_data = msg.result
                            if isinstance(res_data, dict) and res_data.get("isError"):
                                success = False
                                error_msg = str(res_data.get("content", "Tool reported error"))
                            else:
                                success = True
                                content = res_data.get("content", []) if isinstance(res_data, dict) else []
                                if isinstance(content, list):
                                    text_contents = []
                                    for block in content:
                                        if isinstance(block, dict) and block.get("type") == "text":
                                            text_contents.append(block.get("text", ""))
                                        elif hasattr(block, "text"):
                                            text_contents.append(block.text)
                                    val = "\n".join(text_contents)
                                else:
                                    val = str(res_data)
                else:
                    # Direct invocation fallback (if not an MCP server)
                    sig = inspect.signature(self.target_func)
                    has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                    if has_kwargs:
                        val = self.target_func(**arguments)
                    else:
                        filtered_args = {k: v for k, v in arguments.items() if k in sig.parameters}
                        val = self.target_func(**filtered_args)
        except KeyboardInterrupt:
            raise
        except BaseException as e:
            success = False
            error_msg = f"{type(e).__name__}: {str(e)}"
            if self.mcp_server:
                print(f"[PythonRunner] MCP Server Internal Exception: {error_msg}", file=sys.stderr)
        finally:
            if self.enable_trace:
                sys.settrace(old_trace)

        end_time = time.perf_counter()
        execution_time_ms = (end_time - start_time) * 1000.0

        return RunnerResult(
            success=success,
            coverage=covered_lines,
            result=val,
            error=error_msg,
            execution_time_ms=execution_time_ms,
            accessed_files=tracer.accessed_files
        )

    def get_tool_metadata(self, tool_name: str) -> tuple:
        if not self.target_func:
            self.start()
        func = self.target_func
        doc = inspect.getdoc(func) or f"Tool {tool_name}"
        sig = inspect.signature(func)
        properties = {}
        required = []
        for name, param in sig.parameters.items():
            if name in ["self", "cls"]:
                continue
            param_type = "string"
            if param.annotation in (int, "int"):
                param_type = "integer"
            elif param.annotation in (float, "float"):
                param_type = "number"
            elif param.annotation in (bool, "bool"):
                param_type = "boolean"
            elif param.annotation in (list, "list") or getattr(param.annotation, "__origin__", None) in (list, tuple):
                param_type = "array"
            elif param.annotation in (dict, "dict") or getattr(param.annotation, "__origin__", None) is dict:
                param_type = "object"
            properties[name] = {"type": param_type}
            if param.default == inspect.Parameter.empty:
                required.append(name)
        schema = {
            "type": "object",
            "properties": properties,
            "required": required
        }
        return tool_name, doc, schema
