import sys
import os
import shutil
import json
import asyncio
import time
import logging
import atheris
from pymongo import MongoClient

from .llm import LLMHandler
from .client import MCPInspector
from . import sanitizers
from .runners import PythonRunner, JSRunner

logger = logging.getLogger(__name__)

# Global variables required by Atheris callback
_current_runner = None
_current_schema = None
_selected_sanitizer_names = []
_silent_bug_found = False
_target_tool_name = ""


def _test_one_input_factory():
    def test_one_input(data):
        global _current_runner, _current_schema, _selected_sanitizer_names, _silent_bug_found, _target_tool_name
        if _current_runner is None or _current_schema is None:
            return

        properties = _current_schema.get("properties", {})
        generated_arguments = {}
        parsed_successfully = False

        import inspect
        sig = None
        if hasattr(_current_runner, "target_func") and _current_runner.target_func:
            try:
                sig = inspect.signature(_current_runner.target_func)
            except Exception:
                pass

        try:
            decoded_str = data.decode("utf-8", errors="ignore")
            parsed_json = json.loads(decoded_str)
            if isinstance(parsed_json, dict):
                for prop_name in properties:
                    if prop_name in parsed_json:
                        generated_arguments[prop_name] = parsed_json[prop_name]
                    else:
                        raise ValueError("Missing property")
                parsed_successfully = True
        except Exception:
            pass

        if not parsed_successfully:
            fdp = atheris.FuzzedDataProvider(data)
            generated_arguments = {}
            for prop_name, prop_attrs in properties.items():
                is_bytes = False
                if sig and prop_name in sig.parameters:
                    param = sig.parameters[prop_name]
                    if param.annotation in (bytes, "bytes") or "bytes" in str(param.annotation):
                        is_bytes = True

                if is_bytes:
                    generated_arguments[prop_name] = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 4096))
                else:
                    prop_type = prop_attrs.get("type")
                    if prop_type == "string":
                        generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 500))
                    elif prop_type == "integer":
                        generated_arguments[prop_name] = fdp.ConsumeInt(4)
                    elif prop_type == "number":
                        generated_arguments[prop_name] = fdp.ConsumeFloat()
                    elif prop_type == "boolean":
                        generated_arguments[prop_name] = fdp.ConsumeBool()
                    else:
                        generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))

        if parsed_successfully:
            for prop_name, val in list(generated_arguments.items()):
                is_bytes = False
                if sig and prop_name in sig.parameters:
                    param = sig.parameters[prop_name]
                    if param.annotation in (bytes, "bytes") or "bytes" in str(param.annotation):
                        is_bytes = True
                
                if is_bytes and not isinstance(val, bytes):
                    if isinstance(val, str):
                        import base64
                        try:
                            generated_arguments[prop_name] = base64.b64decode(val.encode("utf-8"))
                        except Exception:
                            generated_arguments[prop_name] = val.encode("utf-8", errors="ignore")
                    else:
                        generated_arguments[prop_name] = str(val).encode("utf-8")

        res = _current_runner.execute(generated_arguments)

        sanitizer_triggered = False
        triggered_by = []
        for val in generated_arguments.values():
            if isinstance(val, str):
                for sanitizer_name in _selected_sanitizer_names:
                    sanitizer_fn = getattr(sanitizers, sanitizer_name, None)
                    if sanitizer_fn and sanitizer_fn(val):
                        sanitizer_triggered = True
                        if sanitizer_name not in triggered_by:
                            triggered_by.append(sanitizer_name)

        if sanitizer_triggered and res.success:
            err_details = (
                f"Silent Bug Alert: Sanitizers {triggered_by} flagged this input as malicious, "
                f"but the target tool executed successfully without raising any exception."
            )
            logger.warning(f"\n[POTENTIAL VULNERABILITY / SILENT BUG FOUND] in '{_target_tool_name}' !")
            logger.warning(f"   -> Faulty Input : {repr(generated_arguments)}")
            logger.warning(f"   -> Tool Output  : {repr(res.result)}")
            logger.warning(f"   -> Analysis     : {err_details}")

            try:
                client = MongoClient("mongodb://localhost:27017/", serverSelectionTimeoutMS=2000)
                db = client["toolfuzz_db"]
                collection = db["vulnerabilities"]
                document = {
                    "tool": _target_tool_name,
                    "input": generated_arguments,
                    "output": res.result,
                    "triggered_sanitizers": triggered_by,
                    "timestamp": time.time(),
                    "analysis": err_details
                }
                collection.insert_one(document)
                logger.info("[MongoDB] Vulnerability successfully logged to MongoDB toolfuzz_db.vulnerabilities.")
            except Exception as mongo_err:
                logger.error(f"[MongoDB] Failed to log vulnerability to database: {mongo_err}")

            _silent_bug_found = True
            sys.exit(1)

    return test_one_input


class MCPDifferentialFuzzer:
    def __init__(self, command: str, args: list, target_tool: str, api_key: str, corpus_dir: str = "./fuzz_corpus"):
        self.command = command
        self.args = args
        self.target_tool = target_tool
        self.corpus_dir = corpus_dir
        self.llm = LLMHandler(api_key=api_key)
        self.inspector = MCPInspector(command=command, args=args)

    def run(self, max_iterations: int = 5, time_per_iteration: int = 20):
        global _current_runner, _current_schema, _selected_sanitizer_names, _silent_bug_found, _target_tool_name
        
        loop = asyncio.new_event_loop()
        
        if self.target_tool in ["*", None]:
            logger.info("Scanning MCP server to discover all tools")
            try:
                tools_to_fuzz = loop.run_until_complete(self.inspector.fetch_all_tools())
                logger.info(f"Found {len(tools_to_fuzz)} tools to fuzz: {tools_to_fuzz}")
            except Exception as e:
                logger.error(f"Failed to list tools from MCP server: {e}")
                return
        else:
            tools_to_fuzz = [self.target_tool]

        for tool in tools_to_fuzz:
            logger.info(f"\n{'='*20} STARTING COVERAGE-GUIDED FUZZING FOR TOOL: {tool} {'='*20}")
            
            try:
                t_name, t_desc, t_schema = loop.run_until_complete(self.inspector.fetch_tool_metadata(tool))
            except Exception as e:
                logger.error(f"Failed to inspect tool '{tool}': {e}. Skipping.")
                continue

            _target_tool_name = tool
            _selected_sanitizer_names = self.llm.select_sanitizers(t_name, t_desc, t_schema, sanitizers.AVAILABLE_SANITIZERS)
            if not _selected_sanitizer_names:
                raise ValueError(f"No sanitizers selected for tool '{tool}'. Fuzzing cannot proceed without active security sanitizers.")
            _current_schema = t_schema
            _silent_bug_found = False
            
            seeds = self.llm.generate_seeds(t_name, t_desc, t_schema)
            if os.path.exists(self.corpus_dir):
                shutil.rmtree(self.corpus_dir)
            os.makedirs(self.corpus_dir)

            for idx, seed in enumerate(seeds):
                with open(os.path.join(self.corpus_dir, f"seed_{idx}.json"), "w") as f:
                    json.dump(seed, f)

            is_js = any(arg.endswith(".js") for arg in self.args) or "node" in self.command
            if is_js:
                _current_runner = JSRunner(self.command, self.args, tool)
                logger.info(f"[{tool}] Using JS Runner")
            else:
                _current_runner = PythonRunner(self.command, self.args, tool)
                logger.info(f"[{tool}] Using Python Runner")

            if not is_js:
                modules_to_instrument = []
                py_file = None
                for arg in self.args:
                    if arg.endswith(".py"):
                        py_file = os.path.basename(arg)
                        break
                if py_file:
                    modules_to_instrument.append(os.path.splitext(py_file)[0])
                
                for root, dirs, files in os.walk("."):
                    dirs[:] = [d for d in dirs if not d.startswith(".") and d not in ("node_modules", ".venv", "fuzz_corpus")]
                    for file in files:
                        if file.endswith(".py") and file != "__init__.py":
                            modules_to_instrument.append(os.path.splitext(file)[0])
                
                logger.info(f"[{tool}] Instrumenting local Python modules: {list(set(modules_to_instrument))}")
                atheris.instrument_imports(include=list(set(modules_to_instrument)))

            try:
                _current_runner.start()
            except Exception as e:
                logger.error(f"Failed to start runner: {e}")
                continue

            atheris_args = [sys.argv[0], f"-max_total_time={time_per_iteration}", "-artifact_prefix=/tmp/", self.corpus_dir]
            
            atheris.Setup(atheris_args, _test_one_input_factory())
            
            try:
                atheris.Fuzz()
            except SystemExit:
                pass
            except Exception as e:
                logger.error(f"Error during Atheris execution: {e}")

            _current_runner.stop()

            for file in os.listdir("."):
                if file.startswith("crash-"):
                    try:
                        os.remove(file)
                    except Exception:
                        pass

            if not _silent_bug_found:
                logger.info(f"Fuzzing session for '{tool}' completed. No silent bugs detected with current coverage.")

            if os.path.exists(self.corpus_dir):
                shutil.rmtree(self.corpus_dir)
