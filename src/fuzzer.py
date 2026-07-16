import sys
import os
import shutil
import json
import asyncio
import time
import logging
import glob

from .llm import LLMHandler
from .client import MCPInspector
from . import sanitizers
from .runners import PythonRunner, JSRunner
from .config import FuzzerConfig
from .reporters import CompositeVulnerabilityReporter, MongoVulnerabilityReporter, ConsoleVulnerabilityReporter
from .input_parser import FuzzInputParser
from .file_manager import FuzzFileManager
from .engine import AtherisFuzzingEngine

from .runners.base import BaseRunner

logger = logging.getLogger(__name__)

class MCPDifferentialFuzzer:
    def __init__(self, command: str, args: list, target_tool: str, api_key: str, 
                 corpus_dir: str = "./fuzz_corpus", override_rules: dict = None, 
                 file_backed_params: dict = None, config: FuzzerConfig = None, 
                 reporter = None, metadata_provider = None, runner_factory = None,
                 predefined_seeds: list = None):
        self.command = command
        self.args = args
        self.target_tool = target_tool
        self.corpus_dir = corpus_dir
        self.llm = LLMHandler(api_key=api_key)
        self.override_rules = override_rules or {}
        self.file_backed_params = file_backed_params or {}
        self.config = config or FuzzerConfig()
        self.predefined_seeds = predefined_seeds or []
        self.target_tool_desc = ""
        
        # Inject metadata provider
        if metadata_provider is None:
            from .client import MCPInspector
            self.inspector = MCPInspector(command=command, args=args)
        else:
            self.inspector = metadata_provider

        # Inject runner factory
        if runner_factory is None:
            self.runner_factory = self._default_runner_factory
        else:
            self.runner_factory = runner_factory

        if reporter is None:
            self.reporter = CompositeVulnerabilityReporter([
                ConsoleVulnerabilityReporter(),
                MongoVulnerabilityReporter()
            ])
        else:
            self.reporter = reporter
            
        self.current_runner = None
        self.current_schema = None
        self.selected_sanitizer_names = []
        self.selected_sanitizer_rules = {}
        self.silent_bug_found = False
        self.target_tool_name = ""

        # Instantiated helpers
        self.file_manager = FuzzFileManager(self.file_backed_params)
        self.input_parser = None

    def _default_runner_factory(self, tool: str) -> BaseRunner:
        is_js = (
            any(arg.endswith(".js") for arg in self.args) or 
            any(js_cmd in self.command for js_cmd in ("node", "npx", "npm", "yarn", "pnpm"))
        )
        if is_js:
            from .runners import JSRunner
            return JSRunner(self.command, self.args, tool)
        else:
            from .runners import PythonRunner
            return PythonRunner(self.command, self.args, tool)

    def test_one_input(self, data: bytes) -> None:
        """The callback executed by Atheris for each input permutation."""
        if self.current_runner is None or self.current_schema is None:
            return

        # 1. Parse Input using delegated parser helper
        generated_arguments, parsed_successfully = self.input_parser.parse(data)

        # 2. Prepare File-Backed Parameters using delegated file manager helper
        generated_arguments, created_temp_files = self.file_manager.prepare_file_params(generated_arguments)

        # 3. Execute and Measure
        res, elapsed, leaked_files = self._execute_and_time(generated_arguments, created_temp_files)

        # 4. Run Sanitizers
        sanitizer_triggered, triggered_by, err_details = self._run_sanitizers(
            generated_arguments, res, elapsed, leaked_files
        )

        # 5. Handle Violations
        if sanitizer_triggered:
            self._handle_violation(generated_arguments, res.result, triggered_by, err_details)

    def _handle_violation(self, inputs: dict, result: any, triggered_by: list[str], err_details: str) -> None:
        """Logs the triggered security exception and terminates process."""
        self.reporter.report(
            self.target_tool_name,
            inputs,
            result,
            triggered_by,
            err_details
        )
        self.silent_bug_found = True
        sys.exit(1)

    def _execute_and_time(self, generated_arguments: dict, created_temp_files: list[str]) -> tuple[any, float, set[str]]:
        """Executes the runner, measures duration, and detects leaked temporary files."""
        import tempfile as tf_mod
        temp_dir = tf_mod.gettempdir()
        try:
            before_files = set(glob.glob(os.path.join(temp_dir, "*")))
        except Exception:
            before_files = set()

        start_time = time.time()
        try:
            res = self.current_runner.execute(generated_arguments)
        finally:
            self.file_manager.clean_temp_files(created_temp_files)
        elapsed = time.time() - start_time

        try:
            after_files = set(glob.glob(os.path.join(temp_dir, "*")))
        except Exception:
            after_files = set()
        
        leaked_files = {f for f in (after_files - before_files) if not f.endswith((".cpuprofile", ".cpuprofile.json")) and "systemd-private-" not in f}

        return res, elapsed, leaked_files

    def _run_sanitizers(self, generated_arguments: dict, res: any, elapsed: float, leaked_files: set[str]) -> tuple[bool, list[str], str]:
        """Runs the fuzzer's active security sanitizers on input/execution details."""
        triggered_by = []
        err_details = ""

        # 1. Check temp file leaks
        leak_triggered, leak_err = self._check_temp_file_leak(leaked_files)
        if leak_triggered:
            triggered_by.append("check_temp_file_leak")
            err_details += leak_err

        # 2. Check resource exhaustion / timeout (e.g. ReDoS)
        timeout_triggered, timeout_err = self._check_resource_exhaustion(elapsed)
        if timeout_triggered:
            triggered_by.append("check_resource_exhaustion")
            err_details += timeout_err

        # 3. Check unexpected library/runtime crashes
        crash_triggered, crash_err = self._check_unexpected_crash(res)
        if crash_triggered:
            triggered_by.append("check_unexpected_crash")
            err_details += crash_err

        # 4. Check standard string-based sanitizers
        string_triggered, string_triggered_by, string_err = self._check_string_sanitizers(generated_arguments, res)
        if string_triggered:
            for s_name in string_triggered_by:
                if s_name not in triggered_by:
                    triggered_by.append(s_name)
            err_details += string_err

        sanitizer_triggered = bool(triggered_by)
        return sanitizer_triggered, triggered_by, err_details

    def _check_temp_file_leak(self, leaked_files: set[str]) -> tuple[bool, str]:
        """Returns True and diagnostic message if temporary files were leaked."""
        if "check_temp_file_leak" in self.selected_sanitizer_names and leaked_files:
            err = f"Temp file leak detected: {list(leaked_files)}. "
            for f in leaked_files:
                try:
                    if os.path.isdir(f):
                        shutil.rmtree(f)
                    else:
                        os.remove(f)
                except Exception:
                    pass
            return True, err
        return False, ""

    def _check_resource_exhaustion(self, elapsed: float) -> tuple[bool, str]:
        """Returns True and diagnostic message if execution duration exceeds config limits."""
        if "check_resource_exhaustion" in self.selected_sanitizer_names and elapsed > self.config.timeout_limit:
            err = f"Resource exhaustion/Timeout detected: Execution took {elapsed:.2f} seconds (Limit: {self.config.timeout_limit}s). "
            return True, err
        return False, ""

    def _check_unexpected_crash(self, res: any) -> tuple[bool, str]:
        """Returns True and diagnostic message if an unhandled library exception is captured."""
        if not res.success and res.error:
            if any(crash_name in res.error for crash_name in self.config.unexpected_crashes):
                err = f"Unexpected library/runtime crash: {res.error}. "
                return True, err
        return False, ""

    def _check_string_sanitizers(self, generated_arguments: dict, res: any) -> tuple[bool, list[str], str]:
        """Checks string inputs against selected security vulnerability checkers."""
        if not res.success:
            return False, [], ""

        triggered_by = []
        err_details = ""
        
        for prop_name, val in generated_arguments.items():
            if not isinstance(val, str):
                continue
                
            for sanitizer_name in self.selected_sanitizer_names:
                if sanitizer_name in ("check_temp_file_leak", "check_resource_exhaustion"):
                    continue
                
                # Context checks
                if sanitizer_name in ("check_unsafe_url_ssrf", "check_local_file_uri"):
                    prop_lower = prop_name.lower()
                    if not ("url" in prop_lower or "uri" in prop_lower or "link" in prop_lower or "path" in prop_lower):
                        continue

                sanitizer_fn = getattr(sanitizers, sanitizer_name, None)
                if sanitizer_fn and sanitizer_fn(val):
                    rule = self.selected_sanitizer_rules.get(sanitizer_name, {})
                    if rule.get("on_trigger") == "allow_success_always":
                        continue
                    elif rule.get("on_trigger") == "allow_success_with_fallback":
                        expected_fallbacks = rule.get("expected_fallback_values", [])
                        if self._matches_fallback_value(res.result, expected_fallbacks):
                            continue
                    
                    if sanitizer_name not in triggered_by:
                        triggered_by.append(sanitizer_name)

        if triggered_by:
            err_details = f"Silent Bug Alert: Sanitizers {triggered_by} flagged this input as malicious, but the target tool executed successfully without raising any exception. "
            return True, triggered_by, err_details
            
        return False, [], ""

    def _matches_fallback_value(self, result_val: any, expected_fallbacks: list) -> bool:
        """Determines if the success output matches configured fallback options."""
        actual_fallbacks = list(expected_fallbacks) if expected_fallbacks else [[]]
        if result_val in actual_fallbacks:
            return True
        for fb in actual_fallbacks:
            if str(result_val) == str(fb):
                return True
            try:
                if isinstance(result_val, str) and json.loads(result_val) == fb:
                    return True
            except Exception:
                pass
        return False

    def run(self, max_iterations: int = 5, time_per_iteration: int = 20):
        tools_to_fuzz = self._discover_tools()
        if not tools_to_fuzz:
            return
        
        for tool in tools_to_fuzz:
            logger.info(f"\n{'='*20} STARTING COVERAGE-GUIDED FUZZING FOR TOOL: {tool} {'='*20}")
            
            initialized = self._initialize_tool_fuzzing(tool)
            if not initialized:
                continue

            self._setup_corpus_seeds()
            modules_to_instrument = self._resolve_instrumented_modules()

            started = self._start_runner(tool, modules_to_instrument)
            if not started:
                continue

            self._execute_fuzzing(time_per_iteration)
            self._cleanup_runner()

    def _discover_tools(self) -> list[str]:
        """Discovers the list of target tools from the MCP server."""
        loop = asyncio.new_event_loop()
        if self.target_tool in ["*", None]:
            logger.info("Scanning MCP server to discover all tools")
            try:
                tools = loop.run_until_complete(self.inspector.fetch_all_tools())
                logger.info(f"Found {len(tools)} tools to fuzz: {tools}")
                return tools
            except Exception as e:
                logger.error(f"Failed to list tools from MCP server: {e}")
                return []
        else:
            return [self.target_tool]

    def _initialize_tool_fuzzing(self, tool: str) -> bool:
        """Performs LLM sanitizer selection and initial setups for a target tool."""
        loop = asyncio.new_event_loop()
        try:
            t_name, t_desc, t_schema = loop.run_until_complete(self.inspector.fetch_tool_metadata(tool))
        except Exception as e:
            logger.error(f"Failed to inspect tool '{tool}': {e}. Skipping.")
            return False

        self.target_tool_name = tool
        self.target_tool_desc = t_desc
        self.selected_sanitizer_names, self.selected_sanitizer_rules = self.llm.select_sanitizers(
            t_name, t_desc, t_schema, sanitizers.AVAILABLE_SANITIZERS
        )
        
        if self.override_rules:
            for k, v in self.override_rules.items():
                if k not in self.selected_sanitizer_names:
                    self.selected_sanitizer_names.append(k)
                self.selected_sanitizer_rules[k] = v
                
        if not self.selected_sanitizer_names:
            raise ValueError(f"No sanitizers selected for tool '{tool}'. Fuzzing cannot proceed without active security sanitizers.")
        
        self.current_schema = t_schema
        self.silent_bug_found = False

        # Initialize the parser adapter with the current tool schema
        self.input_parser = FuzzInputParser(self.current_schema, self.file_backed_params, self.current_runner)
        return True

    def _setup_corpus_seeds(self) -> None:
        """Generates the initial fuzzing corpus via LLM or uses predefined seeds."""
        if self.predefined_seeds:
            seeds = self.predefined_seeds
        else:
            seeds = self.llm.generate_seeds(self.target_tool_name, self.target_tool_desc, self.current_schema)
        if os.path.exists(self.corpus_dir):
            shutil.rmtree(self.corpus_dir)
        os.makedirs(self.corpus_dir)

        for idx, seed in enumerate(seeds):
            with open(os.path.join(self.corpus_dir, f"seed_{idx}.json"), "w") as f:
                json.dump(seed, f)

    def _resolve_instrumented_modules(self) -> list[str]:
        """Resolves the set of Python modules to instrument for coverage tracking."""
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
        
        # Also instrument top-level Python packages in the workspace directory
        for item in os.listdir("."):
            if os.path.isdir(item) and not item.startswith(".") and item not in ("node_modules", ".venv", "fuzz_corpus", "src", "tests"):
                try:
                    if any(f.endswith(".py") for r, d, fs in os.walk(item) for f in fs):
                        modules_to_instrument.append(item)
                except Exception:
                    pass

        # Instrument configured dependencies
        for dep in self.config.dependencies_to_instrument:
            try:
                __import__(dep)
                modules_to_instrument.append(dep)
            except ImportError:
                pass
                
        return list(set(modules_to_instrument))

    def _start_runner(self, tool: str, modules_to_instrument: list[str]) -> bool:
        """Initializes and launches the execution runner."""
        self.current_runner = self.runner_factory(tool)
        logger.info(f"[{tool}] Using runner: {self.current_runner.__class__.__name__}")

        # Re-initialize the parser with the runner in place
        self.input_parser.current_runner = self.current_runner

        try:
            # Check if JSRunner is being used (or if it's explicitly node/JS)
            is_js = "JSRunner" in self.current_runner.__class__.__name__ or getattr(self.current_runner, "is_js", False)
            if not is_js:
                logger.info(f"[{tool}] Instrumenting local Python modules: {modules_to_instrument}")
                import atheris
                with atheris.instrument_imports(include=modules_to_instrument):
                    self.current_runner.start()
            else:
                logger.info(f"[{tool}] Instrumenting JS fake coverage helper module.")
                import atheris
                with atheris.instrument_imports(include=["src.runners.fake_coverage"]):
                    self.current_runner.start()
            return True
        except Exception as e:
            logger.error(f"Failed to start runner: {e}")
            return False

    def _execute_fuzzing(self, time_per_iteration: int) -> None:
        """Runs the fuzzer loop via the engine driver."""
        engine = AtherisFuzzingEngine(self.corpus_dir, time_per_iteration)
        engine.fuzz(self.test_one_input)

    def _cleanup_runner(self) -> None:
        """Stops the runner and removes temporary crash logs."""
        if self.current_runner:
            self.current_runner.stop()

        for file in os.listdir("."):
            if file.startswith("crash-"):
                try:
                    os.remove(file)
                except Exception:
                    pass

        if not self.silent_bug_found:
            logger.info(f"Fuzzing session completed. No silent bugs detected with current coverage.")

        if os.path.exists(self.corpus_dir):
            shutil.rmtree(self.corpus_dir)

    def run_single(self, input_data: dict) -> None:
        """Executes a single test run on the tool and displays results."""
        tools_to_fuzz = self._discover_tools()
        if not tools_to_fuzz:
            logger.error("No tools discovered.")
            return
            
        # Target tool name resolution
        target = self.target_tool or (tools_to_fuzz[0] if tools_to_fuzz else None)
        if not target:
            logger.error("No target tool specified.")
            return
            
        if target not in tools_to_fuzz:
            logger.error(f"Tool '{target}' not found in discovered tools: {tools_to_fuzz}")
            return
            
        initialized = self._initialize_tool_fuzzing(target)
        if not initialized:
            logger.error("Failed to initialize tool execution.")
            return
            
        modules = self._resolve_instrumented_modules()
        started = self._start_runner(target, modules)
        if not started:
            logger.error("Failed to start tool execution runner.")
            return
            
        try:
            logger.info(f"[*] Executing '{target}' with arguments: {input_data}")
            result = self.current_runner.execute(input_data)
            
            print("\n" + "="*20 + " RESULTS " + "="*20)
            print(f"Status   : {'SUCCESS' if result.success else 'FAILED'}")
            if result.success:
                print(f"Output   : {result.result}")
            else:
                print(f"Error    : {result.error}")
            print(f"Coverage : {len(result.coverage)} block(s) hit")
            if result.coverage:
                print("Block Hits:")
                for cov in list(result.coverage)[:10]:
                    print(f" - {cov}")
                if len(result.coverage) > 10:
                    print(f" ... and {len(result.coverage) - 10} more blocks")
            print("="*49)
        except Exception as e:
            logger.error(f"Error during execution: {e}")
        finally:
            if self.current_runner:
                self.current_runner.stop()
