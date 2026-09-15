import sys
import os
import re
import site
import importlib
import importlib.util
import inspect
import time
from typing import Callable, Dict, Any, Optional, Tuple
from .base import BaseRunner, RunnerResult
from ..sanitizers.introspection import (
    FileAccessTracer,
    DeserializationTracer,
    CommandExecutionTracer,
    SQLExecutionTracer,
    FileWriteTracer,
    CodeExecutionTracer,
    NetworkExecutionTracer,
    TempFileLeakTracer,
    LogInjectionTracer,
    SensitiveDataLoggingTracer,
    SSLCertificateValidationTracer,
    UnrestrictedIPBindingTracer,
    ReDoSTracer,
    BlockingEventLoopCallTracer,
    WeakHashTracer,
    WeakPRNGTracer,
    NonceReuseTracer,
    UnverifiedCodeDownloadTracer,
    XXETracer,
    DataAmplificationTracer
)


# ---------------------------------------------------------------------------
# Target discovery helpers (pure functions; unit-tested in
# tests/test_python_runner_discovery.py).
#
# HISTORY (nazmul.todo item 86, 2026-09-15): every Python row of the
# gpt41-full campaign (44/44) was `executable: unknown, n_exec=0` -- the
# runner never imported a single real target. Three independent causes:
#   A. prepare_targets emits the venv CONSOLE SCRIPT (.venv/bin/osm-mcp-server,
#      args=[]) and start() fed that PATH to importlib.import_module().
#   B. FastMCP tools live in the server instance's registry, not as
#      module-level callables; uml-mcp even resolves `mcp` lazily through a
#      module __getattr__, so dir(module) never lists it.
#   C. The target's dependencies were never importable: ToFu is py3.11 + mcp
#      2.x, target venvs were py3.10-3.14 + mcp 1.x, and src/fuzzer.py
#      pre-imports 107 mcp 2.x modules via MCPInspector, so a target's
#      `from mcp.server.fastmcp import FastMCP` could never resolve.
# ToFu reports nothing when this fails -- so every failure below is LOUD.
# ---------------------------------------------------------------------------

_INTERP_RE = re.compile(r"^python(\d+(\.\d+)?)?(\.exe)?$")
_SERVER_ATTR_NAMES = ("mcp", "server", "app", "srv", "mcp_server", "fastmcp", "api")
_SERVER_FACTORY_NAMES = ("get_mcp_server", "create_mcp_server", "create_server",
                         "build_server", "get_server", "create_app", "make_server",
                         "get_app")


def _is_interpreter(command: str) -> bool:
    return bool(_INTERP_RE.match(os.path.basename(command or "")))


def _venv_root_from_command(command: str) -> Optional[str]:
    """/x/.venv/bin/<anything> -> /x/.venv, only if it really is a venv."""
    if not command:
        return None
    bindir = os.path.dirname(os.path.abspath(command))
    if os.path.basename(bindir) not in ("bin", "Scripts"):
        return None
    root = os.path.dirname(bindir)
    return root if os.path.exists(os.path.join(root, "pyvenv.cfg")) else None


def _venv_site_packages(venv_root: str) -> Tuple[Optional[str], list]:
    """(site-packages for the RUNNING interpreter or None, [pythonX.Y tags found])."""
    lib = os.path.join(venv_root, "lib")
    tags = []
    if os.path.isdir(lib):
        tags = sorted(n for n in os.listdir(lib) if n.startswith("python"))
    want = f"python{sys.version_info.major}.{sys.version_info.minor}"
    sp = os.path.join(lib, want, "site-packages")
    return (sp if os.path.isdir(sp) else None), tags


def _parse_console_script(path: str) -> Optional[Tuple[str, str]]:
    """Read a pip/uv console-script shim and return (module, attr).

    Shims look like:  from osm_mcp_server import main ... sys.exit(main())
    We import the MODULE and never call the attr (it would run the server).
    """
    try:
        with open(path, "rb") as f:
            head = f.read(65536)
        if not head.startswith(b"#!"):
            return None
        text = head.decode("utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    m = re.search(r"^from\s+([\w\.]+)\s+import\s+(\w+)", text, re.M)
    if m:
        return m.group(1), m.group(2)
    m = re.search(r"^import\s+([\w\.]+)", text, re.M)
    if m:
        return m.group(1), ""
    return None


def _entry_from_pyproject(project_dir: str, script_name: str) -> Optional[Tuple[str, str]]:
    """[project.scripts] / [tool.poetry.scripts] lookup -> (module, func)."""
    pp = os.path.join(project_dir or "", "pyproject.toml")
    if not os.path.exists(pp):
        return None
    try:
        import tomllib
        with open(pp, "rb") as f:
            data = tomllib.load(f)
        scripts = {}
        scripts.update((data.get("project") or {}).get("scripts") or {})
        scripts.update(((data.get("tool") or {}).get("poetry") or {}).get("scripts") or {})
        target = scripts.get(script_name)
        if not target or not isinstance(target, str):
            return None
        mod, _, func = target.partition(":")
        return mod.strip(), func.strip()
    except Exception:
        return None


def _is_fastmcp_like(obj) -> bool:
    """FastMCP (mcp 1.x, fastmcp 2-4) or MCPServer (mcp 2.x), incl. subclasses."""
    if isinstance(obj, type):
        return False
    for c in type(obj).__mro__:
        if c.__name__ in ("FastMCP", "MCPServer"):
            return True
        mod = getattr(c, "__module__", "") or ""
        if mod == "fastmcp" or mod.startswith(("mcp.server.fastmcp", "mcp.server.mcpserver", "fastmcp.")):
            return True
    return False


def _is_lowlevel_server(obj) -> bool:
    if isinstance(obj, type):
        return False
    for c in type(obj).__mro__:
        if c.__name__ == "Server" and (getattr(c, "__module__", "") or "").startswith("mcp.server"):
            return True
    return False


def _lowlevel_of(inst):
    # mcp 1.x FastMCP: ._mcp_server ; mcp 2.x MCPServer: ._lowlevel_server
    return getattr(inst, "_mcp_server", None) or getattr(inst, "_lowlevel_server", None)


def _registry_tools(inst) -> Dict[str, Any]:
    """Every tool object the server instance knows, keyed by registered name."""
    out: Dict[str, Any] = {}
    cands = []
    tm = getattr(inst, "_tool_manager", None)
    if tm is not None:
        cands.append(getattr(tm, "_tools", None))
        cands.append(getattr(tm, "_tool_specs", None))
    cands.append(getattr(inst, "_tools", None))
    lp = getattr(inst, "local_provider", None)
    if lp is not None:
        cands.append(getattr(lp, "_tools", None))
    for d in cands:
        if not isinstance(d, dict):
            continue
        for k, v in d.items():
            out.setdefault(str(k), v)
            nm = getattr(v, "name", None)
            if isinstance(nm, str):
                out.setdefault(nm, v)
    return out


def _tool_callable(tool_obj) -> Optional[Callable]:
    if tool_obj is None:
        return None
    fn = getattr(tool_obj, "fn", None) or getattr(tool_obj, "func", None)
    if callable(fn):
        return fn
    return tool_obj if callable(tool_obj) else None


def _wants_context(fn: Callable) -> bool:
    """True if a direct call could not supply the MCP Context the tool expects."""
    try:
        sig = inspect.signature(fn)
    except (TypeError, ValueError):
        return False
    for name, p in sig.parameters.items():
        ann = p.annotation
        ann_name = getattr(ann, "__name__", None) or (ann if isinstance(ann, str) else "")
        if isinstance(ann_name, str) and ann_name.split(".")[-1] == "Context":
            return True
        if name in ("ctx", "context") and p.default is inspect.Parameter.empty:
            return True
    return False


def _ships_own_sdk(site_packages: str) -> bool:
    return bool(site_packages) and os.path.isdir(os.path.join(site_packages, "mcp"))


def _dist_version(site_packages: str, dist: str) -> str:
    try:
        for n in os.listdir(site_packages):
            if n.lower().startswith(dist.lower() + "-") and n.endswith(".dist-info"):
                with open(os.path.join(site_packages, n, "METADATA"), encoding="utf-8", errors="ignore") as f:
                    for line in f:
                        if line.startswith("Version:"):
                            return line.split(":", 1)[1].strip()
    except OSError:
        pass
    return "?"


class PythonRunner(BaseRunner):
    def __init__(self, command: str, args: list, target_tool: str, cwd: Optional[str] = None,
                 custom_env: Optional[dict] = None):
        super().__init__(command, args, target_tool)
        self.target_func: Callable = None
        self.module_name = ""
        self.fastmcp_instance = None
        self.mcp_server = None
        self.enable_trace = True
        # BUG 21 plumbing: the target's own directory (configs' "cwd").
        self.cwd = os.path.abspath(cwd) if cwd else None
        # Placeholder credentials the target is meant to see (config "env");
        # everything else credential-shaped is scrubbed from os.environ before
        # the in-process import (runners/secrets.py).
        self.custom_env = dict(custom_env or {})
        self.scrubbed_env_names: list = []
        self.entry_attr = ""            # console-script function name, never called
        self.tool_schema: Optional[dict] = None
        self.tool_description: Optional[str] = None
        self.site_packages: Optional[str] = None
        self.sdk_shadowed = False

    # ------------------------------------------------------------------ env
    def predict_module_name(self) -> str:
        """Best-effort target module name WITHOUT importing anything.

        fuzzer._start_runner needs it before start(): atheris only instruments
        packages named in instrument_imports(include=...), and module_name used
        to be "" until start() ran -- so the target package was never
        instrumented and libFuzzer fuzzed blind.
        """
        for arg in self.args:
            if arg.endswith(".py"):
                base = os.path.splitext(os.path.basename(arg))[0]
                return "mcp_target_module" if base == "__main__" else base
        if "-m" in self.args:
            idx = self.args.index("-m")
            if idx + 1 < len(self.args):
                return self.args[idx + 1]
        if not _is_interpreter(self.command):
            entry = _parse_console_script(self.command)
            if not entry:
                root = self.cwd or (os.path.dirname(_venv_root_from_command(self.command) or "") or "")
                entry = _entry_from_pyproject(root, os.path.basename(self.command))
            if entry:
                return entry[0]
        return ""

    _NOT_TARGET_DIRS = {".venv", "venv", "node_modules", "tests", "test", "docs", "examples",
                        "build", "dist", "__pycache__", "site-packages", "fuzz_corpus"}

    def predict_instrument_packages(self) -> list:
        """Top-level package names atheris must instrument, WITHOUT importing.

        predict_module_name() alone is not enough when the launch file is a
        thin entry script: uml-mcp starts as `python server.py`, whose 30 lines
        import everything from `mcp_core.*`. Instrumenting only `server` gave
        libFuzzer zero coverage features and it exited after the seed corpus
        ("no interesting inputs"), silently (2026-09-15). So also include every
        package directory under the target's cwd and cwd/src.
        """
        names = set()
        mod = self.predict_module_name()
        if mod:
            names.add(mod)
            names.add(mod.split(".")[0])
        for root in (self.cwd, os.path.join(self.cwd, "src") if self.cwd else None):
            if not root or not os.path.isdir(root):
                continue
            try:
                entries = os.listdir(root)
            except OSError:
                continue
            for e in entries:
                if e.startswith(".") or e in self._NOT_TARGET_DIRS:
                    continue
                p = os.path.join(root, e)
                if os.path.isdir(p) and os.path.exists(os.path.join(p, "__init__.py")):
                    names.add(e)
                elif e.endswith(".py") and e != "__init__.py" and not e.startswith("test"):
                    names.add(e[:-3])
        return sorted(n for n in names if n)

    def _activate_target_env(self):
        """Make the target venv's site-packages importable, at the FRONT of sys.path.

        Raises loudly on an interpreter-version mismatch: a cp313 wheel cannot
        load into ToFu's cp311 process, and a silent fallback here is exactly
        the "healthy 0 findings" failure mode this codebase keeps producing.
        """
        venv = _venv_root_from_command(self.command)
        if venv is None and self.cwd:
            cand = os.path.join(self.cwd, ".venv")
            if os.path.exists(os.path.join(cand, "pyvenv.cfg")):
                venv = cand
        if venv is None:
            return
        sp, tags = _venv_site_packages(venv)
        if sp is None:
            if tags:
                cur = f"python{sys.version_info.major}.{sys.version_info.minor}"
                raise RuntimeError(
                    f"target venv {venv} was built for {', '.join(tags)} but ToFu runs "
                    f"{cur}; in-process import is impossible. Re-prepare the target with "
                    f"TOFU_TARGET_PYTHON={sys.version_info.major}.{sys.version_info.minor} "
                    f"(eval/prepare_targets.py --redo --only-repo <repo>).")
            return
        self.site_packages = sp
        before = list(sys.path)
        site.addsitedir(sp)                       # honours .pth (editable installs)
        added = [p for p in sys.path if p not in before]
        for p in added:
            sys.path.remove(p)
        front = []
        if self.cwd:
            for extra in (os.path.join(self.cwd, "src"), self.cwd):
                if os.path.isdir(extra):
                    front.append(extra)
        for p in front + added:
            if p in sys.path:
                sys.path.remove(p)
        sys.path[:0] = front + added
        # ToFu's own MCP SDK (mcp 2.x) is already imported by src.client. If the
        # target ships its own `mcp` (1.x API: mcp.server.fastmcp), drop the
        # cached modules so the target's version is what its imports resolve to.
        # Objects ToFu already bound (MCPInspector's ClientSession) keep working.
        if _ships_own_sdk(sp):
            mine = sys.modules.get("mcp")
            mine_file = getattr(mine, "__file__", "") or ""
            if mine is None or not mine_file.startswith(os.path.abspath(sp)):
                purged = [k for k in sys.modules if k == "mcp" or k.startswith("mcp.")]
                for k in purged:
                    del sys.modules[k]
                self.sdk_shadowed = True
                print(f"[PythonRunner] shadowing ToFu's mcp with target's mcp "
                      f"{_dist_version(sp, 'mcp')} from {sp} ({len(purged)} cached modules dropped)",
                      file=sys.stderr)

    # -------------------------------------------------------------- import
    def _load_file_module(self, py_file: str):
        base_name = os.path.splitext(os.path.basename(py_file))[0]
        py_dir = os.path.dirname(py_file)
        if py_dir not in sys.path:
            sys.path.insert(0, py_dir)
        if base_name == "__main__":
            self.module_name = "mcp_target_module"
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
            return module
        self.module_name = base_name
        try:
            return importlib.import_module(self.module_name)
        except Exception:
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
            return module

    def _import_target(self):
        py_file = None
        for arg in self.args:
            if arg.endswith(".py"):
                py_file = os.path.abspath(arg)
                break
        if py_file:
            return self._load_file_module(py_file)

        if "-m" in self.args:
            idx = self.args.index("-m")
            if idx + 1 < len(self.args):
                self.module_name = self.args[idx + 1]
                try:
                    return importlib.import_module(self.module_name)
                except ImportError:
                    return importlib.import_module(f"{self.module_name}.__main__")

        if not _is_interpreter(self.command):
            # Bug A: a console-script shim. Import the module it names; NEVER
            # call the entry function (it starts the stdio server and blocks).
            entry = _parse_console_script(self.command)
            if not entry:
                root = self.cwd or os.path.dirname(_venv_root_from_command(self.command) or "")
                entry = _entry_from_pyproject(root, os.path.basename(self.command))
            if not entry:
                raise ImportError(
                    f"'{self.command}' is neither a .py file, `-m module`, nor a readable "
                    f"console-script shim (no `from X import Y` line, and no matching "
                    f"[project.scripts] entry in {self.cwd or '<cwd unknown>'}/pyproject.toml)")
            self.module_name, self.entry_attr = entry
            return importlib.import_module(self.module_name)

        if self.args and os.sep not in self.args[-1] and not self.args[-1].startswith("-"):
            self.module_name = self.args[-1]
            return importlib.import_module(self.module_name)

        raise ImportError(
            f"cannot locate a target module: command={self.command!r} args={self.args!r}")

    # ----------------------------------------------------------- discovery
    def _consider(self, obj) -> bool:
        if _is_fastmcp_like(obj):
            self.fastmcp_instance = obj
            self.mcp_server = _lowlevel_of(obj) or self.mcp_server
            return True
        if _is_lowlevel_server(obj):
            self.mcp_server = obj
            return True
        return False

    def _find_server_instance(self, module):
        """Locate the FastMCP/MCPServer (or low-level Server) the target built."""
        # 1. build_server factory kept from the original implementation
        if hasattr(module, "build_server") and callable(getattr(module, "build_server")):
            try:
                try:
                    inst = module.build_server(prewarm=False)
                except TypeError:
                    inst = module.build_server()
                if self._consider(inst):
                    return
            except Exception as e:
                print(f"[PythonRunner] build_server failed: {e}", file=sys.stderr)

        # 2. module globals (plain `mcp = FastMCP(...)` at module level)
        for attr in list(vars(module).values()):
            if self._consider(attr) and self.fastmcp_instance is not None:
                return

        # 3. conventional names via getattr -- fires a module-level __getattr__
        #    (uml-mcp resolves `mcp` lazily so it is absent from dir()).
        for name in _SERVER_ATTR_NAMES:
            try:
                obj = getattr(module, name, None)
            except Exception:
                obj = None
            if obj is not None and self._consider(obj) and self.fastmcp_instance is not None:
                return

        # 4. zero-arg factories
        for name in _SERVER_FACTORY_NAMES:
            fac = getattr(module, name, None)
            if not callable(fac):
                continue
            try:
                inst = fac()
            except Exception as e:
                print(f"[PythonRunner] {name}() failed: {e}", file=sys.stderr)
                continue
            if self._consider(inst) and self.fastmcp_instance is not None:
                return

        # 5. submodules of the imported package (osm_mcp_server.server.mcp)
        prefix = (self.module_name or "").split(".")[0]
        if prefix:
            for name, mod in list(sys.modules.items()):
                if mod is None or not (name == prefix or name.startswith(prefix + ".")):
                    continue
                for attr in list(vars(mod).values()):
                    if self._consider(attr) and self.fastmcp_instance is not None:
                        return

    def _lookup_tool(self, module):
        inst = self.fastmcp_instance
        tool_obj = None
        if inst is not None:
            tool_obj = _registry_tools(inst).get(self.target_tool)
            if tool_obj is None:
                for meth in ("get_tools", "list_tools"):
                    lister = getattr(inst, meth, None)
                    if lister is None:
                        continue
                    try:
                        import asyncio
                        res = lister()
                        if inspect.isawaitable(res):
                            loop = asyncio.new_event_loop()
                            try:
                                res = loop.run_until_complete(res)
                            finally:
                                loop.close()
                        items = res.values() if isinstance(res, dict) else (res or [])
                        for t in items:
                            if getattr(t, "name", None) == self.target_tool:
                                tool_obj = t
                                break
                    except Exception:
                        pass
                    if tool_obj is not None:
                        break
        if tool_obj is not None:
            self.tool_schema = getattr(tool_obj, "parameters", None) or getattr(tool_obj, "inputSchema", None)
            self.tool_description = getattr(tool_obj, "description", None)
            fn = _tool_callable(tool_obj)
            needs_ctx = bool(getattr(tool_obj, "context_kwarg", None)) or (fn is not None and _wants_context(fn))
            # Prefer the in-process JSON-RPC server whenever the target built
            # one: it applies the server's own argument validation/coercion and
            # isError semantics, which is what the silent-bug oracle judges. A
            # bare fn(**args) call skips validation (raw dicts where the server
            # would build pydantic models -> spurious TypeErrors counted as
            # rejections, and "successes" the real server would refuse), and
            # cannot supply an MCP Context at all. TOFU_PY_BARE_CALL=1 forces
            # the old direct-call behaviour for A/B comparison.
            bare_forced = bool(os.environ.get("TOFU_PY_BARE_CALL"))
            if self.mcp_server is not None and fn is not None and (not bare_forced or needs_ctx):
                if bare_forced and needs_ctx:
                    print(f"[PythonRunner] '{self.target_tool}' takes an MCP Context -> "
                          f"TOFU_PY_BARE_CALL ignored, calling through the in-process server",
                          file=sys.stderr)
                self.target_func = None
            else:
                self.target_func = fn
            return

        # Module-level callable (plain-function fixtures, Click commands).
        if hasattr(module, self.target_tool):
            candidate = getattr(module, self.target_tool)
            if hasattr(candidate, "callback") and callable(candidate.callback):
                self.target_func = candidate.callback
            elif callable(candidate):
                self.target_func = candidate

    def start(self):
        """Import the target in-process and locate the tool to fuzz."""
        # The target shares this process: anything it can read from
        # /proc/self/environ or os.environ is ours. Scrub before import.
        from .secrets import scrub_process_env
        self.scrubbed_env_names = list(scrub_process_env(keep=self.custom_env))
        self._activate_target_env()
        module = self._import_target()

        self.target_func = None
        self.fastmcp_instance = None
        self.mcp_server = None
        self.tool_schema = None
        self.tool_description = None

        self._find_server_instance(module)
        self._lookup_tool(module)

        if self.target_func is None and self.mcp_server is None:
            known = sorted(_registry_tools(self.fastmcp_instance)) if self.fastmcp_instance is not None else []
            raise AttributeError(
                f"Could not find callable tool/function '{self.target_tool}' in module "
                f"'{self.module_name}' (server instance: "
                f"{type(self.fastmcp_instance).__name__ if self.fastmcp_instance is not None else 'none found'}; "
                f"registered tools: {known[:20]})")
        where = "bare function" if self.target_func is not None else "in-process JSON-RPC server"
        print(f"[PythonRunner] {self.target_tool}: module={self.module_name} via {where}"
              f"{' (target venv site-packages active)' if self.site_packages else ''}",
              file=sys.stderr)

    def execute(self, arguments: dict) -> RunnerResult:
        if not self.target_func and not self.mcp_server:
            return RunnerResult(success=False, coverage=set(), error="Runner not started or function not found")

        covered_lines = set()

        def trace_lines(frame, event, arg):
            if event == 'line':
                code = frame.f_code
                filename = code.co_filename

                # Trace target module, local third_party files, or site-packages dependencies
                is_target = (bool(self.module_name) and self.module_name in filename) or \
                            (bool(self.cwd) and filename.startswith(self.cwd))
                is_dependency = "site-packages" in filename or "third_party" in filename

                if (is_target or is_dependency) and not any(x in filename for x in ["<", "importlib", "encodings", "linecache", "anyio", "mcp"]):
                    covered_lines.add(f"{filename}:{frame.f_lineno}")
            return trace_lines

        success = True
        error_msg = None
        start_time = time.perf_counter()

        val = None
        from ..sanitizers.introspection import (
            FileAccessTracer, DeserializationTracer, CommandExecutionTracer,
            SQLExecutionTracer, FileWriteTracer, CodeExecutionTracer, NetworkExecutionTracer, TempFileLeakTracer,
            LogInjectionTracer, SSLCertificateValidationTracer
        )
        tracer = FileAccessTracer()
        deser_tracer = DeserializationTracer()
        cmd_tracer = CommandExecutionTracer()
        sql_tracer = SQLExecutionTracer()
        file_write_tracer = FileWriteTracer()
        code_tracer = CodeExecutionTracer()
        net_tracer = NetworkExecutionTracer()
        temp_leak_tracer = TempFileLeakTracer()
        log_tracer = LogInjectionTracer()
        ssl_tracer = SSLCertificateValidationTracer()
        bind_tracer = UnrestrictedIPBindingTracer()
        redos_tracer = ReDoSTracer()
        blocking_tracer = BlockingEventLoopCallTracer()
        hash_tracer = WeakHashTracer()
        prng_tracer = WeakPRNGTracer()
        nonce_tracer = NonceReuseTracer()
        download_tracer = UnverifiedCodeDownloadTracer()
        xxe_tracer = XXETracer()
        amplification_tracer = DataAmplificationTracer()

        from contextlib import ExitStack

        # Save previous trace function
        old_trace = sys.gettrace()
        if self.enable_trace:
            sys.settrace(trace_lines)
        try:
            with ExitStack() as stack:
                stack.enter_context(tracer)
                stack.enter_context(deser_tracer)
                stack.enter_context(cmd_tracer)
                stack.enter_context(sql_tracer)
                stack.enter_context(file_write_tracer)
                stack.enter_context(code_tracer)
                stack.enter_context(net_tracer)
                stack.enter_context(temp_leak_tracer)
                stack.enter_context(log_tracer)
                stack.enter_context(ssl_tracer)
                stack.enter_context(bind_tracer)
                stack.enter_context(redos_tracer)
                stack.enter_context(blocking_tracer)
                stack.enter_context(hash_tracer)
                stack.enter_context(prng_tracer)
                stack.enter_context(nonce_tracer)
                stack.enter_context(download_tracer)
                stack.enter_context(xxe_tracer)
                stack.enter_context(amplification_tracer)

                if self.target_func:
                    sig = inspect.signature(self.target_func)
                    has_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())
                    if has_kwargs:
                        call_args = arguments
                    else:
                        call_args = {k: v for k, v in arguments.items() if k in sig.parameters}

                    if inspect.iscoroutinefunction(self.target_func):
                        import asyncio
                        try:
                            loop = asyncio.get_event_loop()
                            if loop.is_running():
                                import nest_asyncio
                                nest_asyncio.apply()
                                val = loop.run_until_complete(self.target_func(**call_args))
                            else:
                                val = loop.run_until_complete(self.target_func(**call_args))
                        except RuntimeError:
                            val = asyncio.run(self.target_func(**call_args))
                    else:
                        val = self.target_func(**call_args)
                elif self.mcp_server:
                    # Use JSON-RPC stdio emulator in-process to run the full server pipeline
                    import anyio
                    import mcp.types as types
                    try:
                        # mcp >= 1.8 wraps messages; older targets (osm: mcp 1.3)
                        # put the JSONRPCMessage on the stream directly.
                        from mcp.shared.message import SessionMessage as _Wrap
                    except ImportError:
                        _Wrap = lambda m: m  # noqa: E731

                    def _msg(payload: dict):
                        # mcp 1.x: JSONRPCMessage is a pydantic RootModel.
                        # mcp 2.x: it is a bare `Union[...]` alias with no
                        # model_validate -- build the concrete model instead.
                        if hasattr(types.JSONRPCMessage, "model_validate"):
                            return types.JSONRPCMessage.model_validate(payload)
                        cls = types.JSONRPCRequest if "id" in payload else types.JSONRPCNotification
                        return cls.model_validate(payload)

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
                            init_req = _msg({
                                "jsonrpc": "2.0",
                                "id": 1,
                                "method": "initialize",
                                "params": {
                                    "protocolVersion": "2024-11-05",
                                    "capabilities": {},
                                    "clientInfo": {"name": "fuzzer", "version": "1.0"}
                                }
                            })
                            await read_stream_writer.send(_Wrap(init_req))
                            await write_stream_reader.receive()

                            # 2. Initialized Notification
                            initialized_notif = _msg({
                                "jsonrpc": "2.0",
                                "method": "notifications/initialized"
                            })
                            await read_stream_writer.send(_Wrap(initialized_notif))

                            # 3. Call Tool Request
                            call_req = _msg({
                                "jsonrpc": "2.0",
                                "id": 2,
                                "method": "tools/call",
                                "params": {
                                    "name": self.target_tool,
                                    "arguments": arguments
                                }
                            })
                            await read_stream_writer.send(_Wrap(call_req))
                            call_resp = await write_stream_reader.receive()

                            # Clean up server by closing the streams
                            await read_stream_writer.aclose()
                            await write_stream.aclose()

                            return call_resp

                    rpc_resp = anyio.run(run_test)
                    msg = rpc_resp.message if hasattr(rpc_resp, 'message') else rpc_resp
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

        res_obj = RunnerResult(
            success=success,
            coverage=covered_lines,
            result=val,
            error=error_msg,
            execution_time_ms=execution_time_ms,
            accessed_files=tracer.accessed_files
        )
        res_obj.deserialization_calls = deser_tracer.deserialization_calls
        res_obj.executed_commands = cmd_tracer.executed_commands
        res_obj.sql_queries = sql_tracer.sql_queries
        res_obj.written_files = file_write_tracer.written_files
        res_obj.evaluated_code_calls = code_tracer.evaluated_code_calls
        res_obj.network_connections = net_tracer.network_connections
        res_obj.leaked_temp_files = temp_leak_tracer.leaked_temp_files
        res_obj.logged_messages = getattr(log_tracer, "logged_messages", [])
        res_obj.unverified_ssl_calls = getattr(ssl_tracer, "unverified_ssl_calls", [])
        res_obj.bound_addresses = getattr(bind_tracer, "bound_addresses", [])
        res_obj.slow_regex_calls = getattr(redos_tracer, "slow_regex_calls", [])
        res_obj.blocking_calls = getattr(blocking_tracer, "blocking_calls", [])
        res_obj.weak_hash_calls = getattr(hash_tracer, "weak_hash_calls", [])
        res_obj.weak_prng_calls = getattr(prng_tracer, "weak_prng_calls", [])
        res_obj.reused_nonces = getattr(nonce_tracer, "reused_nonces", [])
        res_obj.unverified_downloads = getattr(download_tracer, "unverified_downloads", [])
        res_obj.xxe_calls = getattr(xxe_tracer, "xxe_calls", [])
        res_obj.amplification_calls = getattr(amplification_tracer, "amplification_calls", [])
        return res_obj

    def get_tool_metadata(self, tool_name: str) -> tuple:
        if not self.target_func and not self.mcp_server:
            self.start()
        # Registry schema first: it is what the server itself advertises, and it
        # is the only option when the tool is called through the in-process server.
        if self.tool_schema:
            doc = self.tool_description or (inspect.getdoc(self.target_func) if self.target_func else None) \
                or f"Tool {tool_name}"
            return tool_name, doc, self.tool_schema
        func = self.target_func
        if func is None:
            raise AttributeError(f"no schema and no callable for tool '{tool_name}'")
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
