"""Regression tests for PythonRunner target discovery (nazmul.todo item 86).

Every Python row of the gpt41-full campaign (44/44) was `executable: unknown,
n_exec=0`: the runner never imported a real target. These tests pin the three
causes so they cannot come back silently:

  A. a venv console-script path was fed to importlib.import_module()
  B. FastMCP-registered tools (incl. lazy module __getattr__ and factories)
     were looked up as module-level attributes
  C. the target venv's site-packages was never activated, and an interpreter
     mismatch (cp313 venv into cp311 ToFu) was not reported

The fixtures use mcp 2.x's MCPServer (the FastMCP rename) because that is the
SDK installed in ToFu's own venv; discovery matches on the class MRO names
{FastMCP, MCPServer}, so the same code path covers mcp 1.x FastMCP targets.
"""
import os
import sys
import textwrap
import uuid

import pytest

from src.runners.python_runner import (
    PythonRunner,
    _parse_console_script,
    _entry_from_pyproject,
    _venv_root_from_command,
    _venv_site_packages,
    _is_fastmcp_like,
    _is_interpreter,
    _wants_context,
)

CUR = f"python{sys.version_info.major}.{sys.version_info.minor}"


def _uniq(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(textwrap.dedent(text))
    return path


def _fake_venv(root, pytag=CUR, script=None, shim_module=None, pth_dir=None):
    """A directory that looks like a uv/pip venv: pyvenv.cfg, bin/, lib/<py>/site-packages."""
    os.makedirs(os.path.join(root, "bin"), exist_ok=True)
    sp = os.path.join(root, "lib", pytag, "site-packages")
    os.makedirs(sp, exist_ok=True)
    _write(os.path.join(root, "pyvenv.cfg"), "home = /nonexistent\nversion_info = 3.11.9\n")
    if pth_dir:
        _write(os.path.join(sp, "_editable_impl_fixture.pth"), pth_dir + "\n")
    if script:
        shim = os.path.join(root, "bin", script)
        _write(shim, f"""\
            #!{root}/bin/python
            # -*- coding: utf-8 -*-
            import sys
            from {shim_module} import main
            if __name__ == "__main__":
                sys.exit(main())
            """)
        os.chmod(shim, 0o755)
    _write(os.path.join(root, "bin", "python"), "#!/bin/sh\nexit 0\n")
    return sp


# ---------------------------------------------------------------- pure helpers

def test_parse_console_script_reads_module_not_path(tmp_path):
    _fake_venv(str(tmp_path / ".venv"), script="osm-mcp-server", shim_module="osm_mcp_server")
    assert _parse_console_script(str(tmp_path / ".venv" / "bin" / "osm-mcp-server")) == ("osm_mcp_server", "main")
    # a binary / non-shim is not a shim
    assert _parse_console_script(str(tmp_path / ".venv" / "bin" / "python")) is None


def test_entry_from_pyproject_project_and_poetry(tmp_path):
    _write(str(tmp_path / "pyproject.toml"), """\
        [project]
        name = "x"
        [project.scripts]
        osm-mcp-server = "osm_mcp_server:main"
        [tool.poetry.scripts]
        legacy-cli = "legacy.pkg.cli:run"
        """)
    assert _entry_from_pyproject(str(tmp_path), "osm-mcp-server") == ("osm_mcp_server", "main")
    assert _entry_from_pyproject(str(tmp_path), "legacy-cli") == ("legacy.pkg.cli", "run")
    assert _entry_from_pyproject(str(tmp_path), "nope") is None


def test_venv_helpers_locate_root_and_site_packages(tmp_path):
    sp = _fake_venv(str(tmp_path / ".venv"), script="tool", shim_module="pkg")
    cmd = str(tmp_path / ".venv" / "bin" / "tool")
    assert _venv_root_from_command(cmd) == str(tmp_path / ".venv")
    found, tags = _venv_site_packages(str(tmp_path / ".venv"))
    assert found == sp and tags == [CUR]
    assert _venv_root_from_command("/usr/bin/python3") is None
    assert _is_interpreter("/x/.venv/bin/python3.11") and not _is_interpreter("/x/.venv/bin/osm-mcp-server")


def test_is_fastmcp_like_matches_mcpserver_and_subclasses_not_classes():
    from mcp.server.mcpserver import MCPServer

    class GeminiCompatible(MCPServer):
        pass

    assert _is_fastmcp_like(MCPServer("a"))
    assert _is_fastmcp_like(GeminiCompatible("b"))
    assert not _is_fastmcp_like(MCPServer)          # the class itself is not an instance
    assert not _is_fastmcp_like(object())


def test_wants_context_detects_ctx_param():
    from mcp.server.mcpserver import Context

    def with_ctx(address: str, ctx: Context): ...
    def plain(address: str): ...
    assert _wants_context(with_ctx) and not _wants_context(plain)


# ------------------------------------------------- bug C: interpreter mismatch

def test_mismatched_venv_raises_loudly_not_silently(tmp_path):
    _fake_venv(str(tmp_path / ".venv"), pytag="python3.99", script="tool", shim_module="pkg")
    r = PythonRunner(command=str(tmp_path / ".venv" / "bin" / "tool"), args=[],
                     target_tool="whatever", cwd=str(tmp_path))
    with pytest.raises(RuntimeError) as ei:
        r.start()
    msg = str(ei.value)
    assert "python3.99" in msg and CUR in msg and "re-prepare" in msg.lower()


def test_interpreter_with_no_target_is_a_clear_error_not_a_path_import(tmp_path):
    _fake_venv(str(tmp_path / ".venv"))
    r = PythonRunner(command=str(tmp_path / ".venv" / "bin" / "python"), args=[],
                     target_tool="t", cwd=str(tmp_path))
    with pytest.raises(ImportError) as ei:
        r.start()
    assert "No module named '/" not in str(ei.value)
    assert "cannot locate a target module" in str(ei.value)


# --------------------------------------------- bug B: registry-based discovery

def test_module_level_mcpserver_registry(tmp_path):
    name = _uniq("srv_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("fixture")

        @mcp.tool()
        def echo_len(text: str) -> str:
            return str(len(text))
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="echo_len")
    r.start()
    assert r.fastmcp_instance is not None and r.mcp_server is not None
    assert r.target_func is None                       # server found -> routed through it, not bare-called
    res = r.execute({"text": "abcd"})
    assert res.success is True and "4" in str(res.result)
    tname, doc, schema = r.get_tool_metadata("echo_len")
    assert schema["properties"]["text"]["type"] == "string"          # registry schema, not signature guess
    # the server's validation is part of the oracle: a type-wrong input is a rejection
    bad = r.execute({"text": {"not": "a string"}})
    assert bad.success is False


def test_bare_call_mode_can_be_forced(tmp_path, monkeypatch):
    name = _uniq("bare_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("fixture")

        @mcp.tool()
        def echo_len(text: str) -> str:
            return str(len(text))
        """)
    monkeypatch.setenv("TOFU_PY_BARE_CALL", "1")
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="echo_len")
    r.start()
    assert callable(r.target_func)
    assert r.execute({"text": "abcd"}).result == "4"


def test_lazy_module_getattr_is_resolved(tmp_path):
    # uml-mcp pattern: `mcp` is built on first attribute access, absent from dir()
    name = _uniq("lazy_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        def _build():
            from mcp.server.mcpserver import MCPServer
            s = MCPServer("lazy")
            @s.tool()
            def generate_uml(code: str) -> str:
                return "ok:" + code
            return s

        def __getattr__(name):
            if name == "mcp":
                s = _build()
                globals()["mcp"] = s
                return s
            raise AttributeError(name)
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="generate_uml")
    r.start()
    assert r.execute({"code": "A->B"}).result == "ok:A->B"


def test_factory_function_is_called(tmp_path):
    name = _uniq("factory_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        _inst = None
        def get_mcp_server():
            global _inst
            if _inst is None:
                from mcp.server.mcpserver import MCPServer
                _inst = MCPServer("fac")
                @_inst.tool()
                def add(a: int, b: int) -> int:
                    return a + b
            return _inst
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="add")
    r.start()
    res = r.execute({"a": 2, "b": 3})
    assert res.success is True and "5" in str(res.result)     # server path returns text content


def test_subclass_named_differently_is_found(tmp_path):
    name = _uniq("subclass_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer
        class GeminiCompatibleFastMCP(MCPServer):
            pass
        app = GeminiCompatibleFastMCP("mcp-text-editor")

        @app.tool()
        def get_text(path: str) -> str:
            return path.upper()
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="get_text")
    r.start()
    assert r.execute({"path": "x"}).result == "X"


def test_wrapper_object_holding_server_on_attribute(tmp_path):
    """item 92: meilisearch/rquest build the server inside a wrapper object
    (create_server() -> MeilisearchMCPServer, whose MCPServer is at .mcp).
    Discovery must unwrap one level instead of "server instance: none found"."""
    name = _uniq("wrap_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer

        class MyMCPServerWrapper:
            def __init__(self):
                self.mcp = MCPServer("wrapped")
                @self.mcp.tool()
                def get_stats(index: str) -> str:
                    return "stats:" + index

        def create_server(url: str = "http://localhost:7700", api_key=None):
            return MyMCPServerWrapper()
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="get_stats")
    r.start()
    assert r.mcp_server is not None                       # unwrapped from .mcp
    res = r.execute({"index": "movies"})
    assert res.success is True and "stats:movies" in str(res.result)


def test_unknown_tool_error_lists_registered_tools(tmp_path):
    name = _uniq("srv_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("fixture")
        @mcp.tool()
        def real_tool(x: int) -> int:
            return x
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="ghost")
    # a FastMCP-like server was found, so the low-level server path stays available
    r.start()
    assert r.target_func is None and r.mcp_server is not None
    res = r.execute({"x": 1})
    assert res.success is False                       # server says: unknown tool


def test_context_tool_routes_through_in_process_server(tmp_path):
    name = _uniq("ctx_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        from mcp.server.mcpserver import MCPServer, Context
        mcp = MCPServer("ctx")

        @mcp.tool()
        async def geocode_address(address: str, ctx: Context) -> str:
            return "geo:" + address
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="geocode_address")
    r.start()
    assert r.target_func is None and r.mcp_server is not None    # routed, not bare-called
    res = r.execute({"address": "Penn State"})
    assert res.success is True and "geo:Penn State" in str(res.result)
    _, _, schema = r.get_tool_metadata("geocode_address")
    assert "address" in schema["properties"] and "ctx" not in schema["properties"]


# -------------------------- bug A + C together: console script + target venv

def test_console_script_end_to_end(tmp_path):
    pkg = _uniq("osmpkg")
    src = str(tmp_path / "src")
    _write(os.path.join(src, pkg, "__init__.py"), """\
        from . import server

        def main():
            server.mcp.run()
        """)
    _write(os.path.join(src, pkg, "server.py"), """\
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("osm")

        @mcp.tool()
        def reverse_geocode(lat: float, lon: float) -> str:
            return f"{lat},{lon}"
        """)
    _write(str(tmp_path / "pyproject.toml"), f"""\
        [project]
        name = "{pkg}"
        [project.scripts]
        osm-mcp-server = "{pkg}:main"
        """)
    venv = str(tmp_path / ".venv")
    sp = _fake_venv(venv, script="osm-mcp-server", shim_module=pkg, pth_dir=src)
    cmd = os.path.join(venv, "bin", "osm-mcp-server")

    r = PythonRunner(command=cmd, args=[], target_tool="reverse_geocode", cwd=str(tmp_path))
    assert r.predict_module_name() == pkg              # known BEFORE start() -> atheris include list
    assert pkg not in sys.modules
    r.start()
    assert r.module_name == pkg and r.entry_attr == "main"
    assert r.site_packages == sp and sys.path[0] in (src, str(tmp_path))
    assert r.mcp_server is not None and r.target_func is None   # found via submodule walk, routed through server
    res = r.execute({"lat": 1.5, "lon": 2.5})
    assert res.success is True and "1.5,2.5" in str(res.result)


def test_console_script_without_shim_falls_back_to_pyproject(tmp_path):
    pkg = _uniq("pypkg")
    _write(str(tmp_path / pkg / "__init__.py"), """\
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("p")
        @mcp.tool()
        def ping() -> str:
            return "pong"
        def main(): ...
        """)
    _write(str(tmp_path / "pyproject.toml"), f"""\
        [project.scripts]
        my-cli = "{pkg}:main"
        """)
    venv = str(tmp_path / ".venv")
    _fake_venv(venv, pth_dir=str(tmp_path))
    # an opaque (non-shim) launcher, e.g. a compiled entry point
    launcher = os.path.join(venv, "bin", "my-cli")
    with open(launcher, "wb") as f:
        f.write(b"\x7fELF binary launcher")
    r = PythonRunner(command=launcher, args=[], target_tool="ping", cwd=str(tmp_path))
    r.start()
    assert r.module_name == pkg
    assert "pong" in str(r.execute({}).result)


def test_predict_instrument_packages_covers_thin_entry_scripts(tmp_path):
    """uml-mcp layout: `python server.py` + the real code in mcp_core/. Only
    instrumenting `server` gave libFuzzer zero coverage and a silent exit."""
    _write(str(tmp_path / "server.py"), "from mcp_core.core.server import main\n")
    _write(str(tmp_path / "app.py"), "x = 1\n")
    _write(str(tmp_path / "mcp_core" / "__init__.py"), "")
    _write(str(tmp_path / "tools" / "__init__.py"), "")
    _write(str(tmp_path / "src" / "srcpkg" / "__init__.py"), "")
    _write(str(tmp_path / "tests" / "__init__.py"), "")          # excluded
    _write(str(tmp_path / ".venv" / "lib" / "__init__.py"), "")  # excluded
    _write(str(tmp_path / "test_something.py"), "")              # excluded
    r = PythonRunner(command=str(tmp_path / ".venv" / "bin" / "python"),
                     args=[str(tmp_path / "server.py")], target_tool="t", cwd=str(tmp_path))
    pk = r.predict_instrument_packages()
    assert {"server", "app", "mcp_core", "tools", "srcpkg"} <= set(pk)
    assert not ({"tests", ".venv", "test_something", "lib"} & set(pk))
    # console-script layout still yields the package itself
    r2 = PythonRunner(command=str(tmp_path / "nothing"), args=[], target_tool="t")   # no cwd, no shim
    assert r2.predict_instrument_packages() == []


def test_import_time_argparse_does_not_see_tofu_argv(tmp_path, monkeypatch):
    """mindmap-mcp-server pattern (VM, 2026-09-15): argparse at module top level
    consumed ToFu's argv, sys.exit(2), and the uncaught SystemExit killed the
    fuzzer (ERR). With argv neutralized the all-optional parser takes defaults."""
    monkeypatch.setattr(sys, "argv", ["python", "-m", "src", "--config", "x.json", "--time", "900"])
    name = _uniq("argv_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        import argparse, sys
        _p = argparse.ArgumentParser()
        _p.add_argument("--return-type", choices=["html", "filePath"], default="html")
        ARGS = _p.parse_args()                       # module top level, like mindmap
        SEEN_ARGV = list(sys.argv)
        from mcp.server.mcpserver import MCPServer
        mcp = MCPServer("argv")

        @mcp.tool()
        def convert(markdown: str) -> str:
            return ARGS.return_type + ":" + markdown
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="convert")
    r.start()                                        # must not raise / exit
    assert sys.argv[0:3] == ["python", "-m", "src"]  # restored afterwards
    res = r.execute({"markdown": "# hi"})
    assert res.success is True and "html:# hi" in str(res.result)


def test_import_time_sys_exit_is_a_clean_start_failure(tmp_path):
    name = _uniq("exit_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        import sys
        sys.exit(3)                                  # e.g. 'markmap not installed' precondition
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="t")
    with pytest.raises(ImportError) as ei:
        r.start()
    assert "sys.exit(3)" in str(ei.value) and "start-failure" in str(ei.value)


# ------------------------------------------ bug 23, Python twin: process env

def test_in_process_target_cannot_see_tofu_credentials(tmp_path, monkeypatch):
    """2026-09-15: mcp-text-editor served /proc/self/environ and the logged tool
    output contained OPENAI_API_KEY 577 times. The in-process target shares
    os.environ with the fuzzer, so it must be scrubbed BEFORE the import --
    while the placeholder credentials a target is meant to receive survive."""
    monkeypatch.setenv("OPENAI_API_KEY", "sk-fake-tofu-credential")
    monkeypatch.setenv("SOME_VENDOR_TOKEN", "should-go-too")
    monkeypatch.setenv("TOFU_LLM_MODEL", "gpt-4.1")            # not a secret; must stay
    name = _uniq("env_mod")
    _write(str(tmp_path / f"{name}.py"), """\
        import os
        from mcp.server.mcpserver import MCPServer
        SEEN_AT_IMPORT = os.environ.get("OPENAI_API_KEY")
        mcp = MCPServer("env")

        @mcp.tool()
        def dump(name: str) -> str:
            return repr((SEEN_AT_IMPORT, os.environ.get(name)))
        """)
    r = PythonRunner(command="python", args=[str(tmp_path / f"{name}.py")], target_tool="dump",
                     custom_env={"TARGET_PLACEHOLDER_API_KEY": "placeholder-123"})
    r.start()
    assert "OPENAI_API_KEY" in r.scrubbed_env_names and "SOME_VENDOR_TOKEN" in r.scrubbed_env_names
    assert "OPENAI_API_KEY" not in os.environ and "SOME_VENDOR_TOKEN" not in os.environ
    assert os.environ["TARGET_PLACEHOLDER_API_KEY"] == "placeholder-123"   # kept
    assert os.environ["TOFU_LLM_MODEL"] == "gpt-4.1"                        # untouched
    out = str(r.execute({"name": "OPENAI_API_KEY"}).result)
    assert "sk-fake-tofu-credential" not in out                             # neither at import nor at call
    out2 = str(r.execute({"name": "TARGET_PLACEHOLDER_API_KEY"}).result)
    assert "placeholder-123" in out2
    monkeypatch.delenv("TARGET_PLACEHOLDER_API_KEY", raising=False)
