import builtins
import functools
import http.client
import json
import os
import pathlib
import shlex
import subprocess
import sys
import threading
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


_HOOK_DIR = Path(__file__).resolve().parent
_PROJECT_ROOT = _HOOK_DIR.parents[1]
_DEFAULT_LOG_PATH = _PROJECT_ROOT / "results" / "oracle.json"
_LOG_PATH = Path(os.environ.get("MCP_FUZZER_ORACLE_LOG", str(_DEFAULT_LOG_PATH))).expanduser()
_LOCK = threading.Lock()
_TLS = threading.local()
_INSTALLED = False
_ORIGINAL_OPEN = builtins.open
_ORIGINAL_PATH_OPEN = pathlib.Path.open
_ORIGINALS: Dict[str, Any] = {}
_FILTERED_ENV_KEYS = {"env", "ENV", "environment", "processEnv"}


def _mark_original(name: str, value: Any) -> None:
    if name not in _ORIGINALS:
        _ORIGINALS[name] = value


def _is_reentrant() -> bool:
    return bool(getattr(_TLS, "in_hook", False))


def _set_reentrant(active: bool) -> None:
    _TLS.in_hook = active


def _safe_resolve(path_str: str) -> Optional[Path]:
    try:
        return Path(path_str).resolve()
    except Exception:
        return None


def _is_internal_frame(filename: str) -> bool:
    normalized = filename.replace("\\", "/")
    if not normalized or normalized.startswith("<"):
        return True

    resolved = _safe_resolve(filename)
    if resolved and resolved.is_relative_to(_HOOK_DIR):
        return True
    if "/site-packages/" in normalized:
        return True

    stdlib_dir = _safe_resolve(os.__file__)
    if stdlib_dir and resolved and resolved.is_relative_to(stdlib_dir.parent):
        return True
    return False


def _capture_context() -> Dict[str, Any]:
    stack: List[str] = []
    origin = None
    frame = sys._getframe(2)
    scanned = 0

    while frame is not None and scanned < 40:
        scanned += 1
        code = frame.f_code
        filename = code.co_filename
        if _is_internal_frame(filename):
            frame = frame.f_back
            continue

        frame_text = f'File "{filename}", line {frame.f_lineno}, in {code.co_name}'
        if origin is None:
            origin = {
                "function": code.co_name,
                "file": filename,
                "line": frame.f_lineno,
                "column": 1,
                "frame": frame_text,
            }
        stack.append(frame_text)
        if len(stack) >= 20:
            break
        frame = frame.f_back

    return {"stack": stack, "origin": origin}


def _filter_env_vars(value: Any) -> Any:
    if isinstance(value, dict):
        filtered: Dict[Any, Any] = {}
        for key, item in value.items():
            if key in _FILTERED_ENV_KEYS:
                filtered[key] = "[Environment variables filtered]"
            elif key == "options" and isinstance(item, dict):
                copied = dict(item)
                if "env" in copied:
                    copied["env"] = "[Environment variables filtered]"
                filtered[key] = _filter_env_vars(copied)
            else:
                filtered[key] = _filter_env_vars(item)
        return filtered
    if isinstance(value, list):
        return [_filter_env_vars(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_filter_env_vars(item) for item in value)
    return value


def _stringify_arg(arg: Any) -> str:
    if isinstance(arg, str):
        return arg
    if isinstance(arg, Path):
        return str(arg)
    if isinstance(arg, (bytes, bytearray)):
        return f"[Bytes:{len(arg)} bytes]"
    if isinstance(arg, dict):
        try:
            return json.dumps(_filter_env_vars(arg), ensure_ascii=False, default=str)
        except Exception:
            return repr(arg)
    if isinstance(arg, (list, tuple)):
        try:
            return json.dumps(_filter_env_vars(list(arg)), ensure_ascii=False, default=str)
        except Exception:
            return repr(arg)
    return str(arg)


def _write_entry(entry: Dict[str, Any]) -> None:
    try:
        _LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps(entry, ensure_ascii=False) + "\n"
        with _LOCK:
            with _ORIGINAL_OPEN(_LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(line)
    except Exception as exc:
        sys.stderr.write(f"[PY_HOOK ERROR] Failed to write oracle log: {exc}\n")


def log_event(sink: str, *args: Any, context: Optional[Dict[str, Any]] = None) -> None:
    if _is_reentrant():
        return

    _set_reentrant(True)
    try:
        captured = context or _capture_context()
        entry: Dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
            "sink": sink,
            "args": [_stringify_arg(arg) for arg in args],
            "stack": captured.get("stack", []),
        }
        if captured.get("origin"):
            entry["origin"] = captured["origin"]
        _write_entry(entry)
    finally:
        _set_reentrant(False)


def _command_text(command: Any, *extra: Any) -> str:
    if isinstance(command, (list, tuple)):
        return " ".join(shlex.quote(str(part)) for part in command)
    if extra:
        return " ".join([str(command)] + [str(part) for part in extra])
    return str(command)


def _result_payload(result: Any) -> Dict[str, Any]:
    payload: Dict[str, Any] = {}
    for attr in ("returncode", "stdout", "stderr"):
        if hasattr(result, attr):
            value = getattr(result, attr)
            if isinstance(value, (bytes, bytearray)):
                value = value[:10000].decode("utf-8", errors="replace")
            elif isinstance(value, str):
                value = value[:10000]
            payload[attr] = value
    return payload


def _should_log_write_mode(mode: str) -> bool:
    return any(flag in mode for flag in ("w", "a", "x", "+"))


def _safe_truncate_text(value: Any, limit: int = 512) -> str:
    if isinstance(value, (bytes, bytearray)):
        text = value[:limit].decode("utf-8", errors="replace")
    else:
        text = str(value)
    return text[:limit]


def _patch_subprocess() -> None:
    _mark_original("subprocess.Popen", subprocess.Popen)
    original_popen = subprocess.Popen

    class PatchedPopen(original_popen):  # type: ignore[misc, valid-type]
        def __init__(self, args: Any, *pargs: Any, **kwargs: Any) -> None:
            context = _capture_context()
            log_event("subprocess.Popen", _command_text(args), {"args": args, "kwargs": kwargs}, context=context)
            super().__init__(args, *pargs, **kwargs)

    PatchedPopen.__name__ = getattr(original_popen, "__name__", "Popen")
    PatchedPopen.__qualname__ = getattr(original_popen, "__qualname__", "Popen")
    subprocess.Popen = PatchedPopen

    _mark_original("subprocess.run", subprocess.run)
    original_run = subprocess.run

    @functools.wraps(original_run)
    def patched_run(args: Any, *pargs: Any, **kwargs: Any) -> Any:
        context = _capture_context()
        log_event("subprocess.run", _command_text(args), {"args": args, "kwargs": kwargs}, context=context)
        result = original_run(args, *pargs, **kwargs)
        log_event("subprocess.run.result", _result_payload(result), context=context)
        return result

    subprocess.run = patched_run

    for attr in ("call", "check_call", "check_output"):
        original = getattr(subprocess, attr)
        _mark_original(f"subprocess.{attr}", original)

        def _make_wrapper(name: str, original_fn: Any) -> Any:
            @functools.wraps(original_fn)
            def patched(args: Any, *pargs: Any, **kwargs: Any) -> Any:
                context = _capture_context()
                log_event(f"subprocess.{name}", _command_text(args), {"args": args, "kwargs": kwargs}, context=context)
                return original_fn(args, *pargs, **kwargs)

            return patched

        setattr(subprocess, attr, _make_wrapper(attr, original))


def _patch_os() -> None:
    for attr in ("system", "popen", "spawnv", "spawnve", "spawnvp", "spawnvpe"):
        if not hasattr(os, attr):
            continue
        original = getattr(os, attr)
        _mark_original(f"os.{attr}", original)

        def _make_wrapper(name: str, original_fn: Any) -> Any:
            @functools.wraps(original_fn)
            def patched(*args: Any, **kwargs: Any) -> Any:
                context = _capture_context()
                log_event(f"os.{name}", *args, context=context)
                return original_fn(*args, **kwargs)

            return patched

        setattr(os, attr, _make_wrapper(attr, original))


def _patch_file_writes() -> None:
    _mark_original("builtins.open", builtins.open)

    @functools.wraps(_ORIGINAL_OPEN)
    def patched_open(file: Any, mode: str = "r", *pargs: Any, **kwargs: Any) -> Any:
        if _should_log_write_mode(str(mode)) and str(file) != str(_LOG_PATH):
            log_event("open", str(file), {"mode": mode}, context=_capture_context())
        return _ORIGINAL_OPEN(file, mode, *pargs, **kwargs)

    builtins.open = patched_open

    _mark_original("pathlib.Path.open", pathlib.Path.open)

    @functools.wraps(_ORIGINAL_PATH_OPEN)
    def patched_path_open(self: pathlib.Path, mode: str = "r", *pargs: Any, **kwargs: Any) -> Any:
        if _should_log_write_mode(str(mode)) and str(self) != str(_LOG_PATH):
            log_event("pathlib.Path.open", str(self), {"mode": mode}, context=_capture_context())
        return _ORIGINAL_PATH_OPEN(self, mode, *pargs, **kwargs)

    pathlib.Path.open = patched_path_open


def _patch_network() -> None:
    _mark_original("urllib.request.urlopen", urllib.request.urlopen)
    original_urlopen = urllib.request.urlopen

    @functools.wraps(original_urlopen)
    def patched_urlopen(url: Any, *pargs: Any, **kwargs: Any) -> Any:
        context = _capture_context()
        request_url = getattr(url, "full_url", url)
        method = getattr(url, "method", None)
        log_event(
            "urllib.request.urlopen",
            str(request_url),
            {"method": method} if method else None,
            context=context,
        )
        return original_urlopen(url, *pargs, **kwargs)

    urllib.request.urlopen = patched_urlopen

    _mark_original("http.client.HTTPConnection.request", http.client.HTTPConnection.request)
    original_request = http.client.HTTPConnection.request

    @functools.wraps(original_request)
    def patched_request(
        self: http.client.HTTPConnection,
        method: str,
        url: str,
        body: Any = None,
        headers: Any = None,
        *,
        encode_chunked: bool = False,
    ) -> Any:
        context = _capture_context()
        log_event(
            "http.client.HTTPConnection.request",
            {
                "method": method,
                "url": url,
                "host": getattr(self, "host", ""),
                "port": getattr(self, "port", ""),
                "headers": headers or {},
            },
            context=context,
        )
        return original_request(self, method, url, body=body, headers=headers, encode_chunked=encode_chunked)

    http.client.HTTPConnection.request = patched_request

    # Avoid importing requests during sitecustomize startup; urllib/http hooks
    # still capture most network activity without risking circular imports.


def _patch_image_io() -> None:
    try:
        from PIL import Image as PILImage
    except Exception:
        return

    _mark_original("PIL.Image.open", PILImage.open)
    original_open = PILImage.open

    @functools.wraps(original_open)
    def patched_image_open(fp: Any, *pargs: Any, **kwargs: Any) -> Any:
        context = _capture_context()
        log_event("PIL.Image.open", str(fp), kwargs or None, context=context)
        return original_open(fp, *pargs, **kwargs)

    PILImage.open = patched_image_open


def _patch_dynamic_execution() -> None:
    for attr in ("eval", "exec"):
        original = getattr(builtins, attr)
        _mark_original(f"builtins.{attr}", original)

        def _make_wrapper(name: str, original_fn: Any) -> Any:
            @functools.wraps(original_fn)
            def patched(source: Any, *pargs: Any, **kwargs: Any) -> Any:
                context = _capture_context()
                origin = context.get("origin") or {}
                origin_function = str(origin.get("function", "")).strip()
                if origin_function not in {"", "<module>"} and isinstance(source, (str, bytes, bytearray)):
                    log_event(
                        f"builtins.{name}",
                        {"source": _safe_truncate_text(source, 512)},
                        context=context,
                    )
                if not pargs and not kwargs:
                    caller = sys._getframe(1)
                    return original_fn(source, caller.f_globals, caller.f_locals)
                return original_fn(source, *pargs, **kwargs)

            return patched

        setattr(builtins, attr, _make_wrapper(attr, original))


def _patch_fastmcp_class(FastMCP: Any) -> None:
    if getattr(FastMCP.__init__, "_mcp_fuzzer_compat", False):
        return

    original_init = FastMCP.__init__

    @functools.wraps(original_init)
    def patched_init(self: Any, *args: Any, **kwargs: Any) -> None:
        # Keep legacy samples runnable under one shared MCP/FastMCP version.
        kwargs.pop("dependencies", None)
        kwargs.pop("description", None)
        kwargs.pop("capabilities", None)
        kwargs.pop("version", None)
        return original_init(self, *args, **kwargs)

    patched_init._mcp_fuzzer_compat = True  # type: ignore[attr-defined]
    FastMCP.__init__ = patched_init


def _patch_fastmcp_compat() -> None:
    try:
        from fastmcp.server.server import FastMCP

        _patch_fastmcp_class(FastMCP)
    except Exception:
        pass

    try:
        from mcp.server.fastmcp import FastMCP

        _patch_fastmcp_class(FastMCP)
    except Exception:
        pass


def install() -> None:
    global _INSTALLED

    if _INSTALLED:
        return

    _patch_subprocess()
    _patch_os()
    _patch_file_writes()
    _patch_network()
    _patch_image_io()
    _patch_dynamic_execution()
    _patch_fastmcp_compat()
    log_event("hook_init", {"pid": os.getpid(), "python": sys.version.split()[0]})
    # PATCH (ToFu): sidecar "<oracle log>.hook_init" marker. The engine truncates the oracle
    # log between rounds, erasing the hook_init line; the sidecar is never cleared, so hook
    # injection stays provable on runs with no sink hit.
    try:
        with _ORIGINAL_OPEN(str(_LOG_PATH) + ".hook_init", "a", encoding="utf-8") as fh:
            fh.write(json.dumps({"pid": os.getpid(), "python": sys.version.split()[0]}) + "\n")
    except Exception:
        pass
    _INSTALLED = True
