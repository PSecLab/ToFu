import os
from pathlib import Path
from typing import Dict, List


_PYTHON_WRAPPERS = {"uv", "poetry", "pipenv", "pdm", "hatch", "rye"}


def _token_name(token: str) -> str:
    return Path(token).name.lower()


def is_python_startup_command(command: List[str]) -> bool:
    if not command:
        return False

    first = _token_name(command[0])
    if first.startswith("python"):
        return True

    if first in _PYTHON_WRAPPERS:
        try:
            run_index = command.index("run")
        except ValueError:
            return False
        if run_index + 1 >= len(command):
            return False
        return _token_name(command[run_index + 1]).startswith("python")

    return False


def _iter_candidate_python_binaries(command: List[str]) -> List[Path]:
    candidates: List[Path] = []
    if not command:
        return candidates

    first = _token_name(command[0])
    if first.startswith("python"):
        candidates.append(Path(command[0]))
        if "--" in command:
            guard_index = command.index("--")
            if guard_index + 1 < len(command):
                inner = Path(command[guard_index + 1])
                if _token_name(str(inner)).startswith("python"):
                    candidates.append(inner)
        return candidates

    if first in _PYTHON_WRAPPERS:
        try:
            run_index = command.index("run")
        except ValueError:
            return candidates
        if run_index + 1 < len(command):
            inner = Path(command[run_index + 1])
            if _token_name(str(inner)).startswith("python"):
                candidates.append(inner)
        return candidates

    return candidates


def _install_hook_pth_for_python(command: List[str], hook_dir: Path) -> bool:
    for python_bin in _iter_candidate_python_binaries(command):
        raw_path = python_bin.expanduser()
        if raw_path.name != "python" and not raw_path.name.startswith("python"):
            continue
        env_root = raw_path.parent.parent
        site_packages_dirs = sorted(env_root.glob("lib/python*/site-packages"))
        if not site_packages_dirs:
            try:
                resolved = raw_path.resolve()
            except Exception:
                resolved = raw_path
            if resolved.parent.name == "bin":
                site_packages_dirs = sorted(resolved.parent.parent.glob("lib/python*/site-packages"))
        if not site_packages_dirs:
            continue
        for site_packages in site_packages_dirs:
            site_packages.mkdir(parents=True, exist_ok=True)
            marker = site_packages / "mcp_fuzzer_hook_auto.pth"
            marker.write_text(str(hook_dir) + "\n", encoding="utf-8")
        return True
    return False


def inject_python_hook_env(
    command: List[str],
    env: Dict[str, str],
    project_root: Path,
) -> Dict[str, str]:
    """Add the Python hook directory to PYTHONPATH for Python MCP servers."""
    updated = dict(env)
    if not is_python_startup_command(command):
        return updated

    hook_dir = (project_root / "instrumentation" / "python").resolve()
    if not hook_dir.exists():
        return updated

    installed_via_pth = _install_hook_pth_for_python(command, hook_dir)
    if not installed_via_pth:
        existing = updated.get("PYTHONPATH", "")
        path_parts = [part for part in existing.split(os.pathsep) if part]
        hook_dir_str = str(hook_dir)
        if hook_dir_str not in path_parts:
            path_parts.insert(0, hook_dir_str)
        updated["PYTHONPATH"] = os.pathsep.join(path_parts)
    updated["MCP_FUZZER_ENABLE_PYTHON_HOOK"] = "1"
    return updated
