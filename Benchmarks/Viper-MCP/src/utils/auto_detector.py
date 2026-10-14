"""
MCPServerAutoDetector

Automatically infer the startup_command for an MCP server repo,
eliminating the need to manually set it in config.yaml.

Supports:
  - Node.js / TypeScript  (package.json, tsc build, npm scripts)
  - Python                (pyproject.toml, setup.py, common filenames)

Usage:
    from src.utils.auto_detector import MCPServerAutoDetector

    detector = MCPServerAutoDetector(project_root="/path/to/MCP-S-FUZZER")
    result = detector.detect("/path/to/some-mcp-server-repo")
    if result:
        print(result.startup_command)   # ["node", "-r", "...", "dist/index.js"]
        print(result.codeql_language)   # "javascript" | "python"
        print(result.confidence)        # 0.0 – 1.0
"""

from __future__ import annotations

import json
import logging
import os
import re
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("viper_mcp.detector")

# ──────────────────────────────────────────────────────────────────
# Data model
# ──────────────────────────────────────────────────────────────────

@dataclass
class DetectionResult:
    """The inferred startup configuration for one MCP server repo."""
    repo_path: Path
    language: str                        # "nodejs" | "python"
    codeql_language: str                 # "javascript" | "python"
    startup_command: List[str]           # ready-to-use command list
    build_command: Optional[List[str]]   # command to build before starting (or None)
    entry_point: Optional[Path]          # resolved entry file (for debugging)
    confidence: float                    # 0.0 – 1.0
    notes: List[str] = field(default_factory=list)
    validated: bool = False              # True if MCP handshake succeeded


# ──────────────────────────────────────────────────────────────────
# Detector
# ──────────────────────────────────────────────────────────────────

class MCPServerAutoDetector:
    """
    Detect and construct the startup_command for an MCP server repo.

    Parameters
    ----------
    project_root:
        Root of the MCP-S-FUZZER project.  Used to locate the
        instrumentation hook (instrumentation/node_hook.js).
    build_timeout:
        Seconds to wait for npm/pip build steps.
    validate:
        If True, actually start the server and send an MCP
        `initialize` JSON-RPC call to confirm it works.
    validate_timeout:
        Seconds to wait for the MCP handshake during validation.
    """

    # Node.js entry-point candidates (checked in order)
    _JS_ENTRY_CANDIDATES = [
        "dist/index.js",
        "dist/server.js",
        "build/index.js",
        "build/server.js",
        "out/index.js",
        "out/server.js",
        "dist/main.js",
        "build/main.js",
        "index.js",
        "server.js",
        "index.mjs",
        "server.mjs",
        "src/index.js",
        "src/server.js",
        "src/index.ts",
        "src/server.ts",
        "src/index.mts",
        "src/server.mts",
    ]

    # Python entry-point candidates (checked in order)
    _PY_ENTRY_CANDIDATES = [
        "server.py",
        "main.py",
        "app.py",
        "__main__.py",
        "src/server.py",
        "src/main.py",
        "src/__main__.py",
    ]

    # Signals in package.json keywords / description that confirm MCP intent
    _MCP_SIGNALS = {"mcp", "model-context-protocol", "modelcontextprotocol", "mcp-server"}

    _NODE_MCP_DEPENDENCIES = {
        "@modelcontextprotocol/sdk",
        "@anthropic-ai/claude-agent-sdk",
    }

    _NODE_ENTRY_STRONG_MARKERS = (
        "@modelcontextprotocol/sdk",
        "@anthropic-ai/claude-agent-sdk",
        "StdioServerTransport",
        "StreamableHTTPServerTransport",
        "McpServer",
        "createSdkMcpServer",
        "ListToolsRequestSchema",
        "CallToolRequestSchema",
        "setRequestHandler(",
        "server.tool(",
        ".tool(",
        "server.connect(",
    )

    _NODE_ENTRY_WEAK_MARKERS = (
        "jsonrpc",
        "initialize",
        "tools/list",
        "tools/call",
        "stdio",
        "model context protocol",
    )

    def __init__(
        self,
        project_root: str | Path = ".",
        build_timeout: int = 120,
        validate: bool = False,
        validate_timeout: int = 10,
    ):
        self.project_root = Path(project_root).resolve()
        self.build_timeout = build_timeout
        self.validate = validate
        self.validate_timeout = validate_timeout

        # Absolute path to the Node.js instrumentation hook.
        legacy_node_hook = self.project_root / "instrumentation" / "node_hook.js"
        js_node_hook = self.project_root / "instrumentation" / "javascript" / "node_hook.js"
        self._node_hook = js_node_hook if js_node_hook.exists() else legacy_node_hook
        # Absolute path to the Python instrumentation hook (sitecustomize shim)
        self._python_hook_dir = self.project_root / "instrumentation" / "python"

    # ──────────────────────────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────────────────────────

    def detect(self, repo_path: str | Path) -> Optional[DetectionResult]:
        """
        Main entry point.  Returns None if the repo cannot be
        identified as a supported MCP server.
        """
        repo = Path(repo_path).resolve()
        logger.debug("Starting detection for repo: %s", repo.name)

        if not repo.is_dir():
            logger.warning("repo_path does not exist: %s", repo)
            return None

        lang = self._detect_language(repo)
        if lang is None:
            logger.debug("[%s] Cannot determine language — not a supported MCP server", repo.name)
            return None

        logger.debug("[%s] Detected language: %s", repo.name, lang)

        if lang == "nodejs":
            result = self._detect_nodejs(repo)
        else:
            result = self._detect_python(repo)

        if result is None:
            logger.info("[%s] Detection failed: no valid entry point found (lang=%s)", repo.name, lang)
            return None

        logger.info(
            "[%s] Detection succeeded: lang=%s entry=%s confidence=%.2f cmd=%s",
            repo.name, result.language,
            result.entry_point.name if result.entry_point else "?",
            result.confidence,
            " ".join(result.startup_command[:4]),
        )

        if self.validate:
            logger.info("[%s] Validating server via MCP handshake …", repo.name)
            result.validated = self._validate_server(result)
            if result.validated:
                logger.info("[%s] MCP handshake OK", repo.name)
            else:
                logger.warning("[%s] MCP handshake FAILED — server may not start correctly", repo.name)
                result.notes.append("MCP handshake validation failed")

        return result

    # ──────────────────────────────────────────────────────────────
    # Language detection
    # ──────────────────────────────────────────────────────────────

    def _detect_language(self, repo: Path) -> Optional[str]:
        """
        Return "nodejs" or "python" based on repo structure.
        Returns None if neither is clearly identifiable.
        """
        has_pkg_json = (repo / "package.json").exists()
        has_ts_config = (repo / "tsconfig.json").exists()
        has_pyproject = (repo / "pyproject.toml").exists()
        has_setup_py = (repo / "setup.py").exists()
        has_requirements = (repo / "requirements.txt").exists()
        py_files = list(repo.glob("*.py")) + list(repo.glob("src/*.py"))

        if has_pkg_json or has_ts_config:
            signals = []
            if has_pkg_json: signals.append("package.json")
            if has_ts_config: signals.append("tsconfig.json")
            logger.debug("[%s] Language=nodejs (signals: %s)", repo.name, ", ".join(signals))
            return "nodejs"
        if has_pyproject or has_setup_py or has_requirements or py_files:
            signals = []
            if has_pyproject: signals.append("pyproject.toml")
            if has_setup_py: signals.append("setup.py")
            if has_requirements: signals.append("requirements.txt")
            if py_files: signals.append(f"{len(py_files)} .py files")
            logger.debug("[%s] Language=python (signals: %s)", repo.name, ", ".join(signals))
            return "python"
        nested_pkg_json = next((p for p in repo.rglob("package.json") if "node_modules" not in p.parts and ".git" not in p.parts), None)
        nested_pyproject = next((p for p in repo.rglob("pyproject.toml") if ".git" not in p.parts), None)
        nested_requirements = next((p for p in repo.rglob("requirements.txt") if ".git" not in p.parts), None)
        nested_main = next(
            (
                p for p in repo.rglob("*.py")
                if ".git" not in p.parts and p.name in {"main.py", "server.py", "__main__.py"}
            ),
            None,
        )
        if nested_pkg_json:
            logger.debug("[%s] Language=nodejs (nested package.json: %s)", repo.name, nested_pkg_json)
            return "nodejs"
        if nested_pyproject or nested_requirements or nested_main:
            logger.debug("[%s] Language=python (nested project signal)", repo.name)
            return "python"
        logger.debug("[%s] No language signals found", repo.name)
        return None

    # ──────────────────────────────────────────────────────────────
    # Node.js / TypeScript detection
    # ──────────────────────────────────────────────────────────────

    def _detect_nodejs(self, repo: Path) -> Optional[DetectionResult]:
        pkg_path = repo / "package.json"
        if not pkg_path.exists():
            nested_result = self._detect_nodejs_nested(repo)
            if nested_result is not None:
                return nested_result
            return None

        try:
            pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to parse package.json in %s: %s", repo, e)
            return None

        notes: List[str] = []
        confidence = 0.5

        # ── 1. Check if this repo or one of its workspaces is actually an MCP server ──────────
        is_root_mcp = self._is_mcp_nodejs(pkg, repo)
        workspace_match = None
        if not is_root_mcp:
            workspace_match = self._resolve_nodejs_workspace_entry(repo, pkg, notes)
            if workspace_match is None:
                nested_result = self._detect_nodejs_nested(repo)
                if nested_result is not None:
                    return nested_result
                logger.debug("[%s] No MCP SDK dependency or signals found, skipping", repo.name)
                return None
            logger.debug("[%s] MCP workspace child confirmed (Node.js)", repo.name)
            confidence += 0.05
        else:
            confidence += 0.1
            logger.debug("[%s] MCP server confirmed (Node.js)", repo.name)

        # ── 2. Find build command ────────────────────────────────
        build_cmd = self._get_nodejs_build_command(pkg, repo)
        if build_cmd:
            logger.debug("[%s] Build command: %s", repo.name, " ".join(build_cmd))
        else:
            logger.debug("[%s] No build command needed (pre-built or JS-only)", repo.name)

        # ── 3. Determine entry point (build if necessary) ────────
        entry = None
        if is_root_mcp:
            entry = self._resolve_nodejs_entry(pkg, repo, build_cmd, notes)
        if entry is None and workspace_match is not None:
            entry, workspace_build_cmd, workspace_notes = workspace_match
            build_cmd = workspace_build_cmd
            notes.extend(workspace_notes)
        if entry is None and is_root_mcp:
            workspace_match = self._resolve_nodejs_workspace_entry(repo, pkg, notes)
            if workspace_match is not None:
                entry, workspace_build_cmd, workspace_notes = workspace_match
                build_cmd = workspace_build_cmd
                notes.extend(workspace_notes)
        if entry is None:
            logger.info("[%s] Could not resolve Node.js entry point", repo.name)
            return None
        confidence += 0.2
        logger.debug("[%s] Entry point resolved: %s", repo.name,
                     entry.relative_to(repo) if entry.is_relative_to(repo) else entry)

        # ── 4. Inject instrumentation ────────────────────────────
        startup_cmd = self._inject_node_instrumentation(entry)
        notes.append(f"entry: {entry.relative_to(repo) if entry.is_relative_to(repo) else entry}")

        # ── 5. Boost confidence if explicit start script exists ──
        scripts = pkg.get("scripts", {})
        if any(k in scripts for k in ("start:mcp", "mcp:start", "mcp", "serve:mcp")):
            confidence = min(confidence + 0.2, 1.0)
            notes.append("explicit mcp start script found in package.json")
            logger.debug("[%s] Explicit MCP start script found → confidence boost", repo.name)

        return DetectionResult(
            repo_path=repo,
            language="nodejs",
            codeql_language="javascript",
            startup_command=startup_cmd,
            build_command=build_cmd,
            entry_point=entry,
            confidence=min(confidence, 1.0),
            notes=notes,
        )

    def _detect_nodejs_nested(self, repo: Path) -> Optional[DetectionResult]:
        candidates: List[tuple[int, Path, dict]] = []
        for pkg_path in sorted(repo.rglob("package.json")):
            if "node_modules" in pkg_path.parts or ".git" in pkg_path.parts:
                continue
            child_repo = pkg_path.parent
            try:
                pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
            except Exception:
                continue
            candidates.append((self._score_workspace_package(child_repo, pkg), child_repo, pkg))

        for _, child_repo, child_pkg in sorted(candidates, key=lambda item: (-item[0], str(item[1]))):
            if not self._is_mcp_nodejs(child_pkg, child_repo):
                continue
            child_build = self._get_nodejs_build_command(child_pkg, child_repo)
            child_notes: List[str] = []
            child_entry = self._resolve_nodejs_entry(child_pkg, child_repo, child_build, child_notes)
            if child_entry is None:
                continue
            rel_child = child_repo.relative_to(repo) if child_repo.is_relative_to(repo) else child_repo
            child_notes.insert(0, f"nested node project: {rel_child}")
            startup_cmd = self._inject_node_instrumentation(child_entry)
            child_notes.append(f"entry: {child_entry.relative_to(repo) if child_entry.is_relative_to(repo) else child_entry}")
            return DetectionResult(
                repo_path=repo,
                language="nodejs",
                codeql_language="javascript",
                startup_command=startup_cmd,
                build_command=child_build,
                entry_point=child_entry,
                confidence=0.75,
                notes=child_notes,
            )
        return None

    def _is_mcp_nodejs(self, pkg: dict, repo: Path) -> bool:
        """Check if this package uses the MCP SDK."""
        all_deps = {}
        all_deps.update(pkg.get("dependencies", {}))
        all_deps.update(pkg.get("devDependencies", {}))
        if any(dep in all_deps for dep in self._NODE_MCP_DEPENDENCIES):
            return True
        # Check keywords / description as fallback
        keywords = {k.lower() for k in pkg.get("keywords", [])}
        desc = pkg.get("description", "").lower()
        if keywords & self._MCP_SIGNALS:
            return True
        if any(sig in desc for sig in self._MCP_SIGNALS):
            return True
        # Scan src files for MCP import as last resort
        for src_file in repo.rglob("*"):
            if not src_file.is_file() or src_file.suffix not in {".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"}:
                continue
            if any(part in {"node_modules", ".git", "dist", "build", "out"} or part.startswith(".") for part in src_file.parts):
                continue
            try:
                content = src_file.read_text(encoding="utf-8", errors="ignore")
                if (
                    "@modelcontextprotocol/sdk" in content
                    or "@anthropic-ai/claude-agent-sdk" in content
                    or "McpServer" in content
                    or "createSdkMcpServer" in content
                ):
                    return True
            except Exception:
                pass
        return False

    def _get_nodejs_build_command(self, pkg: dict, repo: Path) -> Optional[List[str]]:
        """Return the build command to compile TypeScript, or None."""
        scripts = pkg.get("scripts", {})
        # Prefer explicit "build" script; ignore pure dev/watch variants
        if "build" in scripts and "watch" not in scripts["build"].lower():
            return ["npm", "run", "build"]
        if (repo / "tsconfig.json").exists():
            # TypeScript project without explicit build script
            return ["npx", "tsc", "-p", "."]
        return None

    def _resolve_nodejs_entry(
        self,
        pkg: dict,
        repo: Path,
        build_cmd: Optional[List[str]],
        notes: List[str],
    ) -> Optional[Path]:
        """
        Find the Node.js entry file.  Build the project first if required.
        Priority:
          1. package.json "main" field
          2. Explicit "start:mcp" / "mcp:start" script target
          3. Well-known dist/index.js candidate list
          4. TypeScript source fallback (ts-node/tsx)
        """
        scripts = pkg.get("scripts", {})

        # ── Priority 1: package.json "main" ─────────────────────
        main_field = pkg.get("main")
        if main_field:
            candidate = self._resolve_node_entry_from_declared_path(repo, main_field, notes)
            logger.debug("[%s] Trying package.json main=%s → %s",
                         repo.name, main_field, "exists" if candidate and candidate.exists() else "missing")
            if candidate:
                return candidate
            raw_candidate = (repo / str(main_field).lstrip("./")).resolve()
            if build_cmd and self._run_build(repo, build_cmd, notes):
                if raw_candidate.exists():
                    return raw_candidate

        # ── Priority 1.5: package.json "bin" field ─────────────
        bin_field = pkg.get("bin")
        if isinstance(bin_field, str):
            candidate = self._resolve_node_entry_from_declared_path(repo, bin_field, notes)
            if candidate:
                return candidate
        elif isinstance(bin_field, dict):
            for _, bin_path in bin_field.items():
                candidate = self._resolve_node_entry_from_declared_path(repo, bin_path, notes)
                if candidate:
                    return candidate

        # ── Priority 2: parse explicit MCP start scripts ─────────
        for script_key in ("start:mcp", "mcp:start", "mcp", "serve:mcp", "start"):
            script_val = scripts.get(script_key, "")
            match = re.search(r"node\s+(?:-\S+\s+)*([^\s]+\.js)", script_val)
            if match:
                candidate = (repo / match.group(1)).resolve()
                logger.debug("[%s] Trying scripts[%s] → %s (%s)",
                             repo.name, script_key, match.group(1),
                             "exists" if candidate.exists() else "missing")
                if candidate.exists():
                    return candidate
                if build_cmd and self._run_build(repo, build_cmd, notes):
                    if candidate.exists():
                        return candidate
            script_candidate = self._resolve_node_entry_from_script(repo, script_key, script_val)
            if script_candidate:
                return script_candidate

        # ── Priority 3: candidate list ────────────────────────────
        for rel in self._JS_ENTRY_CANDIDATES:
            candidate = (repo / rel).resolve()
            if candidate.exists():
                logger.debug("[%s] Found candidate: %s", repo.name, rel)
                return candidate

        # Not built → try once
        if build_cmd:
            logger.debug("[%s] No pre-built entry found, triggering build", repo.name)
            if self._run_build(repo, build_cmd, notes):
                for rel in self._JS_ENTRY_CANDIDATES:
                    candidate = (repo / rel).resolve()
                    if candidate.exists():
                        logger.debug("[%s] Post-build entry found: %s", repo.name, rel)
                        return candidate

        # ── Priority 4: TypeScript source (ts-node / tsx) ────────
        for ts_rel in ("src/index.ts", "index.ts", "src/main.ts", "src/server.ts", "server.ts"):
            ts_file = (repo / ts_rel).resolve()
            if ts_file.exists():
                notes.append(f"using ts-node fallback for {ts_rel}")
                logger.debug("[%s] Falling back to TypeScript source: %s", repo.name, ts_rel)
                return ts_file

        scanned_candidate = self._scan_nodejs_probable_entry(repo, notes)
        if scanned_candidate is not None:
            return scanned_candidate

        logger.info("[%s] All entry point strategies exhausted — no entry found", repo.name)
        return None

    def _resolve_node_entry_from_declared_path(
        self,
        repo: Path,
        declared_path: str,
        notes: List[str],
    ) -> Optional[Path]:
        declared_path = str(declared_path).lstrip("./")
        candidate = (repo / declared_path).resolve()
        if self._accept_node_entry_candidate(repo, candidate):
            notes.append(f"entry declared in package.json: {declared_path}")
            return candidate

        # Common pattern: package.json declares dist/server.js but source lives in src/server.ts.
        if declared_path.startswith("dist/") and declared_path.endswith(".js"):
            src_rel = "src/" + declared_path[len("dist/") : -3] + ".ts"
            src_candidate = (repo / src_rel).resolve()
            if src_candidate.exists():
                notes.append(f"using source fallback for declared entry {declared_path} -> {src_rel}")
                return src_candidate
            src_js_rel = "src/" + declared_path[len("dist/") :]
            src_js_candidate = (repo / src_js_rel).resolve()
            if src_js_candidate.exists():
                notes.append(f"using JS source fallback for declared entry {declared_path} -> {src_js_rel}")
                return src_js_candidate

        if declared_path.startswith("build/") and declared_path.endswith(".js"):
            src_rel = "src/" + declared_path[len("build/") : -3] + ".ts"
            src_candidate = (repo / src_rel).resolve()
            if src_candidate.exists():
                notes.append(f"using source fallback for declared entry {declared_path} -> {src_rel}")
                return src_candidate

        if declared_path.startswith("out/") and declared_path.endswith(".js"):
            src_rel = "src/" + declared_path[len("out/") : -3] + ".ts"
            src_candidate = (repo / src_rel).resolve()
            if src_candidate.exists():
                notes.append(f"using source fallback for declared entry {declared_path} -> {src_rel}")
                return src_candidate

        return None

    def _resolve_node_entry_from_script(
        self,
        repo: Path,
        script_key: str,
        script_val: str,
    ) -> Optional[Path]:
        ts_or_js_match = re.search(
            r"(?:tsx|ts-node(?:-esm)?|node)\b(?:\s+--?[^\s]+)*\s+([^\s]+\.(?:ts|js|mjs|cjs|mts|cts))",
            script_val,
        )
        if not ts_or_js_match:
            return None
        rel = ts_or_js_match.group(1).lstrip("./")
        candidate = (repo / rel).resolve()
        logger.debug("[%s] Trying script entry[%s] → %s (%s)",
                     repo.name, script_key, rel, "exists" if candidate.exists() else "missing")
        if self._accept_node_entry_candidate(repo, candidate):
            return candidate
        return None

    def _accept_node_entry_candidate(self, repo: Path, candidate: Path) -> bool:
        if not candidate.exists():
            return False
        if not self._is_suspicious_node_entry_path(repo, candidate):
            return True
        if self._looks_like_nodejs_mcp_entry(candidate):
            return True
        logger.debug(
            "[%s] Rejecting suspicious non-server entry candidate: %s",
            repo.name,
            candidate.relative_to(repo) if candidate.is_relative_to(repo) else candidate,
        )
        return False

    def _is_suspicious_node_entry_path(self, repo: Path, candidate: Path) -> bool:
        try:
            rel = candidate.relative_to(repo)
        except ValueError:
            rel = candidate
        rel_text = str(rel).replace("\\", "/").lower()
        name = candidate.name.lower()
        stem = candidate.stem.lower()

        if rel_text.startswith("scripts/") or "/scripts/" in rel_text:
            return True
        if rel_text.startswith("bin/") or "/bin/" in rel_text:
            return True
        if "/cli/" in rel_text or name.startswith("cli."):
            return True
        if any(token in stem for token in ("patch", "setup", "sync", "migrate", "migration", "deploy", "update")):
            return True
        return False

    def _looks_like_nodejs_mcp_entry(self, candidate: Path) -> bool:
        try:
            content = candidate.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            return False
        if any(marker in content for marker in self._NODE_ENTRY_STRONG_MARKERS):
            return True
        weak_hits = sum(1 for marker in self._NODE_ENTRY_WEAK_MARKERS if marker in content.lower())
        return weak_hits >= 4

    def _resolve_nodejs_workspace_entry(
        self,
        repo: Path,
        root_pkg: dict,
        notes: List[str],
    ) -> Optional[tuple[Path, Optional[List[str]], List[str]]]:
        workspaces = self._get_workspace_patterns(repo, root_pkg)
        if not workspaces:
            return None

        workspace_packages: List[tuple[int, Path, dict]] = []
        seen_children: set[Path] = set()
        for pattern in workspaces:
            if str(pattern).startswith("!"):
                continue
            base_pattern = str(pattern).rstrip("/")
            package_glob = f"{base_pattern}/package.json"
            for pkg_path in sorted(repo.glob(package_glob)):
                child_repo = pkg_path.parent
                if child_repo in seen_children:
                    continue
                seen_children.add(child_repo)
                try:
                    child_pkg = json.loads(pkg_path.read_text(encoding="utf-8"))
                except Exception:
                    continue
                workspace_packages.append(
                    (self._score_workspace_package(child_repo, child_pkg), child_repo, child_pkg)
                )

        workspace_notes: List[str] = []
        for _, child_repo, child_pkg in sorted(workspace_packages, key=lambda item: (-item[0], str(item[1]))):
            if not self._is_mcp_nodejs(child_pkg, child_repo):
                continue
            child_build = self._get_nodejs_build_command(child_pkg, child_repo)
            child_notes: List[str] = []
            child_entry = self._resolve_nodejs_entry(child_pkg, child_repo, child_build, child_notes)
            if child_entry is None:
                continue
            rel_child = child_repo.relative_to(repo) if child_repo.is_relative_to(repo) else child_repo
            workspace_notes.append(f"workspace entry: {rel_child}")
            workspace_notes.extend(child_notes)
            return child_entry, child_build, workspace_notes
        return None

    def _get_workspace_patterns(self, repo: Path, root_pkg: dict) -> List[str]:
        workspaces = root_pkg.get("workspaces", [])
        if isinstance(workspaces, dict):
            workspaces = workspaces.get("packages", [])
        if isinstance(workspaces, list) and workspaces:
            return [str(pattern) for pattern in workspaces]

        pnpm_workspace = repo / "pnpm-workspace.yaml"
        if not pnpm_workspace.exists():
            return []

        patterns: List[str] = []
        in_packages = False
        for raw_line in pnpm_workspace.read_text(encoding="utf-8", errors="ignore").splitlines():
            line = raw_line.rstrip()
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if stripped == "packages:":
                in_packages = True
                continue
            if in_packages:
                if not raw_line.startswith((" ", "\t", "-")):
                    break
                match = re.match(r'^\s*-\s*["\']?([^"\']+)["\']?\s*$', raw_line)
                if match:
                    patterns.append(match.group(1))
        return patterns

    def _score_workspace_package(self, child_repo: Path, child_pkg: dict) -> int:
        score = 0
        name = str(child_pkg.get("name", "")).lower()
        rel = str(child_repo).lower().replace("\\", "/")

        if "/packages/" in rel or rel.startswith("packages/"):
            score += 4
        if re.search(r"(^|/)(samples|sample|examples|example|tests|test|fixtures|template|templates|e2e-tests)(/|$)", rel):
            score -= 5
        if "mcp" in name:
            score += 6
        if "mcp" in rel:
            score += 5
        if re.search(r"(^|/)packages/mcp(-|/|$)", rel):
            score += 5
        if "server" in name:
            score += 2
        if "server" in child_repo.name.lower():
            score += 2

        all_deps = {}
        all_deps.update(child_pkg.get("dependencies", {}))
        all_deps.update(child_pkg.get("devDependencies", {}))
        if "@modelcontextprotocol/sdk" in all_deps:
            score += 4

        main_field = str(child_pkg.get("main", "")).lower()
        if "server" in main_field or "stdio" in main_field:
            score += 2

        scripts = child_pkg.get("scripts", {})
        for key in ("start:mcp", "mcp:start", "mcp", "serve:mcp", "start:stdio", "start"):
            script_val = str(scripts.get(key, "")).lower()
            if "mcp" in script_val or "stdio" in script_val or "server" in script_val:
                score += 2
                break

        return score

    def _scan_nodejs_probable_entry(
        self,
        repo: Path,
        notes: List[str],
    ) -> Optional[Path]:
        candidate_paths: List[Path] = []
        for path in sorted(repo.rglob("*")):
            if not path.is_file():
                continue
            if path.suffix not in {".ts", ".js", ".mjs", ".cjs", ".mts", ".cts"}:
                continue
            rel_parts = path.relative_to(repo).parts
            if any(
                part.startswith(".")
                or part in {"node_modules", "dist", "build", "out", "coverage", "__tests__", "test", "tests"}
                for part in rel_parts
            ):
                continue
            lowered = path.name.lower()
            if not (
                lowered in {
                    "index.ts", "index.js", "index.mts",
                    "server.ts", "server.js", "server.mts",
                    "cli.ts", "cli.js", "cli.mts",
                    "__main__.ts",
                }
                or "mcp" in lowered
            ):
                continue
            candidate_paths.append(path)

        for candidate in candidate_paths:
            try:
                content = candidate.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if (
                "@modelcontextprotocol/sdk" not in content
                and "@anthropic-ai/claude-agent-sdk" not in content
                and "StdioServerTransport" not in content
                and "createSdkMcpServer" not in content
                and "McpServer" not in content
            ):
                continue
            if (
                "StdioServerTransport" not in content
                and "server.connect(" not in content
                and "createSdkMcpServer" not in content
            ):
                continue
            rel = candidate.relative_to(repo)
            notes.append(f"scanned probable entry: {rel}")
            return candidate.resolve()
        return None

    def _inject_node_instrumentation(self, entry: Path) -> List[str]:
        """Build the final startup command with the oracle hook injected."""
        # Determine runner
        if entry.suffix in {".ts", ".mts", ".cts"}:
            # TypeScript source: use tsx (faster than ts-node)
            base_cmd = ["npx", "tsx"]
        else:
            base_cmd = ["node"]

        if self._node_hook.exists():
            return base_cmd + ["-r", str(self._node_hook), str(entry)]
        else:
            logger.warning("Node.js instrumentation hook not found: %s", self._node_hook)
            return base_cmd + [str(entry)]

    # ──────────────────────────────────────────────────────────────
    # Python detection
    # ──────────────────────────────────────────────────────────────

    def _detect_python(self, repo: Path) -> Optional[DetectionResult]:
        notes: List[str] = []
        confidence = 0.4

        py_repo = repo
        if not self._is_mcp_python(py_repo):
            nested_repo = None
            for candidate_repo in self._find_nested_python_projects(repo):
                if self._is_mcp_python(candidate_repo):
                    nested_repo = candidate_repo
                    break
            if nested_repo is None:
                logger.debug("Not a Python MCP server: %s", repo)
                return None
            py_repo = nested_repo
            rel_nested = py_repo.relative_to(repo) if py_repo.is_relative_to(repo) else py_repo
            notes.append(f"nested python project: {rel_nested}")
            confidence += 0.1
        else:
            confidence += 0.15

        # ── 1. Find build/install command ────────────────────────
        build_cmd = self._get_python_build_command(py_repo)

        # ── 2. Determine entry point ─────────────────────────────
        entry, cmd_prefix = self._resolve_python_entry(py_repo, build_cmd, notes)
        if entry is None:
            logger.debug("No Python entry found in %s", py_repo)
            return None
        confidence += 0.2

        # ── 3. Inject Python oracle instrumentation ──────────────
        startup_cmd = self._inject_python_instrumentation(entry, cmd_prefix, py_repo)

        return DetectionResult(
            repo_path=repo,
            language="python",
            codeql_language="python",
            startup_command=startup_cmd,
            build_command=build_cmd,
            entry_point=entry,
            confidence=min(confidence, 1.0),
            notes=notes,
        )

    def _is_mcp_python(self, repo: Path) -> bool:
        """Check if this repo is a Python MCP server."""
        # Check dependency files
        for dep_file in ("pyproject.toml", "requirements.txt", "setup.py"):
            path = repo / dep_file
            if path.exists():
                content = path.read_text(encoding="utf-8", errors="ignore")
                if "mcp" in content.lower() or "modelcontextprotocol" in content.lower():
                    return True
        # Scan Python files for mcp.run() / FastMCP / McpServer imports
        for py_file in repo.glob("**/*.py"):
            if any(part.startswith(".") or part in {"venv", ".venv", "__pycache__", "site-packages"} for part in py_file.parts):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if re.search(
                    r"from\s+mcp\b|import\s+mcp\b|mcp\.run\(|FastMCP|fastmcp|McpServer|MCPServer|StreamableHTTPSessionManager|mcp\.server\.",
                    content,
                ):
                    return True
                protocol_hits = 0
                for marker in ("jsonrpc", "tools/list", "tools/call", "initialize", "mcp_stream_url", "mcp_sse_url", "mcp_url"):
                    if marker in content:
                        protocol_hits += 1
                if protocol_hits >= 3:
                    return True
            except Exception:
                pass
        return False

    def _find_nested_python_projects(self, repo: Path) -> List[Path]:
        candidates: List[tuple[int, Path]] = []
        for pyproject in repo.rglob("pyproject.toml"):
            if ".git" in pyproject.parts:
                continue
            candidates.append((5, pyproject.parent))
        for requirements in repo.rglob("requirements.txt"):
            if ".git" in requirements.parts:
                continue
            candidates.append((4, requirements.parent))
        for main_py in repo.rglob("*.py"):
            if any(part.startswith(".") or part in {"venv", ".venv", "__pycache__", "site-packages"} for part in main_py.parts):
                continue
            lowered = main_py.name.lower()
            if lowered in {"server.py", "main.py", "__main__.py"} or lowered.endswith("_server.py"):
                candidates.append((3, main_py.parent))
        if not candidates:
            return []
        dedup: dict[Path, int] = {}
        for score, path in candidates:
            score += self._score_nested_python_path(path)
            dedup[path] = max(score, dedup.get(path, 0))
        return [path for path, _ in sorted(dedup.items(), key=lambda item: (-item[1], str(item[0])))]

    def _score_nested_python_path(self, path: Path) -> int:
        rel = str(path).lower().replace("\\", "/")
        score = 0
        if "mcp" in rel:
            score += 4
        if "server" in rel:
            score += 2
        if any(part in {"examples", "example", "tests", "test", "fixtures"} for part in path.parts):
            score -= 3
        return score

    def _get_python_build_command(self, repo: Path) -> Optional[List[str]]:
        if (repo / "pyproject.toml").exists():
            return ["pip", "install", "-e", ".", "--quiet"]
        if (repo / "setup.py").exists():
            return ["pip", "install", "-e", ".", "--quiet"]
        if (repo / "requirements.txt").exists():
            return ["pip", "install", "-r", "requirements.txt", "--quiet"]
        return None

    def _resolve_python_entry(
        self,
        repo: Path,
        build_cmd: Optional[List[str]],
        notes: List[str],
    ):
        """
        Returns (entry_path, cmd_prefix) where cmd_prefix is the
        interpreter prefix (e.g. ["python"] or ["python", "-m", "pkg"]).
        """
        # ── Priority 1: pyproject.toml [project.scripts] ─────────
        pkg_name, script_entry = self._parse_pyproject_scripts(repo)
        if script_entry:
            # Try the installed console script
            notes.append(f"pyproject scripts entry: {script_entry}")
            return Path(script_entry), ["python", "-m"]  # type: ignore[return-value]

        # ── Priority 2: package is a module with __main__.py ──────
        if pkg_name:
            main_py = repo / pkg_name / "__main__.py"
            if main_py.exists():
                return main_py, ["python", "-m", pkg_name]
            src_main = repo / "src" / pkg_name / "__main__.py"
            if src_main.exists():
                return src_main, ["python", "-m", pkg_name]

        # ── Priority 2.5: src package with __main__.py ───────────
        src_dir = repo / "src"
        if src_dir.exists():
            for child in sorted(src_dir.iterdir()):
                if not child.is_dir():
                    continue
                src_main = child / "__main__.py"
                if src_main.exists():
                    return src_main, ["python", "-m", child.name]

        # ── Priority 3: well-known entry filenames ────────────────
        for rel in self._PY_ENTRY_CANDIDATES:
            candidate = (repo / rel).resolve()
            if candidate.exists():
                # Confirm it has mcp.run() or equivalent
                try:
                    content = candidate.read_text(encoding="utf-8", errors="ignore")
                    if re.search(r"mcp\.run\(|\.run\(|__main__|FastMCP|fastmcp|MCPServer|mcp\.server\.|StreamableHTTPSessionManager", content):
                        notes.append(f"entry file: {rel}")
                        return candidate, ["python"]
                    protocol_hits = sum(
                        1 for marker in ("jsonrpc", "tools/list", "tools/call", "initialize", "mcp_stream_url", "mcp_sse_url", "mcp_url")
                        if marker in content
                    )
                    if protocol_hits >= 3:
                        notes.append(f"protocol-style MCP entry file: {rel}")
                        return candidate, ["python"]
                except Exception:
                    pass

        # ── Priority 4: grep all .py files for mcp.run() ─────────
        for py_file in sorted(repo.glob("**/*.py")):
            if any(part.startswith(".") or part == "venv" or part == "__pycache__"
                   for part in py_file.parts):
                continue
            try:
                content = py_file.read_text(encoding="utf-8", errors="ignore")
                if re.search(r"(?:mcp|server|app)\.run\s*\(", content):
                    notes.append(f"found mcp.run() in {py_file.relative_to(repo)}")
                    return py_file, ["python"]
                if re.search(r"FastMCP|fastmcp|MCPServer|from\s+mcp\b|import\s+mcp\b|mcp\.server\.|StreamableHTTPSessionManager", content):
                    rel = py_file.relative_to(repo)
                    notes.append(f"found MCP python entry in {rel}")
                    if py_file.name == "__main__.py":
                        pkg_parts = list(rel.parts[:-1])
                        if pkg_parts and pkg_parts[0] == "src":
                            pkg_parts = pkg_parts[1:]
                        if pkg_parts:
                            return py_file, ["python", "-m", ".".join(pkg_parts)]
                    return py_file, ["python"]
                protocol_hits = sum(
                    1 for marker in ("jsonrpc", "tools/list", "tools/call", "initialize", "mcp_stream_url", "mcp_sse_url", "mcp_url")
                    if marker in content
                )
                if protocol_hits >= 4 and ("FastAPI(" in content or "uvicorn.run" in content):
                    rel = py_file.relative_to(repo)
                    notes.append(f"found protocol-style MCP service in {rel}")
                    return py_file, ["python"]
            except Exception:
                pass

        return None, None

    def _parse_pyproject_scripts(self, repo: Path):
        """Parse pyproject.toml for package name and [project.scripts] entries."""
        pyproject = repo / "pyproject.toml"
        if not pyproject.exists():
            return None, None
        try:
            import tomllib  # Python 3.11+
        except ImportError:
            try:
                import tomli as tomllib  # fallback
            except ImportError:
                # Manual regex parse as last resort
                content = pyproject.read_text(encoding="utf-8", errors="ignore")
                name_m = re.search(r'^\s*name\s*=\s*"([^"]+)"', content, re.MULTILINE)
                pkg_name = name_m.group(1).replace("-", "_") if name_m else None
                return pkg_name, None

        try:
            with open(pyproject, "rb") as f:
                data = tomllib.load(f)
        except Exception:
            return None, None

        project = data.get("project", {})
        pkg_name = project.get("name", "").replace("-", "_")
        scripts = project.get("scripts", {})
        # Also check Poetry-style
        poetry_scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})
        scripts.update(poetry_scripts)

        # Return the first script entry that looks like an MCP server
        for name, target in scripts.items():
            if "mcp" in name.lower() or "server" in name.lower():
                return pkg_name, target
        if scripts:
            return pkg_name, next(iter(scripts.values()))

        return pkg_name, None

    def _inject_python_instrumentation(
        self,
        entry: Path,
        cmd_prefix: List[str],
        repo: Path,
    ) -> List[str]:
        """
        Build Python startup command with oracle instrumentation.

        Strategy: prepend a sitecustomize.py shim via PYTHONPATH.
        The actual env injection happens in ServerLauncher; here we
        just return the base command.  The shim dir is noted in the
        startup_command as a special sentinel so ServerLauncher can
        pick it up.
        """
        # If cmd_prefix ends with "-m module", return as-is
        if len(cmd_prefix) >= 3 and cmd_prefix[1] == "-m":
            return cmd_prefix  # ["python", "-m", "package_name"]
        return cmd_prefix + [str(entry)]

    # ──────────────────────────────────────────────────────────────
    # Build helper
    # ──────────────────────────────────────────────────────────────

    def _run_build(self, repo: Path, build_cmd: List[str], notes: List[str]) -> bool:
        """Run the build command in repo. Returns True on success."""
        cmd_str = " ".join(build_cmd)
        notes.append(f"running build: {cmd_str}")
        logger.info("[%s] Running build: %s", repo.name, cmd_str)
        t0 = time.time()
        try:
            result = subprocess.run(
                build_cmd,
                cwd=str(repo),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=self.build_timeout,
            )
            elapsed = time.time() - t0
            if result.returncode == 0:
                notes.append("build succeeded")
                logger.info("[%s] Build succeeded in %.1fs", repo.name, elapsed)
                return True
            else:
                snippet = result.stderr.strip()[:200]
                notes.append(f"build failed (rc={result.returncode}): {snippet}")
                logger.warning("[%s] Build failed (rc=%d, %.1fs): %s",
                               repo.name, result.returncode, elapsed, snippet)
                return False
        except subprocess.TimeoutExpired:
            notes.append(f"build timed out after {self.build_timeout}s")
            logger.warning("[%s] Build timed out after %ds", repo.name, self.build_timeout)
            return False
        except Exception as e:
            notes.append(f"build error: {e}")
            logger.warning("[%s] Build error: %s", repo.name, e)
            return False

    # ──────────────────────────────────────────────────────────────
    # Validation: real MCP handshake
    # ──────────────────────────────────────────────────────────────

    def _validate_server(self, result: DetectionResult) -> bool:
        """
        Start the server, send MCP `initialize` over stdio, and check
        for a valid JSON-RPC response.  Returns True on success.
        """
        env = os.environ.copy()
        _tmp_fd, _tmp_path = tempfile.mkstemp(suffix=".json")
        os.close(_tmp_fd)
        env["MCP_FUZZER_ORACLE_LOG"] = _tmp_path
        # Inject Python hook dir if available
        if result.language == "python" and self._python_hook_dir.exists():
            env["PYTHONPATH"] = str(self._python_hook_dir) + os.pathsep + env.get("PYTHONPATH", "")

        try:
            proc = subprocess.Popen(
                result.startup_command,
                cwd=str(result.repo_path),
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
        except FileNotFoundError as e:
            logger.debug("Validation failed to start process: %s", e)
            return False

        # MCP initialize request (JSON-RPC 2.0)
        init_msg = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcp-s-fuzzer-detector", "version": "1.0"},
            },
        }) + "\n"

        try:
            proc.stdin.write(init_msg.encode())
            proc.stdin.flush()
            # Some servers print banners or startup hints to stdout before the
            # JSON-RPC initialize response, so keep reading until we either see
            # a valid JSON line or hit the validation deadline.
            deadline = time.time() + self.validate_timeout
            response_buffer = b""
            while time.time() < deadline:
                chunk = proc.stdout.read1(4096) if hasattr(proc.stdout, "read1") else proc.stdout.read(4096)
                if chunk:
                    response_buffer += chunk
                    for line in response_buffer.decode(errors="ignore").splitlines():
                        line = line.strip()
                        if not line.startswith("{"):
                            continue
                        try:
                            data = json.loads(line)
                        except Exception:
                            continue
                        if data.get("id") == 1 and "result" in data:
                            return True
                elif proc.poll() is not None:
                    break
                time.sleep(0.05)

            if response_buffer:
                for line in response_buffer.decode(errors="ignore").splitlines():
                    line = line.strip()
                    if not line.startswith("{"):
                        continue
                    try:
                        data = json.loads(line)
                    except Exception:
                        continue
                    if data.get("id") == 1 and "result" in data:
                        return True
            return False
        except Exception as e:
            logger.debug("Validation handshake error: %s", e)
            return False
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
