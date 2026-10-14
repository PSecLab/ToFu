import os
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from src.utils.instrumentation import inject_python_hook_env


class ServerLauncher:
    def __init__(
        self,
        repo_path: str,
        startup_command: Optional[List[str]] = None,
        work_dir: Optional[str] = None,
        env: Optional[Dict[str, str]] = None,
        instrument: bool = False,
        instrumentation_script: Optional[str] = None,
    ):
        self.repo_path = Path(repo_path).resolve()
        self.work_dir = Path(work_dir) if work_dir else self.repo_path
        self.startup_command = startup_command or ["node", "dist/index.js"]
        self.env = dict(env) if env else {}
        self.instrument = instrument
        self.instrumentation_script = instrumentation_script
        self._process: Optional[subprocess.Popen] = None

    def _build_command(self) -> List[str]:
        if self.instrument and self.instrumentation_script:
            script = Path(self.instrumentation_script).resolve()
            if script.exists():
                return ["node", "-r", str(script)] + self.startup_command[1:]
        return self.startup_command

    def start(self) -> subprocess.Popen:
        cmd = self._build_command()
        cwd = str(self.work_dir)
        env = os.environ.copy()
        env.update(self.env)
        results_dir = Path(__file__).parent.parent.parent / "results"
        default_log_path = results_dir / "oracle.json"
        env["MCP_FUZZER_ORACLE_LOG"] = os.environ.get(
            "MCP_FUZZER_ORACLE_LOG", str(default_log_path)
        )
        env = inject_python_hook_env(cmd, env, Path(__file__).resolve().parents[2])

        self._process = subprocess.Popen(
            cmd,
            cwd=cwd,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return self._process

    def stop(self):
        """Stop the launched server process."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self._process = None
