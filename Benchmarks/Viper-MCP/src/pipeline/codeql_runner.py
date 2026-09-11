import logging
import subprocess
from pathlib import Path
from typing import Optional

logger = logging.getLogger("viper_mcp.codeql")


class CodeQLRunner:
    def __init__(
        self,
        codeql_binary: str,
        repo_path: str,
        database_path: str,
        output_path: str,
        language: str = "javascript",
        query_pack_root: Optional[str] = None,
    ):
        self.codeql_binary = codeql_binary
        self.repo_path = Path(repo_path).resolve()
        self.database_path = Path(database_path).resolve()
        self.output_path = Path(output_path).resolve()
        self.language = language
        self.sarif_path: Optional[Path] = None
        self.query_pack_root = Path(query_pack_root).resolve() if query_pack_root else None

    def database_create(self) -> bool:
        self.database_path.mkdir(parents=True, exist_ok=True)
        cmd = [
            self.codeql_binary,
            "database",
            "create",
            str(self.database_path),
            f"--language={self.language}",
            f"--source-root={self.repo_path}",
            "--overwrite",
        ]
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=str(self.repo_path))
            return True
        except subprocess.CalledProcessError as e:
            logger.error("CodeQL database create failed: %s", e.stderr)
            return False

    def analyze(self, queries: str, sarif_filename: str = "results.sarif") -> Optional[Path]:

        self.output_path.mkdir(parents=True, exist_ok=True)
        self.sarif_path = self.output_path / sarif_filename
        query_args = (queries,) if isinstance(queries, str) else list(queries)
        cmd = [
            self.codeql_binary,
            "database",
            "analyze",
            "--format=sarif-latest",
            f"--output={self.sarif_path}",
            "--sarif-add-snippets",
            "--",
            str(self.database_path),
            *query_args,
        ]
        try:
            logger.info(f"Running CodeQL analyze with queries: {queries}")
            logger.debug(f"Full command: {' '.join(str(x) for x in cmd)}")
            cwd = str(self.query_pack_root) if self.query_pack_root and self.query_pack_root.is_dir() else None
            if cwd:
                logger.debug("Running analyze with cwd=%s (query pack root)", cwd)
            result = subprocess.run(cmd, check=True, capture_output=True, text=True, cwd=cwd)
            logger.info(f"CodeQL analyze completed successfully")
            if result.stdout:
                logger.debug(f"CodeQL stdout: {result.stdout}")
            return self.sarif_path
        except subprocess.CalledProcessError as e:
            logger.error("CodeQL analyze failed with exit code %d", e.returncode)
            logger.error("CodeQL stderr: %s", e.stderr)
            if e.stdout:
                logger.error("CodeQL stdout: %s", e.stdout)
            logger.error("Command that failed: %s", ' '.join(str(x) for x in cmd))
            return None

    def run_full_scan(self, queries: str) -> Optional[Path]:
        if not self.database_create():
            return None
        return self.analyze(queries)
