import asyncio
import re
from pathlib import Path
from typing import Optional

from ..utils.config import Config
from ..utils.logger import setup_logger
from ..codeql.anchor_pipeline import ensure_anchored_report
from .codeql_runner import CodeQLRunner
from .sarif_extractor import extract_from_sarif


class PipelineOrchestrator:

    def __init__(self, config: Config):
        self.config = config
        self.logger = setup_logger(config.logging)
        self.codeql_cfg = config.codeql
        self.mcp_cfg = config.mcp_server
        self.output_cfg = config.output

    def _get_repo_name(self, repo_path: str) -> str:
        repo_path_obj = Path(repo_path)
        repo_name = repo_path_obj.name if repo_path_obj.is_dir() else repo_path_obj.stem
        repo_name = re.sub(r'[^\w\-_\.]', '_', repo_name)
        return repo_name

    def _has_existing_codeql_results(self, repo_output_dir: Path, db_path: Path, sarif_filename: str = "results.sarif") -> bool:
        """Return True if database and scan results already exist, so CodeQL can be skipped."""
        sarif_path = repo_output_dir / sarif_filename
        db_yml = db_path / "codeql-database.yml"
        db_ok = db_path.is_dir() and db_yml.is_file()
        sarif_ok = sarif_path.is_file() and sarif_path.stat().st_size > 0
        return db_ok and sarif_ok

    def run_codeql_scan(self) -> Optional[Path]:
        if not self.codeql_cfg.get("enabled", True):
            self.logger.info("CodeQL scan disabled, skipping")
            return None

        repo_path = self.mcp_cfg.get("repo_path", "")
        if not repo_path or not Path(repo_path).exists():
            self.logger.warning(f"Repo path not found: {repo_path}")
            return None

        repo_name = self._get_repo_name(repo_path)
        base_output = Path(self.codeql_cfg.get("report_path", "./output"))
        
        repo_output_dir = base_output / repo_name
        db_path = repo_output_dir / "codeql_db"
        output_path = repo_output_dir
        sarif_filename = "results.sarif"
        existing_sarif = repo_output_dir / sarif_filename

        # Skip CodeQL if database and SARIF results already exist
        if self._has_existing_codeql_results(repo_output_dir, db_path, sarif_filename):
            self.logger.info(
                "CodeQL database and results already exist for '%s', skipping scan (use --skip-codeql to avoid this check)",
                repo_name,
            )
            return existing_sarif if existing_sarif.is_file() else None
        
        codeql_bin = self.codeql_cfg.get("codeql_binary_path", "codeql")
        queries = self.codeql_cfg.get("queries", "javascript-security-and-quality")
        if not queries:
            self.logger.error("CodeQL queries not configured. Please set 'queries' in config.yaml")
            return None

        query_pack_root = self.codeql_cfg.get("query_pack_root")
        runner = CodeQLRunner(
            codeql_binary=codeql_bin,
            repo_path=repo_path,
            database_path=str(db_path),
            output_path=str(output_path),
            language=self.codeql_cfg.get("language", "javascript"),
            query_pack_root=query_pack_root,
        )
        self.logger.info(f"Running CodeQL scan for repository '{repo_name}' with queries: {queries}")
        sarif_path = runner.run_full_scan(queries)
        if sarif_path:
            self.logger.info(f"CodeQL SARIF for '{repo_name}': {sarif_path}")
        return sarif_path

    def extract_rules(self, sarif_path: Path) -> tuple:
        repo_path = self.mcp_cfg.get("repo_path", "")
        repo_name = self._get_repo_name(repo_path)
        base_output = Path(self.codeql_cfg.get("report_path", "./output"))
        output_dir = base_output / repo_name
        output_dir.mkdir(parents=True, exist_ok=True)

        enter_path, oracle_path = extract_from_sarif(
            str(sarif_path), str(output_dir), repo_path
        )
        self.logger.info(f"Extracted enter_hook for '{repo_name}': {enter_path}, oracle: {oracle_path}")

        try:
            report_path = ensure_anchored_report(
                codeql_cfg=self.codeql_cfg,
                mcp_cfg=self.mcp_cfg,
                sarif_path=Path(sarif_path),
                force=True,
                log=self.logger,
            )
            if report_path:
                self.logger.info(f"Fuzzer report for '{repo_name}': {report_path}")
        except Exception as e:
            self.logger.warning(f"Report/anchor enrichment failed: {e}")

        return enter_path, oracle_path

    def get_startup_command(self) -> list:
        cmd = self.mcp_cfg.get("startup_command")
        if cmd:
            return cmd if isinstance(cmd, list) else cmd.split()
        repo_path = Path(self.mcp_cfg.get("repo_path", ""))
        dist = repo_path / "dist" / "index.js"
        src = repo_path / "src" / "index.ts"
        if dist.exists():
            return ["node", str(dist)]
        if src.exists():
            return ["npx", "ts-node", str(src)]
        return ["node", "index.js"]

    def run(self) -> bool:
        sarif_path = self.run_codeql_scan()
        if sarif_path:
            self.extract_rules(Path(sarif_path))
        return True


async def run_pipeline(config_path: str = "config.yaml") -> bool:
    from ..utils.config import Config

    config = Config(config_path)
    orch = PipelineOrchestrator(config)
    orch.run()
    return True
