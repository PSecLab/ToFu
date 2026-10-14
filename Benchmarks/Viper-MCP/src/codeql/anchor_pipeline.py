from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import Any, Dict, Optional

from .anchored_evidence import enrich_report_with_anchored_evidence


def repo_output_dir(codeql_cfg: Dict[str, Any], mcp_cfg: Dict[str, Any]) -> Path:
    repo_path = str(mcp_cfg.get("repo_path") or "")
    repo = Path(repo_path)
    repo_name = repo.name if repo.is_dir() else repo.stem
    repo_name = re.sub(r"[^\w\-_.]", "_", repo_name)
    return (Path(codeql_cfg.get("report_path", "./output")) / repo_name).resolve()


def _load_report(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def report_needs_anchor(report_path: Path) -> bool:
    report = _load_report(report_path)
    if not report:
        return True
    anchored = report.get("anchored_evidence")
    return not isinstance(anchored, dict) or anchored.get("mode") != "codeql_anchor_queries"


def ensure_anchored_report(
    *,
    codeql_cfg: Dict[str, Any],
    mcp_cfg: Dict[str, Any],
    sarif_path: Optional[Path] = None,
    force: bool = False,
    log: Any = None,
) -> Optional[Path]:
    """Create/update report.json and attach CodeQL anchor evidence.

    This is the single system path for codeql_anchor_queries. It is called both
    after a fresh static scan and before fuzzing when --skip-codeql reuses old
    artifacts.
    """
    output_dir = repo_output_dir(codeql_cfg, mcp_cfg)
    report_path = output_dir / "report.json"
    db_path = output_dir / "codeql_db"
    debug_path = output_dir / "anchored_evidence.json"
    sarif = Path(sarif_path).resolve() if sarif_path else output_dir / "results.sarif"

    if not report_path.exists() and sarif.exists():
        try:
            sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
            from codeql.convert_sarif import convert_sarif_to_report

            convert_sarif_to_report(str(sarif), str(report_path), log=log)
        except Exception as exc:
            if log and hasattr(log, "warning"):
                log.warning("Failed to convert SARIF before anchor enrichment: %s", exc)
            return None

    if not report_path.exists():
        if log and hasattr(log, "warning"):
            log.warning("Anchor enrichment skipped: report not found: %s", report_path)
        return None

    if not force and not report_needs_anchor(report_path):
        if log and hasattr(log, "info"):
            log.info("Anchor enrichment already present: %s", report_path)
        return report_path

    ok = enrich_report_with_anchored_evidence(
        report_path=str(report_path),
        codeql_binary=codeql_cfg.get("codeql_binary_path", "codeql"),
        database_path=str(db_path),
        query_pack_root=codeql_cfg.get("query_pack_root"),
        language=codeql_cfg.get("language", ""),
        debug_output_path=str(debug_path),
        log=log,
    )
    if log and hasattr(log, "info"):
        log.info("Anchor enrichment %s for %s", "completed" if ok else "fell back", report_path)
    return report_path
