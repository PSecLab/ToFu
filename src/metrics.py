import os
import re
import csv
import time
import hashlib
import logging
import threading
from dataclasses import dataclass, asdict
from typing import Optional
from pymongo import MongoClient

logger = logging.getLogger(__name__)

# Robust Regex matching standard and compact LibFuzzer event lines (case-insensitive)
LIBFUZZER_LINE_RE = re.compile(
    r"^#(?P<exec_count>\d+)\s+(?P<event_type>[A-Za-z0-9_]+)\s+"
    r"(?:cov:\s*(?P<cov>\d+)\s+)?"
    r"(?:ft:\s*(?P<ft>\d+)\s+)?"
    r"(?:corp:\s*(?P<corp_count>\d+)/(?P<corp_bytes>\d+)b\s+)?"
    r"(?:lim:\s*\d+\s+)?"
    r"exec/s:\s*(?P<exec_per_sec>\d+)",
    re.IGNORECASE,
)


@dataclass
class CoverageDataPoint:
    timestamp: float
    relative_time_sec: float
    tool: str
    exec_count: int
    event_type: str
    cov_edges: int
    features: int
    corpus_count: int
    corpus_bytes: int
    exec_per_sec: int

    def to_dict(self) -> dict:
        return asdict(self)


class CoverageTimelineCollector:
    """
    Collects, parses, and persists code coverage timelines over time.
    Supports continuous time-interval snapshots (e.g. every 60s) and LibFuzzer events.
    """

    CSV_HEADER = [
        "timestamp",
        "relative_time_sec",
        "tool",
        "exec_count",
        "event_type",
        "cov_edges",
        "features",
        "corpus_count",
        "corpus_bytes",
        "exec_per_sec",
    ]

    def __init__(
        self,
        output_dir: str = "metrics",
        csv_filename: Optional[str] = None,
        export_csv: bool = True,
        export_mongo: bool = False,
        mongo_uri: str = "mongodb://localhost:27017/",
        mongo_db: str = "toolfuzz_db",
        mongo_collection: str = "coverage_timeline",
        sample_interval_sec: float = 60.0,
    ):
        self.output_dir = output_dir
        self.export_csv = export_csv
        self.export_mongo = export_mongo
        self.mongo_uri = mongo_uri
        self.mongo_db_name = mongo_db
        self.mongo_collection_name = mongo_collection
        self.sample_interval_sec = sample_interval_sec

        self._lock = threading.Lock()
        self._current_tool = ""
        self._start_time = None
        self.data_points: list[CoverageDataPoint] = []

        # Latest known cumulative metrics state
        self._last_exec_count = 0
        self._last_cov = 0
        self._last_ft = 0
        self._last_corp_count = 0
        self._last_corp_bytes = 0
        self._last_exec_per_sec = 0

        self._csv_file = None
        self._csv_writer = None
        self._csv_path = None
        self._mongo_client = None

        # --- Findings-over-time timeline (opt-in, e.g. the 24h deep campaign) ---
        # Off by default: only active when TOFU_FINDINGS_TIMELINE is set to a
        # truthy value (the 24h run script sets it). Normal runs pay nothing.
        self._findings_enabled = os.environ.get(
            "TOFU_FINDINGS_TIMELINE", ""
        ).strip().lower() not in ("", "0", "false", "no")
        self._findings_file = None
        self._findings_writer = None
        self._findings_path = None
        self._seen_findings: set[str] = set()
        self._n_distinct_findings = 0

        # Periodic background sampler thread
        self._sampler_thread = None
        self._stop_sampler = threading.Event()

        if self.export_csv:
            os.makedirs(self.output_dir, exist_ok=True)
            if csv_filename:
                self._csv_path = os.path.join(self.output_dir, csv_filename)
            else:
                timestamp_str = time.strftime("%Y%m%d_%H%M%S")
                self._csv_path = os.path.join(
                    self.output_dir, f"coverage_timeline_{timestamp_str}.csv"
                )
            self._init_csv()

    def _init_csv(self):
        file_exists = os.path.exists(self._csv_path) and os.path.getsize(self._csv_path) > 0
        self._csv_file = open(self._csv_path, mode="a", newline="", encoding="utf-8")
        self._csv_writer = csv.DictWriter(self._csv_file, fieldnames=self.CSV_HEADER)
        if not file_exists:
            self._csv_writer.writeheader()
            self._csv_file.flush()

    FINDINGS_HEADER = [
        "relative_time_sec",
        "tool",
        "n_distinct",
        "input_hash",
        "triggered_sanitizers",
        "input_preview",
    ]

    def _init_findings_csv(self):
        """Lazily open the findings-timeline CSV (only when the first finding fires
        and the feature is enabled). Shares output_dir with the coverage timeline
        so the two series line up on the same per-config time base."""
        os.makedirs(self.output_dir, exist_ok=True)
        timestamp_str = time.strftime("%Y%m%d_%H%M%S")
        self._findings_path = os.path.join(
            self.output_dir, f"findings_timeline_{timestamp_str}.csv"
        )
        exists = os.path.exists(self._findings_path) and os.path.getsize(self._findings_path) > 0
        self._findings_file = open(self._findings_path, mode="a", newline="", encoding="utf-8")
        self._findings_writer = csv.DictWriter(self._findings_file, fieldnames=self.FINDINGS_HEADER)
        if not exists:
            self._findings_writer.writeheader()
            self._findings_file.flush()

    def record_finding(self, tool_name: str, inputs, triggered_sanitizers, analysis: str = "") -> None:
        """Append one row per NEW distinct (input, sanitizer-set) alert, timestamped
        relative to this tool's fuzz start. No-op unless TOFU_FINDINGS_TIMELINE is
        set, so it never touches normal runs. Never raises into the fuzz loop.

        The relative time uses the same start reference as the coverage sampler
        (set in set_tool), giving an aligned bugs-over-time series for RQ4."""
        if not self._findings_enabled:
            return
        try:
            sans = sorted(triggered_sanitizers or [])
            key_src = f"{repr(inputs)}|{','.join(sans)}"
            h = hashlib.sha1(key_src.encode("utf-8", errors="replace")).hexdigest()[:16]
            with self._lock:
                if h in self._seen_findings:
                    return
                self._seen_findings.add(h)
                self._n_distinct_findings += 1
                rel = max(0.0, time.time() - self._start_time) if self._start_time else 0.0
                if self._findings_writer is None:
                    self._init_findings_csv()
                self._findings_writer.writerow({
                    "relative_time_sec": round(rel, 3),
                    "tool": tool_name or self._current_tool,
                    "n_distinct": self._n_distinct_findings,
                    "input_hash": h,
                    "triggered_sanitizers": ",".join(sans),
                    "input_preview": repr(inputs)[:200],
                })
                self._findings_file.flush()
        except Exception as e:
            logger.debug(f"record_finding skipped (non-fatal): {e}")

    def _get_mongo_collection(self):
        if self._mongo_client is None:
            self._mongo_client = MongoClient(
                self.mongo_uri, serverSelectionTimeoutMS=2000
            )
        db = self._mongo_client[self.mongo_db_name]
        return db[self.mongo_collection_name]

    def set_tool(self, tool_name: str, start_time: Optional[float] = None):
        """Sets the current target tool and starts the periodic timeline sampler."""
        with self._lock:
            self._current_tool = tool_name
            self._start_time = start_time if start_time is not None else time.time()
            self._last_exec_count = 0
            self._last_cov = 0
            self._last_ft = 0
            self._last_corp_count = 0
            self._last_corp_bytes = 0
            self._last_exec_per_sec = 0

        self._start_sampler()

    def _start_sampler(self):
        """Spawns the background time-interval sampler thread if enabled."""
        if self.sample_interval_sec and self.sample_interval_sec > 0 and self._sampler_thread is None:
            self._stop_sampler.clear()
            self._sampler_thread = threading.Thread(target=self._sampler_loop, daemon=True)
            self._sampler_thread.start()

    def _sampler_loop(self):
        """Emits a snapshot every sample_interval_sec (e.g. every 60s) regardless of LibFuzzer pulse steps."""
        while not self._stop_sampler.wait(timeout=self.sample_interval_sec):
            with self._lock:
                if not self._start_time:
                    continue
                now = time.time()
                rel_sec = max(0.0, now - self._start_time)
                # Compute average exec/s if last recorded was 0
                avg_speed = (
                    int(self._last_exec_count / rel_sec)
                    if (rel_sec > 0 and self._last_exec_count > 0)
                    else self._last_exec_per_sec
                )
                dp = CoverageDataPoint(
                    timestamp=now,
                    relative_time_sec=round(rel_sec, 3),
                    tool=self._current_tool,
                    exec_count=self._last_exec_count,
                    event_type="TIME_SAMPLE",
                    cov_edges=self._last_cov,
                    features=self._last_ft,
                    corpus_count=self._last_corp_count,
                    corpus_bytes=self._last_corp_bytes,
                    exec_per_sec=avg_speed,
                )
                self._record_datapoint_unlocked(dp)

    def record_execution_progress(self, exec_count: int):
        """Updates internal execution counter from the fuzzer test loop."""
        with self._lock:
            if exec_count > self._last_exec_count:
                self._last_exec_count = exec_count

    def record_datapoint(self, dp: CoverageDataPoint):
        """Stores a coverage data point in memory, CSV, and MongoDB."""
        with self._lock:
            self._record_datapoint_unlocked(dp)

    def _record_datapoint_unlocked(self, dp: CoverageDataPoint):
        self.data_points.append(dp)

        # 1. CSV
        if self.export_csv and self._csv_writer:
            try:
                self._csv_writer.writerow(dp.to_dict())
                self._csv_file.flush()
            except Exception as e:
                logger.error(f"[CoverageCollector] Failed to write CSV row: {e}")

        # 2. MongoDB
        if self.export_mongo:
            try:
                col = self._get_mongo_collection()
                col.insert_one(dp.to_dict())
            except Exception as e:
                logger.debug(f"[CoverageCollector] MongoDB metric logging skipped: {e}")

    def parse_libfuzzer_line(
        self, line: str, tool_name: Optional[str] = None, start_time: Optional[float] = None
    ) -> Optional[CoverageDataPoint]:
        """
        Parses a single LibFuzzer line. If it matches a coverage event, creates and records
        the CoverageDataPoint.
        """
        line_clean = line.strip()
        match = LIBFUZZER_LINE_RE.search(line_clean)
        if not match:
            return None

        now = time.time()
        tool = tool_name or self._current_tool or "unknown"
        ref_start = start_time or self._start_time or now
        relative_time = max(0.0, now - ref_start)

        with self._lock:
            # Update last known metrics
            exec_cnt = int(match.group("exec_count"))
            if exec_cnt > self._last_exec_count:
                self._last_exec_count = exec_cnt

            cov_val = match.group("cov")
            if cov_val is not None:
                self._last_cov = int(cov_val)

            ft_val = match.group("ft")
            if ft_val is not None:
                self._last_ft = int(ft_val)

            corp_count_val = match.group("corp_count")
            if corp_count_val is not None:
                self._last_corp_count = int(corp_count_val)

            corp_bytes_val = match.group("corp_bytes")
            if corp_bytes_val is not None:
                self._last_corp_bytes = int(corp_bytes_val)

            self._last_exec_per_sec = int(match.group("exec_per_sec"))

            dp = CoverageDataPoint(
                timestamp=now,
                relative_time_sec=round(relative_time, 3),
                tool=tool,
                exec_count=self._last_exec_count,
                event_type=match.group("event_type").upper(),
                cov_edges=self._last_cov,
                features=self._last_ft,
                corpus_count=self._last_corp_count,
                corpus_bytes=self._last_corp_bytes,
                exec_per_sec=self._last_exec_per_sec,
            )
            self._record_datapoint_unlocked(dp)
            return dp

    def emit_final_snapshot(self, total_execs: Optional[int] = None):
        """Emits an exact final snapshot at the end of the session."""
        with self._lock:
            if not self._start_time:
                return
            now = time.time()
            rel_sec = max(0.0, now - self._start_time)
            if total_execs is not None and total_execs > self._last_exec_count:
                self._last_exec_count = total_execs
            speed = (
                int(self._last_exec_count / rel_sec)
                if (rel_sec > 0 and self._last_exec_count > 0)
                else self._last_exec_per_sec
            )
            dp = CoverageDataPoint(
                timestamp=now,
                relative_time_sec=round(rel_sec, 3),
                tool=self._current_tool,
                exec_count=self._last_exec_count,
                event_type="FINAL_SNAPSHOT",
                cov_edges=self._last_cov,
                features=self._last_ft,
                corpus_count=self._last_corp_count,
                corpus_bytes=self._last_corp_bytes,
                exec_per_sec=speed,
            )
            self._record_datapoint_unlocked(dp)

    def close(self):
        """Flushes and closes all open file, thread, and database handles."""
        self._stop_sampler.set()
        if self._sampler_thread and self._sampler_thread.is_alive():
            self._sampler_thread.join(timeout=1.0)
            self._sampler_thread = None

        with self._lock:
            if self._csv_file and not self._csv_file.closed:
                try:
                    self._csv_file.flush()
                    self._csv_file.close()
                except Exception:
                    pass
            if self._findings_file and not self._findings_file.closed:
                try:
                    self._findings_file.flush()
                    self._findings_file.close()
                except Exception:
                    pass
            if self._mongo_client:
                try:
                    self._mongo_client.close()
                except Exception:
                    pass
