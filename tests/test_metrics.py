import os
import csv
import time
import pytest
from src.metrics import CoverageTimelineCollector, CoverageDataPoint, LIBFUZZER_LINE_RE


def test_regex_matching_various_libfuzzer_lines():
    # 1. NEW event
    line1 = "#1234\tNEW\tcov: 456 ft: 789 corp: 12/34b lim: 64 exec/s: 120 rss: 45Mb"
    m1 = LIBFUZZER_LINE_RE.search(line1)
    assert m1 is not None
    assert m1.group("exec_count") == "1234"
    assert m1.group("event_type") == "NEW"
    assert m1.group("cov") == "456"
    assert m1.group("ft") == "789"
    assert m1.group("corp_count") == "12"
    assert m1.group("corp_bytes") == "34"
    assert m1.group("exec_per_sec") == "120"

    # 2. PULSE event
    line2 = "#2500 PULSE cov: 512 ft: 900 corp: 15/48b lim: 128 exec/s: 150 rss: 50Mb"
    m2 = LIBFUZZER_LINE_RE.search(line2)
    assert m2 is not None
    assert m2.group("exec_count") == "2500"
    assert m2.group("event_type") == "PULSE"
    assert m2.group("cov") == "512"
    assert m2.group("ft") == "900"
    assert m2.group("corp_count") == "15"
    assert m2.group("corp_bytes") == "48"
    assert m2.group("exec_per_sec") == "150"

    # 3. REDUCE event
    line3 = "#5000\tREDUCE\tcov: 512 ft: 900 corp: 15/40b exec/s: 155 rss: 52Mb"
    m3 = LIBFUZZER_LINE_RE.search(line3)
    assert m3 is not None
    assert m3.group("event_type") == "REDUCE"
    assert m3.group("corp_bytes") == "40"

    # 4. INITED event
    line4 = "#120\tINITED\tcov: 45 ft: 50 corp: 1/1b lim: 64 exec/s: 0 rss: 30Mb"
    m4 = LIBFUZZER_LINE_RE.search(line4)
    assert m4 is not None
    assert m4.group("event_type") == "INITED"
    assert m4.group("cov") == "45"

    # 5. Non-matching lines (like normal logs)
    assert LIBFUZZER_LINE_RE.search("INFO: Seed: 12345") is None
    assert LIBFUZZER_LINE_RE.search("Done 123 runs in 1 second") is None


def test_coverage_timeline_collector_csv(tmp_path):
    metrics_dir = str(tmp_path / "metrics")
    collector = CoverageTimelineCollector(
        output_dir=metrics_dir,
        csv_filename="test_coverage.csv",
        export_csv=True,
        export_mongo=False,
    )

    t0 = time.time() - 10.0  # started 10s ago
    collector.set_tool("fetch_data", start_time=t0)

    # Stream several lines
    l1 = "#100\tINITED\tcov: 20 ft: 30 corp: 1/10b lim: 64 exec/s: 0 rss: 30Mb"
    l2 = "#500\tNEW\tcov: 45 ft: 80 corp: 5/120b lim: 64 exec/s: 200 rss: 32Mb"
    l3 = "#1000\tPULSE\tcov: 45 ft: 80 corp: 5/120b lim: 64 exec/s: 210 rss: 33Mb"

    dp1 = collector.parse_libfuzzer_line(l1)
    dp2 = collector.parse_libfuzzer_line(l2)
    dp3 = collector.parse_libfuzzer_line(l3)

    assert dp1 is not None and dp1.event_type == "INITED"
    assert dp2 is not None and dp2.event_type == "NEW"
    assert dp3 is not None and dp3.event_type == "PULSE"
    assert len(collector.data_points) == 3

    collector.close()

    # Read CSV file and verify contents
    csv_file = os.path.join(metrics_dir, "test_coverage.csv")
    assert os.path.exists(csv_file)

    with open(csv_file, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    assert len(rows) == 3
    assert rows[0]["tool"] == "fetch_data"
    assert rows[0]["event_type"] == "INITED"
    assert rows[0]["cov_edges"] == "20"
    assert rows[0]["features"] == "30"
    assert rows[0]["corpus_count"] == "1"
    assert rows[0]["corpus_bytes"] == "10"

    assert rows[1]["event_type"] == "NEW"
    assert rows[1]["cov_edges"] == "45"
    assert rows[1]["features"] == "80"
    assert float(rows[1]["relative_time_sec"]) >= 10.0

    assert rows[2]["event_type"] == "PULSE"
    assert rows[2]["exec_count"] == "1000"
