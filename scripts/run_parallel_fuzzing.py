#!/usr/bin/env python3
"""
Multi-Tool Parallel Campaign Runner
Launches N concurrent fuzzing runs targeting different tools in parallel.
Each tool runs in its own isolated process, collecting metrics and timeline data.
"""

import os
import sys
import time
import signal
import logging
import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] [%(processName)s] %(message)s"
)
logger = logging.getLogger("MultiFuzzRunner")

# 6 diverse target tools across document converters, URL verifiers, memory management, archives and security introspection
DEFAULT_TARGET_SUITE = [
    {
        "name": "markitdown_convert",
        "cmd": [sys.executable, "targets/fuzz_markitdown_mcp.py", "--time"],
        "desc": "MarkItDown Document & URI Converter (convert_to_markdown)"
    },
    {
        "name": "http_check_url",
        "cmd": [sys.executable, "targets/fuzz_http_check.py", "--time"],
        "desc": "HTTP & URL Security Inspector (check_url_features)"
    },
    {
        "name": "extract_har_archive",
        "cmd": [sys.executable, "targets/fuzz_extract_har.py", "--time"],
        "desc": "HAR / ZIP Archive Extractor (extract_har)"
    },
    {
        "name": "basic_memory_search",
        "cmd": [sys.executable, "targets/fuzz_basic_memory.py", "--tool", "search", "--time"],
        "desc": "Basic Memory Note & Semantic Search (basic_memory.search)"
    },
    {
        "name": "memo_search",
        "cmd": [sys.executable, "targets/fuzz_memo.py", "--tool", "memo_search", "--duration"],
        "desc": "Memo Knowledge & Graph Search (memo_search)"
    },
    {
        "name": "pmb_search",
        "cmd": [sys.executable, "targets/fuzz_pmb.py", "--single-tool", "search", "--max-time-per-target-sec"],
        "desc": "Persistent Memory Bank Search (pmb.search)"
    }
]


def run_target(target: dict, duration_sec: int, workspace_dir: str) -> dict:
    tool_name = target["name"]
    desc = target["desc"]
    base_cmd = list(target["cmd"])

    if "--time" in base_cmd:
        idx = base_cmd.index("--time")
        if idx == len(base_cmd) - 1:
            base_cmd.append(str(duration_sec))
        else:
            base_cmd[idx + 1] = str(duration_sec)
    elif "--duration" in base_cmd:
        idx = base_cmd.index("--duration")
        if idx == len(base_cmd) - 1:
            base_cmd.append(str(duration_sec))
        else:
            base_cmd[idx + 1] = str(duration_sec)
    elif "--max-time-per-target-sec" in base_cmd:
        idx = base_cmd.index("--max-time-per-target-sec")
        if idx == len(base_cmd) - 1:
            base_cmd.append(str(duration_sec))
        else:
            base_cmd[idx + 1] = str(duration_sec)

    log_dir = os.path.join(workspace_dir, "logs_parallel")
    os.makedirs(log_dir, exist_ok=True)
    log_file_path = os.path.join(log_dir, f"fuzz_{tool_name}.log")

    logger.info(f"🚀 [START] Launching '{tool_name}' ({desc}) for {duration_sec}s...")
    start_t = time.time()

    with open(log_file_path, "w", encoding="utf-8") as log_f:
        proc = subprocess.Popen(
            base_cmd,
            cwd=workspace_dir,
            stdout=log_f,
            stderr=subprocess.STDOUT,
            env=os.environ.copy()
        )
        try:
            exit_code = proc.wait(timeout=duration_sec + 30)
        except subprocess.TimeoutExpired:
            proc.send_signal(signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            exit_code = 0

    elapsed = time.time() - start_t
    logger.info(f"✅ [DONE] Target '{tool_name}' completed in {elapsed:.1f}s (Exit code: {exit_code}). Log: {log_file_path}")
    return {
        "tool": tool_name,
        "elapsed": elapsed,
        "exit_code": exit_code,
        "log": log_file_path
    }


def main():
    parser = argparse.ArgumentParser(description="Multi-Tool Parallel Campaign Runner")
    parser.add_argument(
        "--time",
        type=int,
        default=300,
        help="Duration per target in seconds (default: 300s / 5min)"
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=6,
        help="Number of concurrent workers (default: 6)"
    )
    args = parser.parse_args()

    workspace_dir = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))
    targets = DEFAULT_TARGET_SUITE[:args.workers]

    print("=" * 70)
    print(f"  TOOLFUZZ MULTI-WORKER CAMPAIGN")
    print(f"  Concurrent Workers : {len(targets)}")
    print(f"  Duration / Worker  : {args.time}s ({args.time / 60:.1f} min)")
    print(f"  Active Targets:")
    for idx, t in enumerate(targets, 1):
        print(f"    [{idx}] {t['name']:<22} - {t['desc']}")
    print("=" * 70)

    start_campaign_time = time.time()

    with ThreadPoolExecutor(max_workers=len(targets)) as executor:
        futures = [
            executor.submit(run_target, target, args.time, workspace_dir)
            for target in targets
        ]
        results = [f.result() for f in futures]

    total_time = time.time() - start_campaign_time
    print("\n" + "=" * 70)
    print(f"  CAMPAIGN COMPLETE - Total wall-clock time: {total_time:.1f}s")
    for r in results:
        print(f"  • {r['tool']:<22} -> Return {r['exit_code']} in {r['elapsed']:.1f}s")
    print("=" * 70)


if __name__ == "__main__":
    main()
