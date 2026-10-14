#!/usr/bin/env python3
"""Run an MCP stdio server while filtering non-JSON stdout chatter.

Some real-world MCP servers print banners or debug logs to stdout before they
emit JSON-RPC messages. The stdio transport treats every stdout line as a
protocol frame, so those banners break client initialization. This guard keeps
JSON-looking lines on stdout and sends everything else to stderr.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
from typing import Iterable, List


def _looks_like_jsonrpc(line: str) -> bool:
    stripped = line.strip()
    if not stripped:
        return False
    if not (stripped.startswith("{") or stripped.startswith("[")):
        return False
    try:
        json.loads(stripped)
    except Exception:
        return False
    return True


def _pump_stdout(stream) -> None:
    for raw in iter(stream.readline, ""):
        if _looks_like_jsonrpc(raw):
            sys.stdout.write(raw)
            sys.stdout.flush()
        else:
            sys.stderr.write(raw)
            sys.stderr.flush()


def _pump_stream(stream, dest) -> None:
    for raw in iter(stream.readline, ""):
        dest.write(raw)
        dest.flush()


def _pump_stdin(child_stdin) -> None:
    try:
        for raw in sys.stdin:
            child_stdin.write(raw)
            child_stdin.flush()
    except BrokenPipeError:
        return
    finally:
        try:
            child_stdin.close()
        except Exception:
            pass


def main(argv: Iterable[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Filter non-JSON stdout from an MCP stdio server")
    parser.add_argument("command", nargs=argparse.REMAINDER, help="Command to run, optionally after --")
    args = parser.parse_args(list(argv) if argv is not None else None)
    command: List[str] = list(args.command)
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("missing command to run")

    child = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
    )
    threads = [
        threading.Thread(target=_pump_stdout, args=(child.stdout,), daemon=True),
        threading.Thread(target=_pump_stream, args=(child.stderr, sys.stderr), daemon=True),
        threading.Thread(target=_pump_stdin, args=(child.stdin,), daemon=True),
    ]
    for thread in threads:
        thread.start()
    return child.wait()


if __name__ == "__main__":
    raise SystemExit(main())
