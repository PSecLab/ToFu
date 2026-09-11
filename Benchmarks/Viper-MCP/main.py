#!/usr/bin/env python3
"""
Viper-MCP main entry.
"""
import argparse
import asyncio
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from src.utils.config import Config
from src.pipeline.orchestrator import PipelineOrchestrator
from src.agent import create_agent_from_config
from src.fuzz.engine import FuzzEngine


def parse_args():
    parser = argparse.ArgumentParser(description="Viper-MCP: agent-mediated vulnerability discovery for MCP servers")
    parser.add_argument(
        "config",
        nargs="?",
        default="config.yaml",
        help="Path to config.yaml (default: config.yaml)",
    )
    parser.add_argument(
        "--skip-codeql",
        action="store_true",
        help="Skip CodeQL scan and SARIF extraction; use existing output",
    )
    parser.add_argument(
        "--skip-fuzz",
        action="store_true",
        help="Skip fuzzing; only run CodeQL and agent connection test",
    )
    parser.add_argument(
        "--test-agent",
        action="store_true",
        help="Only test agent connection with one prompt, then exit",
    )
    parser.add_argument(
        "--test-agent-init",
        action="store_true",
        help="Only initialize the MCP agent and list tool names, then exit",
    )
    return parser.parse_args()


async def main() -> int:
    args = parse_args()
    config_path = args.config
    config = Config(config_path)

    if not args.skip_codeql:
        orch = PipelineOrchestrator(config)
        orch.run()
    else:
        print("Skipping CodeQL scan (--skip-codeql)")

    if args.test_agent_init:
        agent = create_agent_from_config(config)
        await agent.initialize()
        print("Agent initialized. Tools:", [tool["name"] for tool in agent.tools_cache])
        await agent.close()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

    if args.test_agent:
        agent = create_agent_from_config(config)
        await agent.initialize()
        result = await agent.execute_prompt("Hello, can you list available tools?")
        print("Agent test result:", result)
        await agent.close()
        sys.stdout.flush()
        sys.stderr.flush()
        os._exit(0)

    if not args.skip_fuzz:
        fuzz_engine = FuzzEngine(config)
        ok = await fuzz_engine.run()
        if not ok:
            print("Fuzzing failed. Check logs for initialization or runtime errors.", file=sys.stderr)
            return 1
        print("Fuzzing completed. Check output directory for results and anomalies.")
    else:
        print("Skipping fuzzing (--skip-fuzz)")
    return 0


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
