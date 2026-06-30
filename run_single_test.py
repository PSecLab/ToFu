#!/usr/bin/env python3
import sys
import os
import json
import argparse
import logging

# Ensure framework packages are importable
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from mcp_fuzzer.runners import PythonRunner, JSRunner

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

def main():
    parser = argparse.ArgumentParser(
        description="Execute a single test run on an MCP tool using the runner system."
    )
    parser.add_argument(
        "--server",
        required=True,
        help="Path to the MCP server target script (e.g., fuzz_json_extractor.py or index.js)"
    )
    parser.add_argument(
        "--tool",
        required=True,
        help="Name of the target tool function to execute"
    )
    parser.add_argument(
        "--input",
        required=True,
        help="Arguments JSON string to pass to the tool (e.g., '{\"text\": \"1{{{{\"}' )"
    )

    args = parser.parse_args()

    # Parse inputs
    try:
        inputs = json.loads(args.input)
        if not isinstance(inputs, dict):
            raise ValueError("Input must be a JSON object / dictionary")
    except Exception as e:
        print(f"Error: Invalid JSON input format: {e}", file=sys.stderr)
        sys.exit(1)

    server_path = args.server
    if not os.path.exists(server_path):
        print(f"Error: Server script not found at '{server_path}'", file=sys.stderr)
        sys.exit(1)

    # Instantiate the correct runner
    is_js = server_path.endswith(".js")
    if is_js:
        runner = JSRunner(command="node", args=[server_path], target_tool=args.tool)
        print(f"[*] Starting JS Runner for tool '{args.tool}'...")
    else:
        runner = PythonRunner(command=sys.executable, args=[server_path], target_tool=args.tool)
        print(f"[*] Starting Python Runner for tool '{args.tool}'...")

    try:
        runner.start()
        print(f"[*] Executing target with arguments: {inputs}")
        result = runner.execute(inputs)
        
        # Display execution output
        print("\n" + "="*20 + " RESULTS " + "="*20)
        print(f"Status   : {'SUCCESS' if result.success else 'FAILED'}")
        if result.success:
            print(f"Output   : {result.result}")
        else:
            print(f"Error    : {result.error}")
        print(f"Coverage : {len(result.coverage)} block(s) hit")
        if result.coverage:
            print("Block Hits:")
            for cov in list(result.coverage)[:10]:
                print(f" - {cov}")
            if len(result.coverage) > 10:
                print(f" ... and {len(result.coverage) - 10} more blocks")
        print("="*49)
        
    except Exception as e:
        print(f"Error during runner execution: {e}", file=sys.stderr)
    finally:
        runner.stop()

if __name__ == "__main__":
    main()
