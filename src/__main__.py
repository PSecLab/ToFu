import argparse
import json
import os
import sys
import logging
from .fuzzer import MCPDifferentialFuzzer
from .sanitizers import SECURITY_PROFILES
from .config import FuzzerConfig

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("src.cli")

def parse_args():
    parser = argparse.ArgumentParser(description="MCP Fuzzer Command Line Interface")
    parser.add_argument("--command", help="Command to run the target MCP server (e.g. node, python)")
    parser.add_argument("--args", nargs="*", help="Arguments for the MCP server command")
    parser.add_argument("--tool", help="Name of the MCP tool to target for fuzzing")
    parser.add_argument("--time", type=int, default=20, help="Fuzzing iteration duration in seconds")
    parser.add_argument("--profile", choices=["base", "controlled_rw", "read_only"], help="Predefined security profile to apply")
    parser.add_argument("--config", help="Path to JSON target configuration file")
    parser.add_argument("--api-key", help="Ollama / Cloud LLM API Key (optional)")
    parser.add_argument("--test-input", help="Arguments JSON string to run a single test execution instead of fuzzing")
    parser.add_argument("--corpus-dir", default=None,
                        help="Corpus directory for this run. MUST be unique per concurrent run: "
                             "the fuzzer wipes this directory when it starts a tool, so runs sharing "
                             "the default ./fuzz_corpus delete each other's corpora.")
    parser.add_argument("--metrics-dir", default=None,
                        help="Metrics/coverage output directory for this run (default: metrics).")
    return parser.parse_args()

def main():
    args = parse_args()
    
    # Defaults
    command = None
    cmd_args = []
    target_tool = None
    override_rules = {}
    predefined_seeds = []
    file_backed_params = {}
    target_cwd = None
    target_env = None
    
    # 1. Load from config file if specified
    if args.config:
        if not os.path.exists(args.config):
            logger.error(f"Configuration file not found: {args.config}")
            sys.exit(1)
        try:
            with open(args.config, "r") as f:
                config_data = json.load(f)
            command = config_data.get("command")
            cmd_args = config_data.get("args", [])
            target_tool = config_data.get("target_tool")
            override_rules = config_data.get("override_rules", {})
            predefined_seeds = config_data.get("predefined_seeds", [])
            # FILE-BACKED PARAMETERS. Without these, a tool that takes a file
            # path receives the literal string the mapper produced ("test") and
            # answers "File not found" on EVERY input -- so it never executes,
            # no sanitizer can fire, and the run reports a healthy 0 findings.
            # Measured 2026-09-10 on ArchimedesCrypto/excel-reader-mcp.
            # __main__ previously never read this key at all, so the whole
            # file-backed path (src/predefined_seeds/, FuzzFileManager, the
            # "predefined_seed:<name>" protocol) was dead in the eval harness
            # even though targets/fuzz_*.py used it. That is why the paper's
            # binary-seed claim was never observed working.
            file_backed_params = config_data.get("file_backed_params", {}) or {}
            # BUG 21: prepare_targets.py has always written "cwd", and nothing
            # ever read it. Targets therefore ran from ToFu's repo root.
            target_cwd = config_data.get("cwd") or None
            # Per-target env (placeholder credentials for env-gated servers).
            target_env = config_data.get("env") or None
            logger.info(f"Loaded configuration from {args.config}")
        except Exception as e:
            logger.error(f"Failed to parse config file: {e}")
            sys.exit(1)

    # 2. CLI Arguments take precedence
    if args.command:
        command = args.command
    if args.args is not None:
        cmd_args = args.args
    if args.tool:
        target_tool = args.tool
        
    # Validation
    if not command:
        logger.error("Error: --command (or command in --config) is required.")
        sys.exit(1)
    if not target_tool:
        logger.error("Error: --tool (or target_tool in --config) is required.")
        sys.exit(1)
        
    # 3. Apply predefined profile if specified
    if args.profile:
        logger.info(f"Applying predefined security profile: {args.profile}")
        profile_rules = SECURITY_PROFILES.get(args.profile, {})
        # Merge profile rules (override_rules in config/CLI takes precedence over default profiles)
        merged_rules = profile_rules.copy()
        merged_rules.update(override_rules)
        override_rules = merged_rules

    # API key resolution
    # No credential default. A hardcoded key here was committed to git history;
    # local Ollama ignores the value, so "ollama" is the right local placeholder.
    _base = os.environ.get("TOFU_LLM_BASE_URL", "")
    api_key = (args.api_key
               or (os.environ.get("OPENAI_API_KEY") if "openai.com" in _base else None)
               or os.environ.get("OLLAMA_CLOUD_API_KEY"))
    if not api_key:
        base = os.environ.get("TOFU_LLM_BASE_URL", "")
        if "localhost" in base or "127.0.0.1" in base:
            api_key = "ollama"
        elif os.environ.get("TOFU_NO_LLM", "").strip().lower() not in ("", "0", "false", "no"):
            api_key = "unused"          # TOFU_NO_LLM: no LLM call is ever made
        else:
            logger.error("No LLM credential. Set OLLAMA_CLOUD_API_KEY, or point "
                         "TOFU_LLM_BASE_URL at a local Ollama daemon.")
            sys.exit(1)

    fuzzer_config = FuzzerConfig()
    if args.metrics_dir:
        fuzzer_config.metrics_dir = args.metrics_dir
    if target_env:
        fuzzer_config.target_env = dict(target_env)
        # PythonRunner imports the target IN-PROCESS, so its env must already
        # be in os.environ before the import; JSRunner gets it via custom_env.
        for k, v in target_env.items():
            os.environ[str(k)] = str(v)
    if target_cwd:
        fuzzer_config.target_cwd = target_cwd
        # The path-traversal oracle judges escapes relative to this.
        if not fuzzer_config.allowed_workspace_dir:
            fuzzer_config.allowed_workspace_dir = target_cwd

    fuzzer = MCPDifferentialFuzzer(
        command=command,
        args=cmd_args,
        target_tool=target_tool,
        api_key=api_key,
        corpus_dir=args.corpus_dir or "./fuzz_corpus",
        override_rules=override_rules,
        predefined_seeds=predefined_seeds,
        file_backed_params=file_backed_params,
        config=fuzzer_config
    )
    
    if args.test_input:
        try:
            inputs = json.loads(args.test_input)
            if not isinstance(inputs, dict):
                raise ValueError("Test input must be a JSON object")
        except Exception as e:
            logger.error(f"Error: Invalid test input JSON format: {e}")
            sys.exit(1)
        fuzzer.run_single(inputs)
    else:
        logger.info(f"Starting fuzzer on tool '{target_tool}' for {args.time} seconds...")
        fuzzer.run(time_per_iteration=args.time)

if __name__ == "__main__":
    main()
