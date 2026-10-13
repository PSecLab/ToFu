# ToFu

**Security testing for the LLM–orchestrator–tool trust boundary.**

ToFu investigates a systems-security problem in agentic AI: model-generated tool arguments are untrusted inputs, and a tool's advertised behavior is not an enforcement mechanism. It uses tool metadata to guide security checks and fuzzing, helping identify cases where tool implementations fail to uphold their documented semantics.

[**Read the paper**](https://arxiv.org/abs/2610.13651) · [**Report an issue**](https://github.com/PSecLab/ToFu/issues)

## Overview

This repository contains the ToFu fuzzing implementation, security checks, target harnesses, and supporting tests. The workflow combines:

1. **Tool discovery:** obtain tool names, descriptions, and input schemas from MCP servers.
2. **Test preparation:** select semantic security checks and prepare seeds using tool metadata, explicit rules, or predefined inputs.
3. **Coverage-guided fuzzing:** mutate inputs with Atheris/libFuzzer and execute them through Python or JavaScript runners.
4. **Outcome analysis:** inspect outputs, errors, timing, and available execution observations for potential security violations.
5. **Reporting:** record candidate findings and coverage/execution metrics for investigation.

The check corpus covers issues such as path traversal, command and code injection, SSRF, unsafe deserialization, information exposure, resource exhaustion, and temporary-file handling. Target-specific checks also cover URL processing, HAR archives, and document conversion.

**Findings are candidates for validation.** Which checks are meaningful depends on the tool's intended contract, configuration, runner, and available observations. The profiles configure test oracles; they do not sandbox a target or enforce access control.

## Setup

Use a Linux environment with a Python version supported by your installed MCP SDK and Atheris packages. JavaScript targets additionally require Node.js and their own dependencies.

Run commands from the repository root:

```bash
git clone https://github.com/PSecLab/ToFu.git
cd ToFu

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m pip install pymongo
```

The current reporting module imports `pymongo`, although it is not listed in `requirements.txt`. Install the target server's dependencies separately. For Python targets, make those dependencies available in the same environment: the Python runner imports target code into the fuzzer process.

For LLM-assisted operation, supply your own API key:

```bash
export OLLAMA_CLOUD_API_KEY="<your-api-key>"
```

The current LLM handler defaults to `minimax-m3:cloud` at `https://ollama.com/v1`, through LangChain's OpenAI-compatible client. Model and endpoint settings are defined in [`src/llm.py`](src/llm.py).

## Run a campaign

The CLI is available through `python -m src`:

```bash
python -m src --help
```

Replace the server path and tool name below with a locally installed target:

```bash
python -m src \
  --command python \
  --args /absolute/path/to/server.py \
  --tool TOOL_NAME \
  --profile base \
  --time 60
```

For a JavaScript target, pass its built JavaScript entry point:

```bash
python -m src \
  --command node \
  --args /absolute/path/to/server.js \
  --tool TOOL_NAME \
  --profile base \
  --time 60
```

`--time` sets the libFuzzer time budget; discovery and setup add overhead. Omit `--profile` to use metadata-guided LLM sanitizer selection. Available profiles are `base`, `controlled_rw`, and `read_only`; their definitions are in [`src/sanitizers/__init__.py`](src/sanitizers/__init__.py).

### JSON configuration

For reusable settings, create a configuration such as `target.json`:

```json
{
  "command": "python",
  "args": ["/absolute/path/to/server.py"],
  "target_tool": "TOOL_NAME",
  "override_rules": {
    "check_unexpected_crash": {},
    "check_resource_exhaustion": {}
  },
  "predefined_seeds": [
    {"input": "example"}
  ]
}
```

Replace `input` with the target tool's actual argument names and provide appropriate seed values.

```bash
python -m src --config target.json --time 60
```

CLI command, arguments, and tool settings override the corresponding configuration values. Explicit `override_rules` take precedence over profile rules; mandatory base checks are also included. Predefined seeds bypass LLM seed generation.

### Execute one input

```bash
python -m src \
  --config target.json \
  --test-input '{"input": "example"}'
```

This mode prints execution status, output or error, and coverage information. It is an execution diagnostic; it does not run the campaign's full sanitizer/reporting pipeline.

## Target harnesses and results

[`targets/`](targets/) contains examples for document converters, URL inspectors, memory tools, terminal tools, and an intentionally vulnerable MCP server. Review each harness's paths, dependencies, selected tool, seeds, and rules before running it. Some examples contain environment-specific paths.

For custom integration, [`MCPDifferentialFuzzer`](src/fuzzer.py) accepts a configuration, explicit rules, predefined seeds, file-backed parameters, and injectable runners, metadata providers, and reporters. [`FuzzerConfig`](src/config.py) controls timing thresholds, instrumentation targets, workspace expectations, and metrics output.

By default:

- Candidate findings are logged to the console and submitted to MongoDB at `mongodb://localhost:27017/`, in `toolfuzz_db.vulnerabilities`. MongoDB reporting failures are logged.
- Metrics are written under `metrics/`; CSV export is enabled.
- libFuzzer artifacts use the `/tmp/` prefix.
- The default `fuzz_corpus/` directory is recreated during setup and removed during normal cleanup. Use it only for disposable campaign data.

A console-only reporter can be supplied through the Python API using `ConsoleVulnerabilityReporter` from [`src/reporters.py`](src/reporters.py).

## Repository guide

| Path | Purpose |
| --- | --- |
| [`src/__main__.py`](src/__main__.py) | CLI and JSON configuration handling |
| [`src/fuzzer.py`](src/fuzzer.py) | Campaign orchestration and security-check dispatch |
| [`src/llm.py`](src/llm.py) | Metadata-guided sanitizer selection and seed preparation |
| [`src/engine.py`](src/engine.py) | Atheris/libFuzzer integration |
| [`src/runners/`](src/runners/) | Python and JavaScript execution adapters |
| [`src/sanitizers/`](src/sanitizers/) | Generic, introspection, and target-specific checks |
| [`src/metrics.py`](src/metrics.py) | Coverage and execution timelines |
| [`targets/`](targets/) | Target-specific campaign harnesses |
| [`scripts/`](scripts/) | Parallel campaigns and introspection audits |
| [`tests/`](tests/) | Fuzzer, sanitizer, and metrics tests |
| [`third_party/`](third_party/) | Target and supporting third-party material |

## Current implementation notes

- Python and JavaScript use different execution and observation mechanisms. Do not assume that every sanitizer receives equivalent evidence on both runners.
- The current checkout does not include `src/seed_bank/`. Seed generation falls back to local schema-based inputs when that directory is absent.
- File-generation helpers in `src/llm.py` reference a `seed_generators` object that is not defined there. Treat this path as requiring additional integration; predefined JSON seeds are supported directly.
- Run target code in a disposable, externally isolated environment with test data. The fuzzer executes target functionality and is not itself a security boundary.

## Tests

Install the test runner and execute the suite from the repository root:

```bash
python -m pip install pytest
python -m pytest tests
```

## Paper and citation

**ToFu: Exploiting and Fuzzing the LLM-Orchestrator-Tool Trust Boundary**  
Md Nazmul Islam Ananto, Pierre Prevost-Avenel, Colin Smith, Kyungtae Kim, Taegyu Kim, and Arslan Khan.  
arXiv:2610.13651, 2026.

The paper describes the broader research and evaluation; the usage instructions above describe the code in this repository.

```bibtex
@misc{ananto2026tofu,
  title         = {ToFu: Exploiting and Fuzzing the {LLM}-Orchestrator-Tool Trust Boundary},
  author        = {Md Nazmul Islam Ananto and Pierre Prevost-Avenel and Colin Smith and Kyungtae Kim and Taegyu Kim and Arslan Khan},
  year          = {2026},
  eprint        = {2610.13651},
  archivePrefix = {arXiv},
  primaryClass  = {cs.CR},
  url           = {https://arxiv.org/abs/2610.13651}
}
```

