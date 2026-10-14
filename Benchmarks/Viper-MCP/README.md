# Viper-MCP

Viper-MCP is an agent-mediated vulnerability discovery framework for MCP servers. It combines static taint analysis, prompt evolution, and runtime exploit validation to test whether natural-language interaction with an LLM agent can drive attacker-controlled input into dangerous MCP tool sinks.

## Included Components

This package contains only the source code required to run Viper-MCP:

- `main.py`: entry point
- `src/`: core implementation
- `ql/`: Viper-MCP CodeQL rules
- `codeql/`: SARIF conversion helper
- `instrumentation/`: Python and JavaScript runtime hooks
- `script/mcp_stdio_guard.py`: stdio wrapper for noisy MCP servers
- `script/python_entrypoint.py`: helper for `module:function` Python entry points
- `config.yaml`: sanitized example runtime configuration

## Not Included

The following categories were intentionally removed from this submission copy:

- vulnerable or benign MCP datasets
- experimental result directories
- batch evaluation scripts
- paper sources and appendices
- environment files and private API keys
- local virtual environments and cached artifacts

## Supported Languages

The current implementation targets:

- Python MCP servers
- JavaScript MCP servers
- TypeScript MCP servers

## Target Vulnerability Classes

Viper-MCP focuses on taint-style vulnerabilities in MCP servers, especially:

- command injection
- path traversal / file-access abuse
- SSRF-style outbound request manipulation

## Installation

```bash
cd Viper-MCP-submission
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
```

If you use CodeQL and LLM-backed prompt generation, configure the corresponding binaries and API keys in `config.yaml` or via environment variables.

## Configuration

The default `config.yaml` is a placeholder template. At minimum you should update:

- `mcp_server.repo_path`
- `mcp_server.startup_command`
- `llm.prompt_generator.*`
- `llm.agent.*`
- `codeql.codeql_binary_path`

Example MCP section:

```yaml
mcp_server:
  repo_path: "/abs/path/to/target-repo"
  transport: "stdio"
  startup_command: ["python", "server.py"]
```

Example LLM section:

```yaml
llm:
  prompt_generator:
    provider: "openai"
    model: "gpt-5.4"
    api_key: "YOUR_API_KEY"
    base_url: "YOUR_BASE_URL"
  agent:
    provider: "openai"
    model: "gpt-5.4"
    api_key: "YOUR_API_KEY"
    base_url: "YOUR_BASE_URL"
```

## Running Viper-MCP

### Full run

```bash
cd Viper-MCP-submission
.venv/bin/python main.py config.yaml
```

### Reuse existing static artifacts

```bash
.venv/bin/python main.py config.yaml --skip-codeql
```

### Test MCP agent initialization only

```bash
.venv/bin/python main.py config.yaml --skip-codeql --test-agent-init
```

### Run a one-prompt smoke test

```bash
.venv/bin/python main.py config.yaml --skip-codeql --test-agent
```

## Typical Outputs

Viper-MCP writes outputs under `results/` and `output/`, including:

- CodeQL SARIF reports
- anchor-enriched vulnerability reports
- MCP interaction traces
- runtime oracle evidence
- round-level fuzzing results

## Notes

- Viper-MCP is intended for controlled local evaluation of MCP servers.
- Many real-world servers require external services, credentials, or local runtimes. Successful end-to-end execution depends on whether those dependencies are satisfied in the test environment.
- The current fuzzing core uses the same five prompt families described in the paper appendix: seed generation, structure mutation, parameter mutation, mutation scheduling, and exploit validation.
