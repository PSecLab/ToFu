# Benchmarks / baselines for ToFu evaluation

Pinned so the comparison is reproducible. Record these commit hashes in the
paper's experimental-setup subsection.

Cloned 2026-09-08.

| Dir | Source | Commit | License | Role |
|---|---|---|---|---|
| `Viper-MCP` | https://anonymous.4open.science/r/Viper-EA4D (downloaded manually) | n/a (anon artifact) | not stated | Closest competing system. CODE ONLY -- no dataset, no repo list, no CVE list. |
| `Cisco-MCP-Scanner` | github.com/cisco-ai-defense/mcp-scanner | 16e684d8bd8faa0f0bb15e04ba2d2089dff42196 | Apache-2.0 | PRIMARY BASELINE. Also used as a baseline by VIPER-MCP, so numbers are cross-comparable. |
| `MCPSafetyScanner` | github.com/johnhalloran321/mcpSafetyScanner | c3e83194bdf3b7f68ed02549ad2546e8fbaaf0ad | MPL-2.0 | SECOND BASELINE. Also used by VIPER-MCP. Stale (last upstream push 2025-04-10). |
| `MCPSecBench` | github.com/AIS2Lab/MCPSecBench | 7612c5a3e811dcf01f64e4f2bb324591a2feaaf4 | MIT | Attack benchmark, NOT a scanner. Withdrawn from ICLR 2026. Weak automated baseline -- harness is largely manual/GUI-driven per its own reviewers. |
| `MCPCorpus` | github.com/Snakinya/MCPCorpus | 295fe37cd972ea9aa1b48578b2d7bcc40a72ee12 | none stated | THE DATASET. 13,875 servers. Website/mcpso_servers_cleaned.json is the file to sample from. |

## Why these two baselines specifically

VIPER-MCP (the closest competing system) evaluates against exactly
MCPSafetyScanner and Cisco AI Defense MCP Scanner, and publishes this table
(its Table 2, on its own 130-vulnerable + 130-benign server benchmark):

| Approach | FPR | FNR |
|---|---|---|
| MCPSafetyScanner | 43.1% | 63.8% |
| Cisco AI Defense | 24.6% | 73.1% |
| VIPER-MCP | 0% | 7.7% |

Using the SAME two baselines makes ToFu's numbers directly comparable to a
published competitor's, which is much stronger than picking our own.

## Running notes

- Cisco MCP Scanner: `uv tool install --python 3.13 cisco-ai-mcp-scanner`.
  Has a stdio mode (`mcp-scanner stdio --stdio-command ...`) so it batches over
  a target list. Supports a LOCAL LLM -> no API key, no cost, less
  nondeterminism. Actively maintained (upstream pushed 2026-09-08).
- MCPSafetyScanner: Python, needs an OpenAI key. Stale; expect install fixes.
- Viper-MCP: needs a venv, CodeQL binary >= 2.16, AND an LLM API key
  (config.yaml defaults to gpt-5.4). Its config takes ONE server at a time
  (`mcp_server.repo_path`) and the batch evaluation scripts were explicitly
  REMOVED from the artifact -- so running it over N targets means writing our
  own loop that generates a config.yaml per target.
  Paper reports ~926s (~15 min) mean per server, Phase II (LLM) dominating.

## Caveats to remember when comparing

- VIPER-MCP covers ONLY 3 taint-style classes: command injection (CWE-78),
  SSRF (CWE-918), path traversal (CWE-22). It explicitly does NOT cover logic
  vulnerabilities, authentication bypasses, or information disclosure. That is
  ToFu's real differentiation -- not "scale", but class coverage derived from
  documented argument semantics.
- VIPER-MCP's 0% FPR is measured on a benchmark it built, 52% of which (67 of
  130) are its own prior discoveries. Self-benchmarking bias; unverifiable
  since the benign 130 are unnamed and every CVE ID in the paper is printed as
  the placeholder "CVE-2026-XXXXX".
- Its 39,884-repo corpus is NOT released and NOT reconstructible (no crawl
  keywords, no dates, no filter code). Confirmed: the artifact we downloaded
  contains code only.
- RECONSTRUCTIBLE OPPORTUNITY: its *other* 63 servers come from public CVEs
  (NVD + GitHub Security Advisories, keywords "MCP", "Model Context Protocol",
  "mcp server", "modelcontextprotocol"; 146 candidates -> 63 kept). That
  portion we CAN rebuild independently as a ground-truth set.
