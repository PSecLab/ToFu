"""Credential scrubbing shared by both runners (bug 23, and its Python twin).

Untrusted MCP servers must never see ToFu's own credentials. JSRunner spawns a
child, so it scrubs the INHERITED environment before Popen. PythonRunner
imports the target IN-PROCESS, so the only environment it can scrub is
os.environ itself -- a target that reads /proc/self/environ reads the fuzzer's.
Measured 2026-09-15 (nazmul.todo item 86): tumf/mcp-text-editor served
/proc/self/environ 1,105 times in a 60s sandbox run and the tool output logged
on disk contained OPENAI_API_KEY 577 times.

Placeholder credentials that a target is MEANT to receive (eval/prepare_targets
TARGET_ENV_HINTS -> config "env") match the same name patterns, so callers pass
them as `keep` and they are re-applied after the scrub.
"""
import os
import sys
from typing import Dict, Iterable, Optional

SECRET_EXACT = {
    "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "OLLAMA_CLOUD_API_KEY",
    "GITHUB_TOKEN", "GH_TOKEN", "HF_TOKEN", "HUGGINGFACE_TOKEN", "HUGGING_FACE_HUB_TOKEN",
    "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN",
    "GOOGLE_APPLICATION_CREDENTIALS", "NPM_TOKEN", "PYPI_TOKEN", "TWINE_PASSWORD",
    "MCP_SCANNER_LLM_API_KEY", "MCP_SCANNER_API_KEY",
}
SECRET_SUFFIX = ("_API_KEY", "_SECRET", "_SECRET_KEY", "_TOKEN", "_PASSWORD", "_PASSWD", "_PRIVATE_KEY")


def is_secret_name(name: str) -> bool:
    nu = (name or "").upper()
    return nu in SECRET_EXACT or nu.endswith(SECRET_SUFFIX)


def scrub_secrets(env: dict) -> dict:
    """Remove credential-shaped keys from `env` IN PLACE and return it."""
    for k in list(env.keys()):
        if is_secret_name(k):
            env.pop(k, None)
    return env


def scrub_process_env(keep: Optional[Dict[str, str]] = None, log=None) -> Iterable[str]:
    """Scrub os.environ for an in-process target; re-apply `keep` afterwards.

    Returns the NAMES removed (never values). Safe to call after the LLM client
    exists: src/llm.LLMHandler reads the key once in __init__ and the openai
    client object holds it, so nothing in ToFu re-reads it from the environment.
    """
    keep = dict(keep or {})
    removed = sorted(k for k in os.environ if is_secret_name(k) and k not in keep)
    for k in removed:
        os.environ.pop(k, None)
    for k, v in keep.items():
        os.environ[str(k)] = str(v)
    if removed:
        (log or (lambda m: print(m, file=sys.stderr)))(
            f"[secrets] scrubbed {len(removed)} credential-shaped var(s) from the fuzzer "
            f"process before importing the target: {removed}")
    return removed
