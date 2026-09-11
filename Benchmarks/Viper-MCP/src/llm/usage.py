from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _to_int(value: Any) -> int:
    try:
        if value is None:
            return 0
        return int(value)
    except (TypeError, ValueError):
        return 0


def normalize_usage(
    *,
    input_tokens: Any = None,
    output_tokens: Any = None,
    total_tokens: Any = None,
    prompt_tokens: Any = None,
    completion_tokens: Any = None,
) -> Dict[str, int]:
    input_value = _to_int(input_tokens if input_tokens is not None else prompt_tokens)
    output_value = _to_int(output_tokens if output_tokens is not None else completion_tokens)
    total_value = _to_int(total_tokens)
    if total_value <= 0:
        total_value = input_value + output_value
    return {
        "input_tokens": input_value,
        "output_tokens": output_value,
        "total_tokens": total_value,
    }


def extract_openai_compatible_usage(response: Any) -> Dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return normalize_usage()
    return normalize_usage(
        prompt_tokens=getattr(usage, "prompt_tokens", None) if not isinstance(usage, dict) else usage.get("prompt_tokens"),
        completion_tokens=getattr(usage, "completion_tokens", None) if not isinstance(usage, dict) else usage.get("completion_tokens"),
        total_tokens=getattr(usage, "total_tokens", None) if not isinstance(usage, dict) else usage.get("total_tokens"),
    )


def extract_anthropic_usage(response: Any) -> Dict[str, int]:
    usage = getattr(response, "usage", None)
    if usage is None and isinstance(response, dict):
        usage = response.get("usage")
    if usage is None:
        return normalize_usage()
    return normalize_usage(
        input_tokens=getattr(usage, "input_tokens", None) if not isinstance(usage, dict) else usage.get("input_tokens"),
        output_tokens=getattr(usage, "output_tokens", None) if not isinstance(usage, dict) else usage.get("output_tokens"),
    )


def extract_langchain_usage(message: Any) -> Dict[str, int]:
    usage_metadata = getattr(message, "usage_metadata", None)
    if isinstance(usage_metadata, dict) and usage_metadata:
        return normalize_usage(
            input_tokens=usage_metadata.get("input_tokens"),
            output_tokens=usage_metadata.get("output_tokens"),
            total_tokens=usage_metadata.get("total_tokens"),
        )

    response_metadata = getattr(message, "response_metadata", None)
    if isinstance(response_metadata, dict):
        token_usage = response_metadata.get("token_usage")
        if isinstance(token_usage, dict) and token_usage:
            return normalize_usage(
                prompt_tokens=token_usage.get("prompt_tokens"),
                completion_tokens=token_usage.get("completion_tokens"),
                total_tokens=token_usage.get("total_tokens"),
            )

    return normalize_usage()


def append_usage_log(log_path: str | Path | None, record: Dict[str, Any]) -> None:
    if not log_path:
        return
    path = Path(log_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = dict(record)
    payload.setdefault("timestamp", utc_now())
    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(payload, ensure_ascii=False) + "\n")


def summarize_usage_log(log_path: str | Path | None) -> Dict[str, Any]:
    summary = {
        "request_count": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "total_tokens": 0,
        "by_role": {},
        "by_model": {},
    }
    if not log_path:
        return summary

    path = Path(log_path)
    if not path.exists():
        return summary

    by_role: Dict[str, Dict[str, int]] = defaultdict(lambda: {"request_count": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0})
    by_model: Dict[str, Dict[str, int]] = defaultdict(lambda: {"request_count": 0, "input_tokens": 0, "output_tokens": 0, "total_tokens": 0})

    for raw_line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        try:
            item = json.loads(line)
        except Exception:
            continue

        usage = normalize_usage(
            input_tokens=item.get("input_tokens"),
            output_tokens=item.get("output_tokens"),
            total_tokens=item.get("total_tokens"),
            prompt_tokens=item.get("prompt_tokens"),
            completion_tokens=item.get("completion_tokens"),
        )
        summary["request_count"] += 1
        summary["input_tokens"] += usage["input_tokens"]
        summary["output_tokens"] += usage["output_tokens"]
        summary["total_tokens"] += usage["total_tokens"]

        role = str(item.get("role") or "").strip()
        if role:
            bucket = by_role[role]
            bucket["request_count"] += 1
            bucket["input_tokens"] += usage["input_tokens"]
            bucket["output_tokens"] += usage["output_tokens"]
            bucket["total_tokens"] += usage["total_tokens"]

        model = str(item.get("model") or "").strip()
        if model:
            bucket = by_model[model]
            bucket["request_count"] += 1
            bucket["input_tokens"] += usage["input_tokens"]
            bucket["output_tokens"] += usage["output_tokens"]
            bucket["total_tokens"] += usage["total_tokens"]

    summary["by_role"] = dict(by_role)
    summary["by_model"] = dict(by_model)
    return summary
