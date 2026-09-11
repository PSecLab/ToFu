#!/usr/bin/env python3
"""Run a Python console-script style entry point.

Some package metadata declares scripts as ``module:function``. That form is not
valid for ``python -m`` directly, so the efficiency runner uses this tiny shim
to execute the callable without requiring editable installation.
"""

from __future__ import annotations

import importlib
import inspect
import sys


def main() -> int:
    if len(sys.argv) < 2 or ":" not in sys.argv[1]:
        print("usage: python_entrypoint.py module:function [args...]", file=sys.stderr)
        return 2
    target = sys.argv[1]
    module_name, function_name = target.split(":", 1)
    sys.argv = [target, *sys.argv[2:]]
    module = importlib.import_module(module_name)
    func = getattr(module, function_name)
    result = func()
    if inspect.isawaitable(result):
        import asyncio

        result = asyncio.run(result)
    return int(result or 0)


if __name__ == "__main__":
    raise SystemExit(main())
