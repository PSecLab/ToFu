#!/usr/bin/env python3
"""Regenerate eval/configs/*.json from eval/state/prepared.jsonl.

The per-tool config files are derived data (prepare_targets.py writes them
alongside prepared.jsonl). If they are lost -- e.g. a fuzzed target deleted them,
item 91, 2026-09-18 -- but prepared.jsonl and the cloned eval/targets/ survive,
this rebuilds them WITHOUT re-cloning/re-installing/re-probing: fast, and needs
no venv. It uses the exact schema prepare_targets emits, pulling env-hint values
from the same static TARGET_ENV_HINTS. `_tool_description` is left "" because the
fuzzer re-fetches tool metadata over stdio at run time.

  python3 eval/regen_configs.py            # write any missing configs
  python3 eval/regen_configs.py --force    # overwrite existing too
"""
import argparse, importlib.util, json, os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "eval", "state")
PREPARED = os.path.join(STATE, "prepared.jsonl")
CFGDIR = os.path.join(ROOT, "eval", "configs")


def _load_env_hints():
    """Import TARGET_ENV_HINTS from prepare_targets without running its main()."""
    try:
        spec = importlib.util.spec_from_file_location(
            "prepare_targets", os.path.join(ROOT, "eval", "prepare_targets.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return getattr(mod, "TARGET_ENV_HINTS", {})
    except Exception as e:
        print(f"WARN: could not import TARGET_ENV_HINTS ({e}); using empty hints")
        return {}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--force", action="store_true", help="overwrite existing configs")
    a = ap.parse_args()
    os.makedirs(CFGDIR, exist_ok=True)
    hints_by = _load_env_hints()

    written = skipped = repos = 0
    seen = set()
    for line in open(PREPARED):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("status") != "ready":
            continue
        repo = r["repo"]
        if repo in seen:
            continue
        seen.add(repo); repos += 1
        hints = hints_by.get(repo, {})
        for tool in (r.get("tools") or []):
            cfg = {
                "_repo": repo, "_set": r.get("set"), "_lang": r.get("lang"),
                "_commit": r.get("commit"), "_stars": r.get("stars"),
                "command": r.get("command"), "args": r.get("args") or [],
                "cwd": r.get("cwd"),
                "python": r.get("python"), "python_entry": r.get("python_entry"),
                "target_tool": tool,
                "_tool_description": "",   # re-fetched over stdio at run time
                "override_rules": {}, "predefined_seeds": [],
                "env": hints,
            }
            fn = f"{repo.replace('/', '__')}__{tool}.json"
            path = os.path.join(CFGDIR, fn)
            if os.path.exists(path) and not a.force:
                skipped += 1
                continue
            with open(path, "w") as f:
                json.dump(cfg, f, indent=1)
            written += 1

    print(f"repos(ready): {repos}  configs written: {written}  kept: {skipped}")
    print(f"-> {CFGDIR}: {len([f for f in os.listdir(CFGDIR) if f.endswith('.json')])} total")


if __name__ == "__main__":
    main()
