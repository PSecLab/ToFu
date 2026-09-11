"""Executability survey. One representative tool per repo, driven with ToFu's
OWN deterministic seeds and the config's file_backed_params/predefined_seeds --
i.e. the same inputs the fuzzer sends when the LLM path falls back."""
import json, glob, os, sys, asyncio
sys.path.insert(0, "/Users/nazmulislamananto/pseclab/ToFu")
os.chdir("/Users/nazmulislamananto/pseclab/ToFu")
os.environ.setdefault("OLLAMA_CLOUD_API_KEY", "ollama")
from src.client import MCPInspector
from src.llm import LLMHandler
from src.file_manager import FuzzFileManager
from src.runners.js_runner import JSRunner
from src.runners.python_runner import PythonRunner

h = LLMHandler.__new__(LLMHandler)
by_repo = {}
for c in sorted(glob.glob("eval/configs/*.json")):
    by_repo.setdefault(json.load(open(c))["_repo"], []).append(c)

out = []
for repo, files in by_repo.items():
    # prefer a config that has file_backed_params, so the file path is exercised
    files = sorted(files, key=lambda f: not json.load(open(f)).get("file_backed_params"))
    cfg = json.load(open(files[0]))
    rec = {"repo": repo, "n_tools": len(files), "tool": cfg["target_tool"]}
    try:
        insp = MCPInspector(command=cfg["command"], args=cfg["args"])
        _n, _d, schema = asyncio.run(insp.fetch_tool_metadata(cfg["target_tool"]))
        seeds = h._local_fallback_mapping(schema, {}) or [{}]
        seeds.append({k: "test" for k in (schema.get("properties") or {})})
        fbp = cfg.get("file_backed_params") or {}
        pseeds = cfg.get("predefined_seeds") or []
        fm = FuzzFileManager(fbp)
        is_js = str(cfg["command"]).startswith("node") or any(str(a).endswith(".js") for a in cfg["args"])
        r = (JSRunner if is_js else PythonRunner)(
            command=cfg["command"], args=cfg["args"], target_tool=cfg["target_tool"])
        r.start()
        oks, errs, covs = 0, [], set()
        for sd in seeds:
            if not isinstance(sd, dict):
                continue
            sd = dict(sd)
            for k in fbp:
                if pseeds:
                    sd[k] = f"predefined_seed:{pseeds[0]}"
            sd, tmp = fm.prepare_file_params(sd)
            res = r.execute(sd)
            fm.clean_temp_files(tmp)
            covs.add(frozenset(res.coverage))
            if res.success:
                oks += 1
            elif res.error:
                errs.append(str(res.error)[:130])
        r.stop()
        rec.update(n_tried=len([s for s in seeds if isinstance(s, dict)]), n_ok=oks,
                   ok=(oks > 0), distinct_cov=len(covs), err=(errs[0] if errs else None),
                   file_backed=bool(fbp))
    except Exception as e:
        rec.update(n_tried=0, n_ok=0, ok=None, distinct_cov=0,
                   err=f"{type(e).__name__}: {e}"[:130], file_backed=False)
    out.append(rec)
    tag = "OK " if rec["ok"] else ("ERR" if rec["ok"] is False else "???")
    print(f"{tag} {repo:<42} tools={rec['n_tools']:<3} ok={rec['n_ok']}/{rec['n_tried']:<3} "
          f"cov_sets={rec['distinct_cov']:<3} {(rec.get('err') or '')[:70]}", flush=True)

json.dump({"_about": "ToFu deterministic seeds + config file_backed_params; one tool per repo",
           "_generated": "2026-09-10", "repos": out},
          open("eval/state/executability_survey.json", "w"), indent=2)
ok = sum(1 for r in out if r["ok"])
print(f"\nrepos executable={ok} not-executable={sum(1 for r in out if r['ok'] is False)}")
print(f"configs behind executable repos: {sum(r['n_tools'] for r in out if r['ok'])} / "
      f"{sum(r['n_tools'] for r in out)}")
