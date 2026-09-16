#!/usr/bin/env python3
"""BASELINE #4: ToolFuzz (eth-sri) over ToFu's prepared MCP servers.

ToolFuzz fuzzes langchain agent TOOLS (RuntimeErrorTester: crash-inducing
prompts; CorrectnessTester: wrong-output prompts). Our targets are MCP servers,
so we bridge each server's tools into langchain via langchain_mcp_adapters and
hand each tool to ToolFuzz.

EXECUTES the tools -> run on the VM/sandbox only, never a bare host.
Resumable: eval/state/toolfuzz_runs.jsonl; re-running skips (repo,tool) already
recorded. Ctrl-C safe.

  VIPER_PY-style: run with ToolFuzz's own py3.10 venv (see
  eval/vm_bootstrap_toolfuzz.sh). gpt-4.1, temperature 0, fuzzer_iters 10.
"""
import os, sys, json, asyncio, argparse, time, traceback, contextlib, signal

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLFUZZ = os.path.join(ROOT, "Benchmarks", "ToolFuzz")
# ToolFuzz imports `src.toolfuzz...` / `src.eval...`; its root must win over
# ToFu's own top-level `src/`. Put it first and chdir there.
sys.path.insert(0, TOOLFUZZ)
os.chdir(TOOLFUZZ)

PREPARED = os.path.join(ROOT, "eval", "state", "prepared.jsonl")
OUT      = os.path.join(ROOT, "eval", "toolfuzz_runs")
INDEX    = os.path.join(ROOT, "eval", "state", "toolfuzz_runs.jsonl")

def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)

def load_done():
    done = set()
    if os.path.exists(INDEX):
        for l in open(INDEX):
            try:
                d = json.loads(l)
                # Only a successful row counts as done; an ERR row is retried
                # on the next launch (the first VM run recorded 127 harness
                # errors that would otherwise have been frozen in as results).
                if d.get("ok"): done.add((d["repo"], d["tool"]))
            except Exception: pass
    return done

def server_cfg(t):
    # env: strip nothing here; the VM is the sandbox. Pass the target's cwd.
    return {"command": t["command"], "args": t.get("args") or [],
            "transport": "stdio", "cwd": t.get("cwd"),
            "env": {**os.environ, **(t.get("env") or {})}}

def _to_text(res):
    # adapters return str, a list of content blocks, or (content, artifact).
    # ToolFuzz string-concatenates tool output, so flatten to one str.
    if isinstance(res, tuple) and len(res) == 2:
        res = res[0]
    if isinstance(res, list):
        return "\n".join(x if isinstance(x, str) else json.dumps(x, default=str) for x in res)
    return res if isinstance(res, str) else json.dumps(res, default=str)

def make_sync(tool):
    """langchain_mcp_adapters builds coroutine-only StructuredTools; ToolFuzz
    (and its ReAct agent) call tools synchronously -> "StructuredTool does not
    support sync invocation." (113/131 tools in the first VM run). Re-wrap
    with a sync func that drives the coroutine on a private event loop."""
    from langchain_core.tools import StructuredTool, ToolException
    async_tool = tool
    async def _call(kwargs):
        # A server-side JSON-RPC error (mcp McpError, e.g. "-32600: File not
        # found") is not a ToolException, so it escaped ToolFuzz's
        # correctness.run_prompt (which catches ToolException only) and killed
        # the whole tool. Normalise every failure to ToolException: fuzz() keys
        # on the type, run_test/run_prompt/ToolNode all catch it.
        try:
            return _to_text(await async_tool.ainvoke(kwargs))
        except ToolException:
            raise
        except Exception as e:
            raise ToolException(f"{type(e).__name__}: {e}") from e
    def _sync(**kwargs):
        return asyncio.run(_call(kwargs))
    async def _async(**kwargs):
        return await _call(kwargs)
    return StructuredTool(name=tool.name, description=tool.description or tool.name,
                          args_schema=tool.args_schema, func=_sync, coroutine=_async,
                          metadata=getattr(tool, "metadata", None), response_format="content")

async def load_tools(name, t):
    from langchain_mcp_adapters.client import MultiServerMCPClient
    client = MultiServerMCPClient({name: server_cfg(t)})
    # get_tools() returns langchain BaseTools that manage their own stdio
    # session per invocation (adapters >=0.1); no persistent session needed.
    return [make_sync(x) for x in await client.get_tools()]

def fuzz_tool(tool, llm, iters, modes, base):
    from src.toolfuzz.agent_executors.langchain.react_new import ReactAgentNew
    rec = {"tool": tool.name}
    agent = ReactAgentNew(tool, llm)
    if agent.agent is None:
        rec["error"] = "react agent build failed (tool schema unsupported)"; rec["ok"] = False
        return rec
    if "runtime" in modes:
        from src.toolfuzz.runtime.runtime_fuzzer import RuntimeErrorTester
        rt = RuntimeErrorTester(llm=llm, tool=tool, agent=agent, fuzzer_iters=iters)
        rt.test(); rt.save(base + ".runtime")
        rec["n_runtime"] = len(rt.test_results)
        rec["n_runtime_fail"] = sum(1 for r in rt.test_results if getattr(r, "is_failure", None)
                                    or (isinstance(r, dict) and r.get("is_failure")))
    if "correctness" in modes:
        from src.toolfuzz.correctness.correctness_fuzzer import CorrectnessTester
        ct = CorrectnessTester(llm=llm, tool=tool, agent=agent,
                               additional_context="", prompt_set_iters=max(1, iters // 2))
        ct.test(); ct.save(base + ".correctness")
        rec["n_correctness"] = len(ct.results)
    rec["ok"] = True
    return rec

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=int(os.environ.get("TOOLFUZZ_ITERS", "10")))
    ap.add_argument("--modes", default="runtime,correctness")
    ap.add_argument("--model", default=os.environ.get("TOOLFUZZ_MODEL", "gpt-4.1"))
    ap.add_argument("--only", default=None, help="substring filter on repo")
    ap.add_argument("--skip", default=os.environ.get("TOOLFUZZ_SKIP", ""),
                    help="comma-separated repo substrings to skip (e.g. servers that block on OAuth)")
    ap.add_argument("--max-tools", type=int, default=0, help="cap tools per repo (0=all)")
    ap.add_argument("--tool-timeout", type=int, default=int(os.environ.get("TOOLFUZZ_TOOL_TIMEOUT","300")), help="per-tool wall-clock cap (s); a hung tool is recorded and skipped")
    a = ap.parse_args()
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]

    if not os.environ.get("OPENAI_API_KEY"):
        log("OPENAI_API_KEY not set"); sys.exit(1)
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(model=a.model, temperature=0)

    targets = [json.loads(l) for l in open(PREPARED)]
    ready = [t for t in targets if t.get("status") == "ready"]
    if a.only:
        ready = [t for t in ready if a.only.lower() in t["repo"].lower()]
    skips = [x.strip().lower() for x in a.skip.split(",") if x.strip()]
    if skips:
        dropped = [t["repo"] for t in ready if any(k in t["repo"].lower() for k in skips)]
        ready = [t for t in ready if t["repo"] not in dropped]
        for r in dropped: log(f"SKIP (--skip) {r}")
    done = load_done()
    os.makedirs(OUT, exist_ok=True); os.makedirs(os.path.dirname(INDEX), exist_ok=True)
    log(f"model={a.model} iters={a.iters} modes={modes} servers={len(ready)}")

    for i, t in enumerate(ready, 1):
        repo = t["repo"]; slug = repo.replace("/", "__")
        log(f"({i}/{len(ready)}) {repo}")
        try:
            tools = asyncio.run(load_tools(slug, t))
        except Exception as e:
            log(f"    LOAD ERR {str(e)[:120]}")
            with open(INDEX, "a") as f:
                f.write(json.dumps({"repo": repo, "tool": "*", "ok": False,
                                    "error": f"load_tools: {str(e)[:200]}"}) + "\n")
            continue
        if a.max_tools: tools = tools[:a.max_tools]
        outdir = os.path.join(OUT, slug); os.makedirs(outdir, exist_ok=True)
        for tool in tools:
            if (repo, tool.name) in done:
                continue
            t0 = time.time()
            base = os.path.join(outdir, tool.name.replace("/", "_"))
            # BaseException on purpose: ToolFuzz's fuzz() wraps every tool call
            # in `except Exception`, which swallowed the old TimeoutError -- a
            # google-cloud-mcp tool ran 355 s past a 300 s cap and was recorded
            # ok. A BaseException subclass cannot be caught by that clause.
            class ToolTimeout(BaseException): pass
            def _timeout(signum, frame): raise ToolTimeout(f"tool exceeded {a.tool_timeout}s")
            signal.signal(signal.SIGALRM, _timeout); signal.alarm(a.tool_timeout)
            try:
                rec = fuzz_tool(tool, llm, a.iters, modes, base)
            except ToolTimeout as e:
                rec = {"tool": tool.name, "ok": False, "error": str(e)}
            except Exception as e:
                rec = {"tool": tool.name, "ok": False, "error": str(e)[:200],
                       "trace": traceback.format_exc()[-400:]}
            finally:
                signal.alarm(0)
            rec.update(repo=repo, seconds=round(time.time() - t0, 1))
            with open(INDEX, "a") as f: f.write(json.dumps(rec) + "\n")
            flag = "ok" if rec.get("ok") else f"ERR {rec.get('error','')[:60]}"
            log(f"    {tool.name:28s} {flag}  ({rec['seconds']}s)")
    log(f"DONE. index -> {INDEX}  results -> {OUT}")

if __name__ == "__main__":
    main()
