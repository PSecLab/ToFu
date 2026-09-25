#!/usr/bin/env python3
"""BASELINE #4: ToolFuzz (eth-sri) over ToFu's prepared MCP servers.

ToolFuzz fuzzes langchain agent TOOLS (RuntimeErrorTester: crash-inducing
prompts; CorrectnessTester: wrong-output prompts). Our targets are MCP servers,
so we bridge each server's tools into langchain via langchain_mcp_adapters and
hand each tool to ToolFuzz.

EXECUTES the tools -> run on the VM/sandbox only, never a bare host.
Resumable: eval/state/toolfuzz_runs.jsonl; re-running skips (repo,tool) already
recorded ok (or final). Ctrl-C safe: the tool in flight is simply redone.

Cost control (2026-09-23; the first campaign spent ~150+ LLM calls per tool):
  * eval/toolfuzz_llm_guard.py -- one model everywhere, persistent response cache,
    cross-process real-call counter, global + per-tool hard caps.
  * budget-capped ToolFuzz testers (same method, bounded breadth; see
    CheapRuntimeErrorTester / CheapCorrectnessPromptGenerator). Knobs are env vars
    and are written into every index row so the configuration is reported.
  * --executable-only: only tools ToFu saw return success at least once (same
    server env); a tool that always errors gives neither tool a finding.

Findings: this runner stores ToolFuzz's raw results (JSON per tool) and the
per-tool counts using ToolFuzz's OWN criteria (src/eval/toolfuzz/utils/
tool_stats.py): runtime failure = TestFailureResult.successful_trigger;
correctness bug = prompt set with argument AND output inconsistency and the
judge's unexpected_agent_output <= 5. eval/score_toolfuzz.py classifies and
compares with ToFu. (The first campaign's n_runtime_fail read a nonexistent
field and n_correctness counted prompt sets tested -- neither was a finding.)

  run with ToolFuzz's own py3.10 venv (see eval/vm_bootstrap_toolfuzz.sh).
"""
import os, sys, json, asyncio, argparse, time, traceback, signal, fcntl

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLFUZZ = os.path.join(ROOT, "Benchmarks", "ToolFuzz")
sys.path.insert(0, os.path.join(ROOT, "eval"))
import toolfuzz_llm_guard as guard  # noqa: E402  (before ToolFuzz builds any ChatOpenAI)

# ToolFuzz imports `src.toolfuzz...` / `src.eval...`; its root must win over
# ToFu's own top-level `src/`. Put it first and chdir there.
sys.path.insert(0, TOOLFUZZ)
os.chdir(TOOLFUZZ)

PREPARED = os.path.join(ROOT, "eval", "state", "prepared.jsonl")
OUT      = os.environ.get("TOOLFUZZ_OUT", os.path.join(ROOT, "eval", "toolfuzz_runs"))
INDEX    = os.environ.get("TOOLFUZZ_INDEX", os.path.join(ROOT, "eval", "state", "toolfuzz_runs.jsonl"))
TOFU_IDX = os.path.join(ROOT, "eval", "state", "runs.gpt41-corpus.jsonl")

# budget knobs (recorded in every row)
RT_MAX_EXAMPLES = int(os.environ.get("TOOLFUZZ_RT_MAX_EXAMPLES", "3"))
RT_MAX_PROMPTS  = int(os.environ.get("TOOLFUZZ_RT_MAX_PROMPTS", "2"))
CT_SETS         = int(os.environ.get("TOOLFUZZ_CT_SETS", "2"))
CT_MAX_PROMPTS  = int(os.environ.get("TOOLFUZZ_CT_MAX_PROMPTS", "4"))

# never hand the harness's secrets / terminal to third-party servers
SCRUB_ENV = ("OPENAI_", "ANTHROPIC_", "TOFU_", "TOOLFUZZ_", "CISCO_LLM", "TMUX")


def log(m): print(f"[{time.strftime('%H:%M:%S')}] {m}", flush=True)


def append_index(rec):
    with open(INDEX, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        f.write(json.dumps(rec) + "\n")
        f.flush()
        fcntl.flock(f, fcntl.LOCK_UN)


def load_done():
    done = set()
    if os.path.exists(INDEX):
        for l in open(INDEX):
            try:
                d = json.loads(l)
                # ok rows and final rows (timeout / per-tool cap) are done; a
                # harness ERR row is retried on the next launch.
                if d.get("ok") or d.get("final"): done.add((d["repo"], d["tool"]))
            except Exception: pass
    return done


def load_list(path):
    if not path: return None
    if not os.path.isabs(path):        # we chdir'd into ToolFuzz; paths are repo-relative
        path = os.path.join(ROOT, path)
    txt = open(path).read().replace("\n", ",")
    return {x.strip().lower() for x in txt.split(",") if x.strip()}


def executable_tools():
    """(repo_lower, tool) pairs where ToFu observed >=1 successful execution."""
    ex = set()
    if not os.path.exists(TOFU_IDX): return None
    for l in open(TOFU_IDX):
        try: r = json.loads(l)
        except Exception: continue
        if r.get("ok") and (r.get("exec_success_rate") or 0) > 0:
            ex.add(((r.get("repo") or "").lower(), r.get("tool")))
    return ex


# Filesystem sandbox (CLAUDE.md: every fuzzer runs under bwrap). ToolFuzz drives
# third-party tools with LLM-chosen arguments; on 2026-09-24 a fuzzed
# newtype-01/obsidian-mcp path escaped its scratch dir and wiped the harness, and
# that repo is in the head-to-head set. Same policy as run_eval._sandbox_cmd:
# whole filesystem read-only, private /tmp, only the server's scratch dir and the
# target's own directory writable, HOME inside scratch.
SANDBOX = os.environ.get("TOOLFUZZ_SANDBOX", "bwrap").strip().lower()
SCRATCH_ROOT = os.path.join(os.environ.get("TOFU_SCRATCH_ROOT")
                            or os.path.join(os.path.expanduser("~"), ".tofu_scratch"), "toolfuzz")


def bwrap_args(writable):
    args = ["--die-with-parent", "--ro-bind", "/", "/", "--dev", "/dev",
            "--tmpfs", "/dev/shm", "--proc", "/proc", "--tmpfs", "/tmp"]
    for d in writable:
        if d and os.path.isdir(d):
            args += ["--bind", d, d]
    # hide the harness's secrets from targets without touching the real file
    # (moving .env aside would break a campaign sharing this checkout)
    envf = os.path.join(ROOT, ".env")
    if os.path.exists(envf):
        args += ["--ro-bind", "/dev/null", envf]
    return args


def sandbox_preflight():
    """Refuse to run rather than run unsandboxed (or count sandbox failures as
    tool failures -- item 14 follow-up: an AppArmor userns restriction made every
    bwrap start fail with 'setting up uid map: Permission denied')."""
    import shutil, subprocess
    if SANDBOX == "none":
        log("WARNING: TOOLFUZZ_SANDBOX=none -- targets run UNSANDBOXED"); return
    if SANDBOX != "bwrap":
        log(f"unknown TOOLFUZZ_SANDBOX={SANDBOX!r}"); sys.exit(4)
    if not shutil.which("bwrap"):
        log("bwrap not installed; refusing to run targets unsandboxed"); sys.exit(4)
    probe = os.path.join(SCRATCH_ROOT, ".probe")
    os.makedirs(probe, exist_ok=True)
    r = subprocess.run(["bwrap"] + bwrap_args([probe]) +
                       ["--", "sh", "-c", f"touch {probe}/ok && ! touch /etc/.tf_probe 2>/dev/null"],
                       capture_output=True, text=True, timeout=30)
    if r.returncode != 0 or not os.path.exists(os.path.join(probe, "ok")):
        log(f"bwrap preflight failed: {(r.stderr or r.stdout).strip()[:200]}"); sys.exit(4)
    log("bwrap preflight ok (scratch writable, / read-only)")


def server_cfg(t, slug):
    env = {k: v for k, v in os.environ.items() if not k.startswith(SCRUB_ENV)}
    env.update(t.get("env") or {})
    cmd, args = t["command"], list(t.get("args") or [])
    if SANDBOX == "bwrap":
        scratch = os.path.join(SCRATCH_ROOT, slug)
        home = os.path.join(scratch, "home")
        os.makedirs(home, exist_ok=True)
        env["HOME"] = home
        env["TMUX_TMPDIR"] = scratch
        for k in ("XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME"):
            env.pop(k, None)
        args = bwrap_args([scratch, t.get("cwd")]) + ["--", cmd] + args
        cmd = "bwrap"
    return {"command": cmd, "args": args, "transport": "stdio", "cwd": t.get("cwd"), "env": env}


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
    # ToolFuzz's sanity-check prompt reads the function name ("invoke X exactly
    # like: <func name>(args)"); without this the agent was told "_sync(...)".
    _sync.__name__ = _sync.__qualname__ = tool.name
    return StructuredTool(name=tool.name, description=tool.description or tool.name,
                          args_schema=tool.args_schema, func=_sync, coroutine=_async,
                          metadata=getattr(tool, "metadata", None), response_format="content")


async def load_tools(name, t):
    from langchain_mcp_adapters.client import MultiServerMCPClient
    client = MultiServerMCPClient({name: server_cfg(t, name)})
    return [make_sync(x) for x in await client.get_tools()]


def cheap_classes():
    """Budget-capped versions of ToolFuzz's testers. Same algorithm; only the
    breadth is bounded:
      runtime:     at most RT_MAX_EXAMPLES failing argument sets are tried per
                   exception type (the unused upstream `bad_examples_per_param`),
                   and the first RT_MAX_PROMPTS generated prompts are run each.
      correctness: CT_SETS prompt sets (upstream prompt_set_iters), each capped at
                   CT_MAX_PROMPTS paraphrases (>=2 keeps the consistency oracle
                   meaningful; <=4 also skips the humanize call)."""
    from src.toolfuzz.runtime.runtime_fuzzer import RuntimeErrorTester
    from src.toolfuzz.runtime.prompt_generation.prompt_generator import RuntimeFailurePromptGeneration
    from src.toolfuzz.correctness import correctness_fuzzer as cf
    from src.toolfuzz.correctness.prompt_generation.prompt_generator import CorrectnessPromptGenerator

    class CheapRuntimeErrorTester(RuntimeErrorTester):
        def test(self):
            pg = RuntimeFailurePromptGeneration(self.tool_extractor)
            bad_arguments_w_exception = self.fuzzer.fuzz()      # direct calls, no LLM
            caught_exceptions = set()
            for exception, bad_arguments in bad_arguments_w_exception.items():
                for i in range(min(len(bad_arguments), RT_MAX_EXAMPLES)):
                    if exception in caught_exceptions:
                        break
                    bad_arg_examples = bad_arguments[i]
                    if not self.sanity_check(self.agent, bad_arg_examples):
                        continue
                    for prompt in pg.generate_prompt(bad_arg_examples)[:RT_MAX_PROMPTS]:
                        thrown, res = self.run_test(self.agent, prompt, exception,
                                                    self.tool_extractor.get_tool_name(),
                                                    bad_arg_examples, self.agent.get_name())
                        self.test_results.append(res)
                        if thrown:
                            caught_exceptions.add(thrown)

        def run_test(self, runnable, prompt, expected_exception, tool_name, bad_args, agent_type):
            """Upstream run_test with one fix: it builds TestFailureResult with
            invocation_params=agent_result.tool_args, which is None when the agent
            never called the tool (or non-str) -> pydantic ValidationError -> its
            own `except Exception` recorded THAT as successful_trigger=True (2,163
            of 6,594 "failures" in the first campaign were this artifact).
            Semantics otherwise unchanged: an exception escaping the agent is a
            trigger; else successful_trigger = agent_result.is_raised_exception."""
            from src.toolfuzz.dataclasses import TestFailureResult as TFR
            try:
                agent_result = runnable(prompt)
            except expected_exception as e:
                return expected_exception, TFR(tool=tool_name, expected_exception=str(expected_exception),
                                               exception=str(type(e)) + str(e), prompt=prompt,
                                               agent_type=agent_type, invocation_params="Invocation was interrupted",
                                               fuzzed_params=str(bad_args), successful_trigger=True,
                                               trace=json.dumps({"error": str(e)}))
            except Exception as e:
                return type(e), TFR(tool=tool_name, expected_exception=str(expected_exception),
                                    exception=str(type(e)) + str(e), prompt=prompt, agent_type=agent_type,
                                    invocation_params="Invocation was interrupted", fuzzed_params=str(bad_args),
                                    successful_trigger=True, trace=json.dumps({"error": str(e)}))
            finally:
                self.context_resetter.reset_context()
            exc = agent_result.exception
            if not isinstance(exc, str):
                exc = str(type(exc)) + str(exc)
            return expected_exception, TFR(tool=tool_name, expected_exception=str(expected_exception),
                                           exception=exc, prompt=prompt, agent_type=agent_type,
                                           invocation_params=str(agent_result.tool_args),
                                           fuzzed_params=str(bad_args),
                                           successful_trigger=bool(agent_result.is_raised_exception),
                                           trace=json.dumps(agent_result.trace, default=str))

    class CheapCorrectnessPromptGenerator(CorrectnessPromptGenerator):
        def to_prompts(self, template, prompt_args):
            return super().to_prompts(template, prompt_args)[:CT_MAX_PROMPTS]

    cf.CorrectnessPromptGenerator = CheapCorrectnessPromptGenerator
    return CheapRuntimeErrorTester, cf.CorrectnessTester


def correctness_bugs(results):
    """ToolFuzz's own criterion (tool_stats.py): per individual run inside a
    prompt set with tool_arguments_inconsistency AND tool_output_inconsistency
    and unexpected_agent_output <= 5. A non-integer degree (judge parse failure)
    is not counted."""
    n = 0
    for s in results:
        if s.tool_arguments_inconsistency and s.tool_output_inconsistency:
            for r in s.individual_run_test_results:
                d = r.unexpected_agent_output
                if isinstance(d, int) and not isinstance(d, bool) and d <= 5:
                    n += 1
    return n


def fuzz_tool(tool, llm, iters, modes, base):
    from src.toolfuzz.agent_executors.langchain.react_new import ReactAgentNew
    RT, CT = cheap_classes()
    rec = {"tool": tool.name}
    agent = ReactAgentNew(tool, llm)
    if agent.agent is None:
        rec.update(ok=False, final=True, error="react agent build failed (tool schema unsupported)")
        return rec
    # ToolFuzz's save_test_results APPENDS to an existing file, so a retried tool
    # accumulated duplicate results. Start every attempt from clean files.
    for suf in (".runtime.json", ".runtime.html", ".correctness.json", ".correctness.html"):
        try: os.remove(base + suf)
        except FileNotFoundError: pass
    capped = False
    if "runtime" in modes:
        rt = RT(llm=llm, tool=tool, agent=agent, fuzzer_iters=iters)
        try:
            rt.test()
        except guard.LLMToolCapExceeded:
            capped = True
        rt.save(base + ".runtime")
        rec["n_runtime_tests"] = len(rt.test_results)
        rec["n_runtime_trigger"] = sum(1 for r in rt.test_results if r.successful_trigger)
    if "correctness" in modes and not capped:
        ct = CT(llm=llm, tool=tool, agent=agent, additional_context="", prompt_set_iters=CT_SETS)
        try:
            ct.test()
        except guard.LLMToolCapExceeded:
            capped = True
        ct.save(base + ".correctness")
        rec["n_correctness_sets"] = len(ct.results)
        rec["n_correctness_bug"] = correctness_bugs(ct.results)
    rec.update(ok=True, capped=capped)
    return rec


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--iters", type=int, default=int(os.environ.get("TOOLFUZZ_ITERS", "10")),
                    help="direct (no-LLM) fuzz invocations per tool")
    ap.add_argument("--modes", default="runtime,correctness")
    ap.add_argument("--only", default=None, help="substring filter on repo")
    ap.add_argument("--repos-file", default=None, help="comma/newline list of repos to run")
    ap.add_argument("--skip-repos-file", default=None, help="comma/newline list of repos to skip")
    ap.add_argument("--skip", default=os.environ.get("TOOLFUZZ_SKIP", ""),
                    help="comma-separated repo substrings to skip")
    ap.add_argument("--executable-only", action="store_true",
                    help="only tools ToFu saw succeed at least once")
    ap.add_argument("--max-tools", type=int, default=0, help="cap tools per repo (0=all)")
    ap.add_argument("--tools", default=None, help="comma list of tool names to run (debugging)")
    ap.add_argument("--shard", default="0/1", help="K/N: this process handles repos i%%N==K")
    ap.add_argument("--tool-timeout", type=int, default=int(os.environ.get("TOOLFUZZ_TOOL_TIMEOUT", "600")),
                    help="per-tool wall-clock cap (s)")
    a = ap.parse_args()
    modes = [m.strip() for m in a.modes.split(",") if m.strip()]
    k, n = (int(x) for x in a.shard.split("/"))

    if not os.environ.get("OPENAI_API_KEY"):
        log("OPENAI_API_KEY not set"); sys.exit(1)
    sandbox_preflight()
    guard.install()
    from langchain_openai import ChatOpenAI
    llm = ChatOpenAI(temperature=0)   # model forced by guard (TOOLFUZZ_MODEL)
    knobs = {"model": llm.model_name, "iters": a.iters, "rt_max_examples": RT_MAX_EXAMPLES,
             "rt_max_prompts": RT_MAX_PROMPTS, "ct_sets": CT_SETS, "ct_max_prompts": CT_MAX_PROMPTS,
             "max_calls_per_tool": guard.MAX_PER_TOOL, "sandbox": SANDBOX}

    ready = [t for t in (json.loads(l) for l in open(PREPARED)) if t.get("status") == "ready"]
    only = load_list(a.repos_file)
    if only is not None:
        ready = [t for t in ready if t["repo"].lower() in only]
    if a.only:
        ready = [t for t in ready if a.only.lower() in t["repo"].lower()]
    skip = load_list(a.skip_repos_file) or set()
    subs = [x.strip().lower() for x in a.skip.split(",") if x.strip()]
    ready = [t for t in ready if t["repo"].lower() not in skip
             and not any(s in t["repo"].lower() for s in subs)]
    ready.sort(key=lambda t: t["repo"].lower())
    ready = [t for i, t in enumerate(ready) if i % n == k]
    exe = executable_tools() if a.executable_only else None
    if a.executable_only and exe is None:
        log(f"--executable-only needs {TOFU_IDX}"); sys.exit(1)

    done = load_done()
    os.makedirs(OUT, exist_ok=True); os.makedirs(os.path.dirname(INDEX), exist_ok=True)
    log(f"shard {k}/{n} servers={len(ready)} knobs={knobs} llm_cap={guard.MAX_CALLS}")
    n_ok = n_err = 0

    for i, t in enumerate(ready, 1):
        repo = t["repo"]; slug = repo.replace("/", "__")
        log(f"({i}/{len(ready)}) {repo}")
        try:
            tools = asyncio.run(load_tools(slug, t))
        except Exception as e:
            if "bwrap" in str(e):
                log(f"ABORT: sandbox failure, not a target failure: {str(e)[:160]}"); sys.exit(4)
            log(f"    LOAD ERR {str(e)[:120]}")
            append_index({"repo": repo, "tool": "*", "ok": False, "error": f"load_tools: {str(e)[:200]}"})
            continue
        if exe is not None:
            tools = [x for x in tools if (repo.lower(), x.name) in exe]
        if a.tools:
            want = {x.strip() for x in a.tools.split(",") if x.strip()}
            tools = [x for x in tools if x.name in want]
        if a.max_tools: tools = tools[:a.max_tools]
        todo = [x for x in tools if (repo, x.name) not in done]
        log(f"    {len(tools)} tools, {len(tools) - len(todo)} done, {len(todo)} to run")
        outdir = os.path.join(OUT, slug); os.makedirs(outdir, exist_ok=True)
        for tool in todo:
            t0 = time.time()
            base = os.path.join(outdir, tool.name.replace("/", "_"))
            # BaseException on purpose: ToolFuzz's fuzz() wraps every tool call
            # in `except Exception`, which swallowed a plain TimeoutError.
            class ToolTimeout(BaseException): pass
            def _timeout(signum, frame): raise ToolTimeout(f"tool exceeded {a.tool_timeout}s")
            signal.signal(signal.SIGALRM, _timeout); signal.alarm(a.tool_timeout)
            guard.begin_tool()
            try:
                rec = fuzz_tool(tool, llm, a.iters, modes, base)
            except guard.LLMBudgetExceeded as e:
                signal.alarm(0)
                log(f"STOP: {e}. Resume after raising TOOLFUZZ_MAX_CALLS; {tool.name} will be redone.")
                sys.exit(3)
            except ToolTimeout as e:
                rec = {"tool": tool.name, "ok": False, "final": True, "error": str(e)}
            except Exception as e:
                rec = {"tool": tool.name, "ok": False, "error": str(e)[:200],
                       "trace": traceback.format_exc()[-400:]}
            finally:
                signal.alarm(0)
            rec.update(repo=repo, seconds=round(time.time() - t0, 1), knobs=knobs, **guard.tool_usage())
            append_index(rec)
            if rec.get("ok"): n_ok += 1
            else: n_err += 1
            flag = ("ok" + (" CAPPED" if rec.get("capped") else "")) if rec.get("ok") \
                else f"ERR {rec.get('error','')[:60]}"
            log(f"    [{n_ok}ok/{n_err}err] {tool.name:28s} {flag}  ({rec['seconds']}s, "
                f"{rec['llm_calls']} calls, rt_trig={rec.get('n_runtime_trigger','-')}, "
                f"ct_bug={rec.get('n_correctness_bug','-')})")
    log(f"DONE shard {k}/{n}. {n_ok} ok, {n_err} err. index -> {INDEX}")


if __name__ == "__main__":
    main()
