#!/usr/bin/env python3
"""LLM cost guard for the ToolFuzz baseline: persistent cache + call counter + hard caps.

Installed by eval/run_toolfuzz.py BEFORE any ToolFuzz module builds a ChatOpenAI:

  * one model for every ToolFuzz LLM role. ToolFuzz hardcodes gpt-4o in its prompt
    generators and correctness oracle while the agent uses whatever it is handed;
    we force TOOLFUZZ_MODEL everywhere (default gpt-4.1 = ToFu's arm), temperature
    as ToolFuzz sets it.
  * a persistent SQLite response cache (langchain global cache). A resumed or
    retried tool replays its LLM calls for free; identical prompts are paid once.
  * a cross-process call counter (fcntl-locked JSON) that counts REAL API calls only
    (cache hits never reach ChatOpenAI._generate), plus token usage.
  * TOOLFUZZ_MAX_CALLS: global hard stop -> LLMBudgetExceeded (BaseException, so no
    `except Exception` in ToolFuzz can swallow it); the run exits cleanly and resumes.
  * TOOLFUZZ_MAX_CALLS_PER_TOOL: per-tool safety net -> LLMToolCapExceeded; the
    runner keeps the tests completed so far and marks the tool capped.

Status from a shell:  python3 eval/toolfuzz_llm_guard.py status
"""
import os, sys, json, time, fcntl, hashlib, sqlite3, threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
STATE = os.path.join(ROOT, "eval", "state")
COUNTER = os.environ.get("TOOLFUZZ_CALLS_FILE", os.path.join(STATE, "toolfuzz_llm_calls.json"))
CACHE_DB = os.environ.get("TOOLFUZZ_CACHE_DB", os.path.join(STATE, "toolfuzz_llm_cache.sqlite"))


class LLMBudgetExceeded(BaseException):
    """Global call budget reached. BaseException on purpose (see module doc)."""


class LLMToolCapExceeded(BaseException):
    """Per-tool call cap reached."""


def _int_env(name, default):
    try:
        return int(os.environ.get(name, default))
    except ValueError:
        return int(default)


MAX_CALLS = _int_env("TOOLFUZZ_MAX_CALLS", "25000")
MAX_PER_TOOL = _int_env("TOOLFUZZ_MAX_CALLS_PER_TOOL", "80")

_tool_calls = 0          # real calls charged to the current tool (this process)
_tool_tokens = [0, 0]    # prompt, completion for the current tool


# ---------------------------------------------------------------- counter
def _locked_update(fn):
    """Read-modify-write the counter file under an exclusive lock. fn(d) -> result."""
    os.makedirs(os.path.dirname(COUNTER), exist_ok=True)
    with open(COUNTER + ".lock", "a+") as lk:
        fcntl.flock(lk, fcntl.LOCK_EX)
        try:
            try:
                with open(COUNTER) as f:
                    d = json.load(f)
            except (FileNotFoundError, ValueError):
                d = {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0,
                     "cache_hits": 0, "started": time.time()}
            out = fn(d)
            d["updated"] = time.time()
            tmp = COUNTER + ".tmp"
            with open(tmp, "w") as f:
                json.dump(d, f)
            os.replace(tmp, COUNTER)
            return out
        finally:
            fcntl.flock(lk, fcntl.LOCK_UN)


def begin_tool():
    global _tool_calls, _tool_tokens
    _tool_calls, _tool_tokens = 0, [0, 0]


def tool_usage():
    return {"llm_calls": _tool_calls, "prompt_tokens": _tool_tokens[0],
            "completion_tokens": _tool_tokens[1]}


def charge():
    """Called immediately before a real API call. Raises instead of spending."""
    global _tool_calls
    if MAX_PER_TOOL and _tool_calls >= MAX_PER_TOOL:
        raise LLMToolCapExceeded(f"per-tool LLM cap {MAX_PER_TOOL} reached")

    def _inc(d):
        if MAX_CALLS and d["calls"] >= MAX_CALLS:
            return False
        d["calls"] += 1
        return True

    if not _locked_update(_inc):
        raise LLMBudgetExceeded(f"global LLM budget {MAX_CALLS} reached")
    _tool_calls += 1


def add_usage(prompt_tokens, completion_tokens):
    _tool_tokens[0] += prompt_tokens or 0
    _tool_tokens[1] += completion_tokens or 0

    def _add(d):
        d["prompt_tokens"] += prompt_tokens or 0
        d["completion_tokens"] += completion_tokens or 0
    _locked_update(_add)


def _hit():
    def _h(d):
        d["cache_hits"] = d.get("cache_hits", 0) + 1
    _locked_update(_h)


def status():
    try:
        with open(COUNTER) as f:
            return json.load(f)
    except (FileNotFoundError, ValueError):
        return {}


# ---------------------------------------------------------------- cache
def _make_cache_cls():
    from langchain_core.caches import BaseCache
    from langchain_core.load import dumps, loads

    class SQLiteLLMCache(BaseCache):
        """Minimal persistent cache (no langchain_community dependency).
        Key = sha256(prompt, llm_string); llm_string carries model, temperature
        and bound tools, so different configurations never collide."""

        def __init__(self, path):
            self.path = path
            self._local = threading.local()
            os.makedirs(os.path.dirname(path), exist_ok=True)
            c = self._conn()
            c.execute("CREATE TABLE IF NOT EXISTS cache (k TEXT PRIMARY KEY, v TEXT)")
            c.commit()

        def _conn(self):
            c = getattr(self._local, "c", None)
            if c is None:
                c = sqlite3.connect(self.path, timeout=60)
                c.execute("PRAGMA journal_mode=WAL")
                self._local.c = c
            return c

        @staticmethod
        def _key(prompt, llm_string):
            return hashlib.sha256(f"{prompt}\x00{llm_string}".encode("utf-8", "replace")).hexdigest()

        def lookup(self, prompt, llm_string):
            row = self._conn().execute("SELECT v FROM cache WHERE k=?",
                                       (self._key(prompt, llm_string),)).fetchone()
            if row is None:
                return None
            try:
                gens = [loads(g) for g in json.loads(row[0])]
            except Exception:
                return None
            _hit()
            return gens

        def update(self, prompt, llm_string, return_val):
            try:
                v = json.dumps([dumps(g) for g in return_val])
            except Exception:
                return
            c = self._conn()
            c.execute("INSERT OR REPLACE INTO cache (k, v) VALUES (?, ?)",
                      (self._key(prompt, llm_string), v))
            c.commit()

        def clear(self, **kwargs):
            c = self._conn()
            c.execute("DELETE FROM cache")
            c.commit()

    return SQLiteLLMCache


# ---------------------------------------------------------------- install
_installed = False


def install():
    """Patch ChatOpenAI once per process. Idempotent."""
    global _installed
    if _installed:
        return
    from langchain_openai import ChatOpenAI
    from langchain_core.globals import set_llm_cache

    if os.environ.get("TOOLFUZZ_CACHE", "1") not in ("0", "false", "no"):
        set_llm_cache(_make_cache_cls()(CACHE_DB))

    forced = os.environ.get("TOOLFUZZ_MODEL", "gpt-4.1")
    seed = os.environ.get("TOOLFUZZ_SEED")
    orig_init = ChatOpenAI.__init__

    def _init(self, *a, **k):
        k["model"] = forced
        k.pop("model_name", None)
        k["streaming"] = False
        k.setdefault("max_retries", 6)
        # bound every single call's cost; ToolFuzz's generations are short JSON
        k.setdefault("max_tokens", int(os.environ.get("TOOLFUZZ_MAX_TOKENS", "2048")))
        if seed:
            k.setdefault("seed", int(seed))
        orig_init(self, *a, **k)

    ChatOpenAI.__init__ = _init

    orig_gen = ChatOpenAI._generate

    def _generate(self, *a, **k):
        charge()
        res = orig_gen(self, *a, **k)
        u = (getattr(res, "llm_output", None) or {}).get("token_usage") or {}
        add_usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
        return res

    ChatOpenAI._generate = _generate

    if hasattr(ChatOpenAI, "_agenerate"):
        orig_agen = ChatOpenAI._agenerate

        async def _agenerate(self, *a, **k):
            charge()
            res = await orig_agen(self, *a, **k)
            u = (getattr(res, "llm_output", None) or {}).get("token_usage") or {}
            add_usage(u.get("prompt_tokens", 0), u.get("completion_tokens", 0))
            return res

        ChatOpenAI._agenerate = _agenerate

    if hasattr(ChatOpenAI, "_stream"):
        orig_stream = ChatOpenAI._stream

        def _stream(self, *a, **k):
            charge()
            yield from orig_stream(self, *a, **k)

        ChatOpenAI._stream = _stream

    _installed = True


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "status":
        d = status()
        if not d:
            print("no calls recorded yet:", COUNTER)
            sys.exit(0)
        el = (d.get("updated", time.time()) - d.get("started", time.time())) / 3600
        print(f"real LLM calls : {d['calls']}  / cap {MAX_CALLS}")
        print(f"cache hits     : {d.get('cache_hits', 0)}")
        print(f"tokens in/out  : {d['prompt_tokens']:,} / {d['completion_tokens']:,}")
        print(f"elapsed        : {el:.2f} h   counter: {COUNTER}")
    else:
        print(__doc__)
