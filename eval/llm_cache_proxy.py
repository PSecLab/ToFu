#!/usr/bin/env python3
"""Record/replay cache for OpenAI-compatible LLM traffic (used for Viper-MCP).

Viper talks to OpenAI through the official SDK (AsyncOpenAI + LangChain ChatOpenAI),
both of which honour a base URL. Point OPENAI_BASE_URL at this proxy and every
chat completion is keyed by a hash of its exact request body:

  hit   -> the recorded response is replayed byte-for-byte (no API call, no cost)
  miss  -> forwarded upstream; a 200 response is recorded, then returned

Streaming (``stream: true``) is supported: the raw SSE bytes are relayed to the
client as they arrive and recorded for replay. Only request bodies and responses
are stored -- never the Authorization header / API key.

Replay is exact only when the request is exact: an agent turn that embeds live tool
output (which can vary between runs) is a new request and goes upstream. The ledger
records hits/misses and upstream token usage per call, so every run's real spend is
measured rather than estimated.

  python3 eval/llm_cache_proxy.py --port 8791 --cache-dir eval/state/viper_llm_cache
  mode (--mode / LLM_CACHE_MODE): rw (default) | ro (miss -> 503, guarantees zero spend)
"""
import argparse, hashlib, http.client, json, os, sys, threading, time, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

VOLATILE = ("user", "stream_options")        # do not affect the answer; excluded from the key
HOP = {"host", "content-length", "accept-encoding", "connection", "keep-alive",
       "transfer-encoding", "proxy-connection"}
LOCK = threading.Lock()


def request_key(path, body):
    try:
        obj = json.loads(body)
        if isinstance(obj, dict):
            obj = {k: v for k, v in obj.items() if k not in VOLATILE}
        canon = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    except Exception:
        canon = body.decode("utf-8", "replace")
    return hashlib.sha256(f"{path}\n{canon}".encode()).hexdigest()


def usage_of(raw, stream):
    """(prompt_tokens, completion_tokens) from a JSON body or the last SSE usage chunk."""
    try:
        if not stream:
            u = json.loads(raw).get("usage") or {}
            return u.get("prompt_tokens"), u.get("completion_tokens")
        for line in reversed(raw.decode("utf-8", "replace").splitlines()):
            if line.startswith("data:") and '"usage"' in line:
                u = json.loads(line[5:].strip()).get("usage") or {}
                return u.get("prompt_tokens"), u.get("completion_tokens")
    except Exception:
        pass
    return None, None


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"            # close-delimited bodies: simplest correct streaming
    server_version = "llm-cache-proxy"

    def log_message(self, *a):                # keep stdout quiet; the ledger is the log
        pass

    def _ledger(self, **kv):
        kv["ts"] = round(time.time(), 3)
        with LOCK, open(os.path.join(self.server.cache_dir, "_ledger.jsonl"), "a") as f:
            f.write(json.dumps(kv) + "\n")

    def _upstream(self, method, body):
        u = self.server.upstream
        conn_cls = http.client.HTTPSConnection if u.scheme == "https" else http.client.HTTPConnection
        conn = conn_cls(u.netloc, timeout=600)
        base = u.path.rstrip("/") or "/v1"          # upstream given without /v1 -> assume it
        path = base + self.path[len(self.server.prefix):] if self.path.startswith(self.server.prefix) else self.path
        hdrs = {k: v for k, v in self.headers.items() if k.lower() not in HOP}
        hdrs["Accept-Encoding"] = "identity"
        if body is not None:
            hdrs["Content-Length"] = str(len(body))
        conn.request(method, path, body=body, headers=hdrs)
        return conn, conn.getresponse()

    def _send(self, status, ctype, raw):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self):                         # e.g. /v1/models: pass through, never cached
        conn, r = self._upstream("GET", None)
        raw = r.read(); conn.close()
        self._send(r.status, r.getheader("Content-Type", "application/json"), raw)

    def do_POST(self):
        body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
        key = request_key(self.path, body)
        try:
            req = json.loads(body)
        except Exception:
            req = {}
        stream = bool(isinstance(req, dict) and req.get("stream"))
        model = req.get("model") if isinstance(req, dict) else None
        path = os.path.join(self.server.cache_dir, key[:2], key + ".json")

        if os.path.exists(path):              # ---- replay
            rec = json.load(open(path))
            raw = rec["raw"].encode("latin-1")
            self._ledger(key=key, hit=True, model=model, stream=stream)
            self._send(200, rec.get("content_type", "application/json"), raw)
            return
        if self.server.mode == "ro":          # ---- replay-only: refuse to spend
            self._ledger(key=key, hit=False, refused=True, model=model, stream=stream)
            self._send(503, "application/json",
                       b'{"error":{"message":"llm-cache-proxy: cache miss in read-only mode"}}')
            return

        conn, r = self._upstream("POST", body)   # ---- miss: forward, relay, record
        ctype = r.getheader("Content-Type", "application/json")
        self.send_response(r.status)
        self.send_header("Content-Type", ctype)
        self.end_headers()
        buf = bytearray()
        while True:
            chunk = r.read1(65536) if hasattr(r, "read1") else r.read(65536)
            if not chunk:
                break
            buf += chunk
            try:
                self.wfile.write(chunk); self.wfile.flush()
            except BrokenPipeError:
                break
        conn.close()
        pt, ct = usage_of(bytes(buf), stream)
        if r.status == 200 and buf:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            tmp = path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"request": req, "content_type": ctype, "raw": bytes(buf).decode("latin-1")}, f)
            os.replace(tmp, path)
        self._ledger(key=key, hit=False, status=r.status, model=model, stream=stream,
                     prompt_tokens=pt, completion_tokens=ct)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--cache-dir", required=True)
    ap.add_argument("--upstream", default="https://api.openai.com/v1")
    ap.add_argument("--mode", default=os.environ.get("LLM_CACHE_MODE", "rw"), choices=["rw", "ro"])
    a = ap.parse_args()
    os.makedirs(a.cache_dir, exist_ok=True)
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), Handler)
    srv.daemon_threads = True
    srv.cache_dir, srv.mode = a.cache_dir, a.mode
    srv.upstream = urllib.parse.urlparse(a.upstream)
    srv.prefix = "/v1"
    print(f"llm-cache-proxy on 127.0.0.1:{a.port} -> {a.upstream} mode={a.mode} cache={a.cache_dir}", flush=True)
    srv.serve_forever()


if __name__ == "__main__":
    main()
