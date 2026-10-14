#!/usr/bin/env python3
"""
Stage-2 extraction: clone every ToFu-runnable MCP repo, extract its MCP tool
registrations and its real sink-API usage, then delete the clone.

RESUMABLE: results.jsonl and failures.jsonl are append-only. Re-running skips
every repo already recorded in either. Safe to kill and restart at any time.

Clones go to VM scratch (~/extract_work) and are deleted immediately after
parsing, so peak disk == (workers x repo size), not the whole corpus.
"""
import json, os, re, subprocess, sys, shutil, time, threading
from concurrent.futures import ThreadPoolExecutor

BASE   = os.path.expanduser("~/mnt/toolfuzzer/Benchmarks/extraction")
WORK   = os.path.expanduser("~/extract_work")
CORPUS = os.path.expanduser("~/corpus_probe/servers.json")
RESULTS  = os.path.join(BASE, "results.jsonl")
FAILURES = os.path.join(BASE, "failures.jsonl")
TARGETS  = os.path.join(BASE, "targets.jsonl")
WORKERS  = 16
CLONE_TIMEOUT = 90

# ---- sink patterns, keyed to ToFu's 21 introspection tracers ----
SINKS = {
 'FileAccess':      [r'\bopen\s*\(', r'\bPath\s*\(', r'pathlib', r'fs\.readFile', r'fs\.createReadStream', r'readFileSync'],
 'FileWrite':       [r'fs\.writeFile', r'writeFileSync', r'fs\.createWriteStream', r'shutil\.(copy|move)', r'\.write\s*\('],
 'CommandExecution':[r'\bsubprocess\b', r'os\.system', r'os\.popen', r'child_process', r'execSync', r'spawnSync', r'\bexeca\b'],
 'NetworkExecution':[r'\brequests\.', r'\bhttpx\b', r'urllib\.request', r'aiohttp', r'\bfetch\s*\(', r'\baxios\b', r'node-fetch', r'got\('],
 'SQLExecution':    [r'\bsqlite3\b', r'psycopg', r'pymysql', r'sqlalchemy', r'\.execute\s*\(', r'\bknex\b', r'\bprisma\b', r'mysql2'],
 'CodeExecution':   [r'\beval\s*\(', r'\bexec\s*\(', r'vm\.runIn', r'new\s+Function\s*\(', r'compile\s*\('],
 'Deserialization': [r'\bpickle\b', r'\bmarshal\b', r'yaml\.load\b', r'js-yaml', r'node-serialize', r'\bdill\b'],
 'DataAmplification':[r'\bzipfile\b', r'\btarfile\b', r'\bgzip\b', r'adm-zip', r'\bunzipper\b', r'\byauzl\b', r'\bzlib\b'],
 'XXE':             [r'xml\.etree', r'\blxml\b', r'xml2js', r'libxmljs', r'DOMParser', r'xmldom', r'minidom'],
 'UnverifiedCodeDownload':[r'urlretrieve', r'\bwget\b', r'curl\s+-', r'download.*\.(sh|exe|bin)', r'pip\s+install', r'npm\s+install'],
 'SensitiveDataLogging':[r'os\.environ', r'process\.env', r'getenv', r'dotenv'],
 'SSLCertValidation':[r'verify\s*=\s*False', r'rejectUnauthorized\s*:\s*false', r'_create_unverified', r'NODE_TLS_REJECT'],
 'WeakHash':        [r'\bmd5\b', r'\bsha1\b', r'hashlib\.(md5|sha1)', r"createHash\(['\"](md5|sha1)"],
 'WeakPRNG':        [r'\brandom\.', r'Math\.random', r'randint', r'choice\('],
 'NonceReuse':      [r'\bnonce\b', r'\biv\s*=', r'initialization_vector'],
 'TempFileLeak':    [r'\btempfile\b', r'mkdtemp', r'mkstemp', r'os\.tmpdir', r'/tmp/'],
 'BlockingEventLoopCall':[r'time\.sleep', r'execSync', r'readFileSync', r'sleep\s*\('],
 'ReDoS':           [r'\bre\.compile', r'\bre\.(match|search|findall)', r'new\s+RegExp'],
 'LogInjection':    [r'logging\.', r'logger\.', r'console\.log', r'print\s*\('],
 'UnrestrictedIPBinding':[r'0\.0\.0\.0', r'host\s*=\s*["\']0', r'listen\s*\('],
 'LoopCondition':   [r'while\s+True', r'while\s*\(\s*true', r'for\s*\(\s*;;'],
}
SINKS_C = {k:[re.compile(p, re.I) for p in v] for k,v in SINKS.items()}

# ---- MCP tool registration patterns ----
TOOL_PATS = [
 re.compile(r'@(?:mcp|server|app)\.tool\s*\(', re.I),
 re.compile(r'@(?:mcp|server|app)\.tool\b'),
 re.compile(r'types\.Tool\s*\(\s*name\s*=\s*["\']([\w\-.]+)', re.I),
 re.compile(r'\bTool\s*\(\s*name\s*=\s*["\']([\w\-.]+)', re.I),
 re.compile(r'\bserver\.tool\s*\(\s*["\']([\w\-.]+)', re.I),
 re.compile(r'\bregisterTool\s*\(\s*["\']([\w\-.]+)', re.I),
 re.compile(r'name\s*:\s*["\']([\w\-.]+)["\']\s*,\s*description\s*:', re.I),
]
NAMED = re.compile(r'def\s+(\w+)\s*\(', re.I)
LIST_TOOLS = re.compile(r'ListToolsRequestSchema|list_tools|listTools', re.I)
SRC_EXT = {'.py','.js','.ts','.mjs','.cjs','.tsx','.jsx'}

lock = threading.Lock()
counter = {'done':0, 'ok':0, 'fail':0}

def load_done():
    done=set()
    for f in (RESULTS, FAILURES):
        if os.path.exists(f):
            for line in open(f):
                try: done.add(json.loads(line)['repo'])
                except Exception: pass
    return done

def scan_repo(path):
    tools=set(); sinks={k:0 for k in SINKS}; nfiles=0; nloc=0; has_list=False
    for root,dirs,files in os.walk(path):
        dirs[:] = [d for d in dirs if d not in
                   ('.git','node_modules','venv','.venv','dist','build','__pycache__','test','tests','.pytest_cache')]
        for fn in files:
            if os.path.splitext(fn)[1].lower() not in SRC_EXT: continue
            fp=os.path.join(root,fn)
            try:
                if os.path.getsize(fp) > 900_000: continue
                src=open(fp, encoding='utf-8', errors='ignore').read()
            except Exception: continue
            nfiles+=1; nloc+=src.count('\n')
            if LIST_TOOLS.search(src): has_list=True
            for pat in TOOL_PATS:
                for m in pat.finditer(src):
                    if m.groups() and m.group(1): tools.add(m.group(1))
                    else:
                        tail=src[m.end():m.end()+400]
                        dm=NAMED.search(tail)
                        if dm: tools.add(dm.group(1))
            for k,pats in SINKS_C.items():
                for p in pats:
                    n=len(p.findall(src))
                    if n: sinks[k]+=n
    return sorted(tools), sinks, nfiles, nloc, has_list

def handle(rec):
    repo=rec['repo']; dest=os.path.join(WORK, repo.replace('/','__'))
    env=dict(os.environ, GIT_TERMINAL_PROMPT='0', GIT_ASKPASS='echo')
    try:
        if os.path.exists(dest): shutil.rmtree(dest, ignore_errors=True)
        p=subprocess.run(['git','clone','--depth','1','--quiet','--no-tags',
                          f"https://github.com/{repo}.git", dest],
                         capture_output=True, timeout=CLONE_TIMEOUT, env=env)
        if p.returncode!=0:
            raise RuntimeError((p.stderr.decode()[:160] or 'clone failed').strip())
        sha=subprocess.run(['git','-C',dest,'rev-parse','HEAD'],
                           capture_output=True, timeout=30).stdout.decode().strip()
        tools,sinks,nfiles,nloc,has_list = scan_repo(dest)
        out=dict(rec, commit=sha, tools=tools, n_tools=len(tools),
                 sinks={k:v for k,v in sinks.items() if v},
                 n_files=nfiles, n_loc=nloc, has_list_tools=has_list, ok=True)
        with lock:
            with open(RESULTS,'a') as f: f.write(json.dumps(out)+"\n")
            counter['ok']+=1; counter['done']+=1
    except Exception as e:
        with lock:
            with open(FAILURES,'a') as f:
                f.write(json.dumps({'repo':repo,'error':str(e)[:200],'ok':False})+"\n")
            counter['fail']+=1; counter['done']+=1
    finally:
        shutil.rmtree(dest, ignore_errors=True)

def main():
    os.makedirs(WORK, exist_ok=True); os.makedirs(BASE, exist_ok=True)
    targets=[json.loads(l) for l in open(TARGETS)]
    done=load_done()
    todo=[t for t in targets if t['repo'] not in done]
    print(f"targets={len(targets)} already_done={len(done)} todo={len(todo)}", flush=True)
    t0=time.time()
    with ThreadPoolExecutor(max_workers=WORKERS) as ex:
        for i,_ in enumerate(ex.map(handle, todo), 1):
            if i % 25 == 0:
                el=time.time()-t0; rate=i/el if el else 0
                eta=(len(todo)-i)/rate/60 if rate else 0
                print(f"[{i}/{len(todo)}] ok={counter['ok']} fail={counter['fail']} "
                      f"{rate:.1f}/s eta={eta:.0f}min", flush=True)
    print(f"DONE ok={counter['ok']} fail={counter['fail']} in {(time.time()-t0)/60:.1f}min", flush=True)

if __name__=='__main__':
    main()
