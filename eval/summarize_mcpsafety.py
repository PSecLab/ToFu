#!/usr/bin/env python3
"""Turn MCPSafetyScanner logs into reportable claim counts.

MCPSafetyScanner never executes a tool and never emits "safe": every audited
server yields a markdown "Vulnerability Analysis Report" from the agno agents.
Its raw output is therefore a list of *claims*, not findings. This script makes
those claims countable:

  * dedups repeated report passes (the agent prints the same report 2-3x)
  * splits host-OS hardening advice (SSH keys, sudo, NFS...) from claims that
    actually reference the server under audit
  * prints per-server and aggregate counts, and dumps every distinct
    server-claim to a CSV for manual triage (real / by-design / unverifiable /
    hallucinated)

Usage:
  python3 eval/summarize_mcpsafety.py [--runs eval/mcpsafety_runs_vm]
                                      [--csv eval/state/mcpsafety_claims.csv]
"""
import argparse, csv, glob, json, os, re, sys

# Claims about the machine the agno agents run on, not about the MCP server
# under audit. The scanner's "remediation" agent emits generic Linux-hardening
# advice (SSH keys, sudo, cron, file perms) for every server it looks at.
HOST_NOISE = re.compile(
    r"ssh|sudo|nfs|samba|netcat|\bnc\b|world-(?:writable|readable)|cron|"
    r"/etc/passwd|shadow file|setuid|suid|firewall|iptables|kernel|"
    r"package updates?|outdated packages|log rotation|umask|open ports?|"
    r"authorized_keys|startup scripts?|file permissions|sensitive files?|"
    r"environment variables?|credential dumping|backdoor|persistence|"
    r"privilege escalation via path|\.bashrc|\.profile|path hijack",
    re.I,
)
# Markdown section headers the numbered-heading regex also matches.
NOT_A_CLAIM = re.compile(
    r"^\W*(tools?|resources?|prompts?|vulnerability analysis|summary table|"
    r"source citations?.*|conclusions?|overview|introduction|references?|"
    r"report summary.*|remediation.*|exploitation.*)\W*$",
    re.I,
)
TITLE = re.compile(r"^\s*(?:DEBUG\s*)?##\s*\d+\.\s*(?:Vulnerability:\s*)?(.+?)\s*$")


def strip(line):
    return re.sub(r"\s+", " ", line.replace("DEBUG", "", 1)).strip()


def claims_for_log(path):
    """Return list of distinct claim titles in first-seen order."""
    seen, out = set(), []
    for raw in open(path, errors="ignore"):
        m = TITLE.match(raw)
        if not m:
            continue
        t = strip(m.group(1)).strip("*`\" ")
        key = t.lower()
        if key in seen or NOT_A_CLAIM.match(t):
            continue
        seen.add(key)
        out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", default="eval/mcpsafety_runs_vm")
    ap.add_argument("--state", default="eval/state/mcpsafety_runs_vm.jsonl")
    ap.add_argument("--csv", default="eval/state/mcpsafety_claims.csv")
    a = ap.parse_args()

    state = {}
    if os.path.exists(a.state):
        for l in open(a.state):
            r = json.loads(l)
            state[r["repo"]] = r  # last row wins

    rows, agg = [], dict(servers=0, ok=0, err=0, server_claims=0, host_claims=0)
    for f in sorted(glob.glob(os.path.join(a.runs, "*.log"))):
        repo = os.path.basename(f)[:-4].replace("__", "/", 1)
        st = state.get(repo, {})
        agg["servers"] += 1
        if not st.get("ok"):
            agg["err"] += 1
            print(f"ERR  {repo:45} {str(st.get('error',''))[:60]}")
            continue
        agg["ok"] += 1
        cl = claims_for_log(f)
        host = [c for c in cl if HOST_NOISE.search(c)]
        srv = [c for c in cl if not HOST_NOISE.search(c)]
        agg["server_claims"] += len(srv)
        agg["host_claims"] += len(host)
        print(f"OK   {repo:45} server={len(srv):2} host={len(host):2} tools={st.get('n_tools_expected')}")
        for c in srv:
            rows.append(dict(repo=repo, kind="server", claim=c, triage="", note=""))
        for c in host:
            rows.append(dict(repo=repo, kind="host", claim=c, triage="host-noise", note=""))

    print("\n--- aggregate ---")
    print(f"servers seen         {agg['servers']}  (ok {agg['ok']}, err {agg['err']})")
    print(f"distinct server-claims {agg['server_claims']}  "
          f"({agg['server_claims']/max(agg['ok'],1):.1f} per ok server)")
    print(f"distinct host-noise    {agg['host_claims']}  "
          f"({100*agg['host_claims']/max(agg['server_claims']+agg['host_claims'],1):.0f}% of all claims)")
    print(f"servers with 0 server-claims: "
          f"{sum(1 for r in state.values() if r.get('ok')) - len({r['repo'] for r in rows if r['kind']=='server'})}")

    os.makedirs(os.path.dirname(a.csv), exist_ok=True)
    with open(a.csv, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["repo", "kind", "claim", "triage", "note"])
        w.writeheader(); w.writerows(rows)
    print(f"\nclaims -> {a.csv}  ({len(rows)} rows; fill `triage` = real|by-design|unverifiable|hallucinated)")


if __name__ == "__main__":
    sys.exit(main())
