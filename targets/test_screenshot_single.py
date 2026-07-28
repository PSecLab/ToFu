import json
import subprocess
import time
import sys

def test_screenshot_input(args_dict):
    server_path = "/home/pierre/Bureau/Toolfuzz/Framework/third_party/chrome-devtools-mcp/build/src/bin/chrome-devtools-mcp.js"
    cmd = ["node", server_path, "--no-usage-statistics", "--browserUrl=http://127.0.0.1:9222"]
    
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    # 1. Initialize MCP Session
    init_req = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "test", "version": "1.0"}
        }
    }
    proc.stdin.write(json.dumps(init_req) + "\n")
    proc.stdin.flush()
    init_res = proc.stdout.readline()
    print("INIT RES:", init_res.strip())
    
    # 2. Call take_screenshot with target args
    call_req = {
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {
            "name": "take_screenshot",
            "arguments": args_dict
        }
    }
    print(f"SENDING CALL: {args_dict}")
    start = time.time()
    proc.stdin.write(json.dumps(call_req) + "\n")
    proc.stdin.flush()
    
    res_line = proc.stdout.readline()
    elapsed = time.time() - start
    print(f"RESPONSE IN {elapsed:.2f}s: {res_line.strip()}")
    proc.terminate()

if __name__ == "__main__":
    test_input = {"format": "webp", "quality": 100, "fullPage": True, "filePath": "full_page.webp"}
    if len(sys.argv) > 1:
        test_input = json.loads(sys.argv[1])
    test_screenshot_input(test_input)
