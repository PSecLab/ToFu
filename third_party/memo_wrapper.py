import os
import sys

# Add memo src to sys.path
memo_src = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "memo", "src")
)
if memo_src not in sys.path:
    sys.path.insert(0, memo_src)

from memo.server import build_server

if __name__ == "__main__":
    server = build_server()
    server.run(transport="stdio")
