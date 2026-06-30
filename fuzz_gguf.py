import sys
import os
import tempfile
import struct
from mcp.server.fastmcp import FastMCP

# Add tools-main/python to path
sys.path.append(os.path.join(os.path.dirname(__file__), "tools-main", "python"))
from gguf_inspect import extract_metadata

mcp = FastMCP("GGUF Inspector MCP Server")

@mcp.tool()
def inspect_gguf(data: bytes) -> str:
    """
    Parses raw bytes of a GGUF file and extracts its metadata key/value pairs.
    """
    # Write bytes to a temporary file
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        from pathlib import Path
        meta = extract_metadata(Path(tmp_path))
        return str(meta)
    except (EOFError, ValueError, KeyError, IndexError, struct.error) as e:
        # Handled parse errors
        return f"Parse error: {e}"
    except Exception as e:
        # Re-raise unexpected crashes (e.g. struct.error, etc. if not caught)
        import struct
        if isinstance(e, struct.error):
            return f"Struct unpack error: {e}"
        raise e
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == "__main__":
    mcp.run()
