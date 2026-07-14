import os
import tempfile
from mcp.server.fastmcp import FastMCP
from markitdown import MarkItDown

mcp = FastMCP("fuzz_markitdown_files")
markitdown = MarkItDown()

# Persistent temp file path
TEMP_FILE = os.path.join(tempfile.gettempdir(), "fuzz_input_doc")

@mcp.tool()
async def convert_file_content(content: str) -> str:
    """Write content to a local file and convert it to markdown to fuzz the parser libraries"""
    try:
        with open(TEMP_FILE, "w", encoding="utf-8", errors="ignore") as f:
            f.write(content)
    except Exception:
        # Ignore write errors
        return ""
    
    uri = f"file://{TEMP_FILE}"
    # Call markitdown conversion
    result = markitdown.convert_uri(uri)
    return result.markdown if result else ""

if __name__ == "__main__":
    mcp.run()
