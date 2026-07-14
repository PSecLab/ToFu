import sys
import os
import tempfile
from mcp.server.fastmcp import FastMCP
from markitdown import MarkItDown
from markitdown._exceptions import UnsupportedFormatException, FileConversionException

mcp = FastMCP("MarkItDown MCP Server")
markitdown = MarkItDown()

@mcp.tool()
def convert_to_markdown(data: bytes, filename: str) -> str:
    """
    Converts raw file bytes to Markdown.
    This tool reads and writes files on the file system, potentially resolving file paths and handling zip extraction which could lead to path traversal.
    It can also fetch remote resources or URLs which requires URL validation to prevent SSRF.
    """
    # Ensure a valid suffix from the fuzzed filename
    if ".." in filename or "/" in filename or "\\" in filename:
        raise ValueError("Path traversal detected in filename")

    suffix = os.path.splitext(filename)[1]
    SUPPORTED_EXTENSIONS = [
        ".txt", ".html", ".htm", ".xml", ".rss", ".json", ".ipynb", 
        ".pdf", ".docx", ".xlsx", ".xls", ".pptx", ".png", ".jpg", 
        ".jpeg", ".mp3", ".wav", ".msg", ".zip", ".epub"
    ]
    
    suffix = os.path.splitext(filename)[1].lower()
    if suffix not in SUPPORTED_EXTENSIONS:
        if filename:
            ext_idx = ord(filename[0]) % len(SUPPORTED_EXTENSIONS)
            suffix = SUPPORTED_EXTENSIONS[ext_idx]
        else:
            suffix = ".txt"

    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        tmp_path = tmp.name

    try:
        result = markitdown.convert(tmp_path)
        return result.text_content
    except (UnsupportedFormatException, FileConversionException) as e:
        return f"Handled converter exception: {e}"
    except Exception as e:
        # Re-raise unexpected crashes to be caught by the fuzzer
        raise e
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

@mcp.tool()
def convert_html_to_markdown(html_content: str) -> str:
    """
    Converts raw HTML content to Markdown.
    This tool is a lenient parser designed to process arbitrary HTML text that might contain invalid, broken, or malicious elements (like XSS scripts). It should always succeed normally with any output and never raise exceptions.
    """
    with tempfile.NamedTemporaryFile(delete=False, suffix=".html", mode="w", encoding="utf-8") as tmp:
        tmp.write(html_content)
        tmp_path = tmp.name

    try:
        result = markitdown.convert(tmp_path)
        return result.text_content
    except (UnsupportedFormatException, FileConversionException) as e:
        return f"Handled converter exception: {e}"
    except Exception as e:
        raise e
    finally:
        if os.path.exists(tmp_path):
            os.remove(tmp_path)

if __name__ == "__main__":
    mcp.run()
