import json
import os
import sys
from serena.agent import SerenaAgent
from serena.tools.file_tools import ReadFileTool

def read_file(relative_path: str = None, **kwargs) -> str:
    """Wrapper function to execute Serena ReadFileTool directly."""
    project_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena")
    )
    agent = SerenaAgent(project=project_dir)
    tool = ReadFileTool(agent)
    
    params = {}
    if relative_path is not None:
        params["relative_path"] = relative_path
    params.update(kwargs)

    return tool.apply_ex(log_call=False, catch_exceptions=False, **params)

def main():
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        return

    try:
        kwargs = json.loads(raw_input)
    except Exception as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)

    result = read_file(**kwargs)
    print(result)

if __name__ == "__main__":
    main()
