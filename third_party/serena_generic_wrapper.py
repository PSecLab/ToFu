import json
import os
import sys
import webbrowser

# Disable browser tab popping during fuzzing
webbrowser.open = lambda *args, **kwargs: True
webbrowser.open_new = lambda *args, **kwargs: True
webbrowser.open_new_tab = lambda *args, **kwargs: True

import serena.dashboard
serena.dashboard.open_url_in_browser = lambda *args, **kwargs: None

from serena.agent import SerenaAgent, AvailableTools, ToolSet
from serena.tools import ToolRegistry

SerenaAgent.open_dashboard_in_browser = lambda *args, **kwargs: None
SerenaAgent.open_dashboard = lambda *args, **kwargs: False

_agent = None

def get_agent():
    global _agent
    if _agent is None:
        project_dir = os.path.abspath(
            os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena")
        )
        _agent = SerenaAgent(project=project_dir)
        registry = ToolRegistry()
        all_tool_names = set(registry._tool_dict.keys())
        _agent._base_toolset = ToolSet(all_tool_names)
        _agent._active_tools = AvailableTools(list(_agent._all_tools.values()))
    return _agent

def invoke_tool(tool_name: str, kwargs: dict):
    agent = get_agent()
    registry = ToolRegistry()
    
    if tool_name not in registry._tool_dict:
        raise ValueError(f"Tool '{tool_name}' not found in Serena ToolRegistry.")
        
    tool_cls = registry._tool_dict[tool_name].tool_class
    tool_instance = tool_cls(agent)
    
    return tool_instance.apply_ex(log_call=False, catch_exceptions=False, **kwargs)

# On expose dynamiquement toutes les fonctions associées au nom de chaque tool Serena
def _create_wrapper_function(name):
    def wrapper_func(**kwargs):
        return invoke_tool(name, kwargs)
    wrapper_func.__name__ = name
    return wrapper_func

registry = ToolRegistry()
for t_name in registry._tool_dict.keys():
    globals()[t_name] = _create_wrapper_function(t_name)

def main():
    raw_input = sys.stdin.read().strip()
    if not raw_input:
        return

    try:
        data = json.loads(raw_input)
    except Exception as e:
        print(f"Error parsing JSON: {e}", file=sys.stderr)
        sys.exit(1)

    tool_name = os.environ.get("TARGET_TOOL")
    if not tool_name:
        print("Error: TARGET_TOOL environment variable not set", file=sys.stderr)
        sys.exit(1)

    result = invoke_tool(tool_name, data)
    print(result)

if __name__ == "__main__":
    main()
