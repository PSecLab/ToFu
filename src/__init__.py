from .fuzzer import MCPDifferentialFuzzer

__all__ = ["MCPDifferentialFuzzer"]

# Alias mcp_fuzzer and its submodules to src to maintain backward compatibility
import sys
sys.modules['mcp_fuzzer'] = sys.modules[__name__]
try:
    from . import runners
    sys.modules['mcp_fuzzer.runners'] = runners
    from . import sanitizers
    sys.modules['mcp_fuzzer.sanitizers'] = sanitizers
except ImportError:
    pass