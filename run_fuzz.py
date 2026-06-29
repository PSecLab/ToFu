import os
import logging
import sys
from mcp_fuzzer import MCPDifferentialFuzzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


def main():
    # Exemple si votre serveur MCP Python est exécutable via un module ou un script
    # Assurez-vous que la variable passée à `include=[]` dans core.py correspond à ce serveur.
    fuzzer = MCPDifferentialFuzzer(
        command=sys.executable,  # Utilise l'interpréteur Python actuel
        args=["-m", "mcp-for-beginners/03-GettingStarted/samples/python/mcp_calculator_server"], # ["path/to/server.py"]
        target_tool="divide", 
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z")
    )
    
    # max_iterations est ignoré car atheris tourne sur le processus principal avec sa propre gestion du temps (time_per_iteration)
    fuzzer.run(time_per_iteration=30)

if __name__ == "__main__":
    main()