import os
import sys
import json
import time
import inspect
import logging
import datetime
import traceback
import argparse
import subprocess

sys.path.append(os.path.dirname(os.path.dirname(__file__)))

from src.fuzzer import MCPDifferentialFuzzer
from src.config import FuzzerConfig
from src.reporters import BaseVulnerabilityReporter, CompositeVulnerabilityReporter, ConsoleVulnerabilityReporter

# Import du ToolRegistry officiel de Serena
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena", "src")))
import serena.tools
from serena.tools import ToolRegistry

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("fuzz_serena_session.log", mode="a")
    ]
)
logger = logging.getLogger("fuzz_serena")


class SerenaMetadataProvider:
    """Fournit les métadonnées directement depuis le ToolRegistry de Serena pour éviter tout blocage stdio/RPC."""
    def __init__(self):
        self.registry = ToolRegistry()

    async def fetch_all_tools(self) -> list:
        return sorted(list(self.registry._tool_dict.keys()))

    async def fetch_tool_metadata(self, tool_name: str) -> tuple:
        if tool_name in self.registry._tool_dict:
            reg_tool = self.registry._tool_dict[tool_name]
            cls = reg_tool.tool_class
            desc = cls.get_tool_description()
            
            sig = inspect.signature(cls.apply)
            properties = {}
            required = []
            for param_name, param in sig.parameters.items():
                if param_name in ("self", "args", "kwargs"):
                    continue
                param_type = "string"
                if param.annotation == int:
                    param_type = "integer"
                elif param.annotation == bool:
                    param_type = "boolean"
                elif param.annotation == dict:
                    param_type = "object"
                elif param.annotation == list:
                    param_type = "array"
                properties[param_name] = {"type": param_type}
                if param.default == inspect.Parameter.empty:
                    required.append(param_name)
            
            schema = {
                "type": "object",
                "properties": properties,
                "required": required
            }
            return tool_name, desc, schema
        return tool_name, f"Serena tool {tool_name}", {"type": "object", "properties": {}}


class JSONFileVulnerabilityReporter(BaseVulnerabilityReporter):
    """
    Reporter qui enregistre toutes les vulnérabilités / bugs trouvés
    dans un fichier JSON cumulatif ainsi qu'un résumé TXT lisible,
    avec un gros affichage console percutant.
    """
    def __init__(self, json_path: str = "serena_vulnerabilities_report.json", txt_path: str = "serena_vulnerabilities_summary.txt"):
        self.json_path = os.path.abspath(json_path)
        self.txt_path = os.path.abspath(txt_path)
        self.findings = []
        self._load_existing()

    def _load_existing(self):
        if os.path.exists(self.json_path):
            try:
                with open(self.json_path, "r", encoding="utf-8") as f:
                    self.findings = json.load(f)
            except Exception as e:
                logger.error(f"Impossible de charger le rapport existant: {e}")

    def report(self, tool_name: str, inputs: dict, output: any, triggered_sanitizers: list[str], analysis: str) -> None:
        def default_serializer(o):
            if isinstance(o, bytes):
                return o.decode('utf-8', errors='replace')
            return repr(o)

        entry = {
            "timestamp": datetime.datetime.now().isoformat(),
            "timestamp_epoch": time.time(),
            "tool": tool_name,
            "inputs": inputs,
            "output": str(output),
            "triggered_sanitizers": triggered_sanitizers,
            "analysis": analysis
        }

        self.findings.append(entry)

        # ---------------------------------------------------------------------
        # GROS PRINT DE DÉCOUVERTE DE BUG / VULNÉRABILITÉ
        # ---------------------------------------------------------------------
        print("\n" + "💥"*40, flush=True)
        print("🔥 [BUG / VULNÉRABILITÉ DÉTECTÉE !] 🔥", flush=True)
        print(f"⏰ Date & Heure : {entry['timestamp']}", flush=True)
        print(f"🛠️  Outil Fuzzé  : {tool_name}", flush=True)
        print(f"⚠️  Sanitizer(s) : {', '.join(triggered_sanitizers)}", flush=True)
        print(f"📥 Input Fautif  : {json.dumps(inputs, default=default_serializer)}", flush=True)
        print(f"🧐 Analyse       : {analysis}", flush=True)
        print(f"📤 Sortie Tool   : {str(output)[:300]}", flush=True)
        print(f"💾 Sauvegardé dans {self.json_path} et {self.txt_path}", flush=True)
        print("💥"*40 + "\n", flush=True)

        # Sauvegarde JSON
        try:
            with open(self.json_path, "w", encoding="utf-8") as f:
                json.dump(self.findings, f, indent=2, default=default_serializer)
        except Exception as e:
            logger.error(f"Erreur écriture rapport JSON: {e}")

        # Sauvegarde résumé TXT lisible
        try:
            with open(self.txt_path, "a", encoding="utf-8") as f:
                f.write("=" * 70 + "\n")
                f.write(f"DATE        : {entry['timestamp']}\n")
                f.write(f"TOOL        : {tool_name}\n")
                f.write(f"SANITIZERS  : {', '.join(triggered_sanitizers)}\n")
                f.write(f"INPUTS      : {json.dumps(inputs, default=default_serializer)}\n")
                f.write(f"ANALYSIS    : {analysis}\n")
                f.write(f"OUTPUT      : {str(output)[:500]}\n")
                f.write("=" * 70 + "\n\n")
        except Exception as e:
            logger.error(f"Erreur écriture résumé TXT: {e}")


def get_serena_tools() -> list[str]:
    """Récupère la liste de tous les outils enregistrés dans le ToolRegistry de Serena."""
    try:
        registry = ToolRegistry()
        tools = sorted(list(registry._tool_dict.keys()))
        return tools
    except Exception as e:
        logger.error(f"Erreur lors de l'accès au ToolRegistry Serena : {e}")
        return ["read_file", "create_text_file", "delete_lines", "replace_lines", "list_dir", "search_for_pattern", "find_file"]


def run_single_tool_fuzzing(tool: str, time_seconds: int):
    """Exécute une itération de fuzzing sur un seul outil dans un processus dédié."""
    python_path = sys.executable
    server_script = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena_generic_wrapper.py")
    )
    sandbox_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "third_party", "serena")
    )
    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus")
    )
    os.makedirs(corpus_base_dir, exist_ok=True)

    config = FuzzerConfig(
        timeout_limit=5.0,
        allowed_workspace_dir=sandbox_dir
    )

    file_backed_params = {
        "relative_path": {
            "extension": ".py",
            "prefix": "fuzz_test_file_"
        },
        "path": {
            "extension": ".txt",
            "prefix": "fuzz_path_"
        },
        "filepath": {
            "extension": ".txt",
            "prefix": "fuzz_filepath_"
        }
    }

    file_reporter = JSONFileVulnerabilityReporter(
        json_path="serena_vulnerabilities_report.json",
        txt_path="serena_vulnerabilities_summary.txt"
    )
    reporter = CompositeVulnerabilityReporter([
        ConsoleVulnerabilityReporter(),
        file_reporter
    ])

    metadata_provider = SerenaMetadataProvider()
    tool_corpus_dir = os.path.join(corpus_base_dir, f"corpus_{tool}")
    os.makedirs(tool_corpus_dir, exist_ok=True)

    fuzzer = MCPDifferentialFuzzer(
        command=python_path,
        args=[server_script],
        target_tool=tool,
        api_key=os.environ.get("OLLAMA_CLOUD_API_KEY", "f3ddcac48ab94ad692154fbb0ba3d283.mvFXxYWZ4pQnmeSA27BnBp8z"),
        corpus_dir=tool_corpus_dir,
        config=config,
        file_backed_params=file_backed_params,
        reporter=reporter,
        metadata_provider=metadata_provider,
        override_rules={
            "check_unexpected_crash": {},
            "check_introspection_sensitive_error_leak": {},
            "check_introspection_redos": {},
            "check_introspection_type_confusion": {},
            "check_introspection_memory_access_violation": {}
        }
    )

    existing_seeds = [os.path.join(tool_corpus_dir, f) for f in os.listdir(tool_corpus_dir) if os.path.isfile(os.path.join(tool_corpus_dir, f))]
    if existing_seeds:
        print(f"🧠 [CORPUS PERSISTANT] {len(existing_seeds)} entrées trouvées pour '{tool}'. Réutilisation sans régénération.", flush=True)
        fuzzer._setup_corpus_seeds = lambda: None
        
        def safe_cleanup():
            if fuzzer.current_runner:
                fuzzer.current_runner.stop()
            for file in os.listdir("."):
                if file.startswith("crash-"):
                    try:
                        os.remove(file)
                    except Exception:
                        pass
        fuzzer._cleanup_runner = safe_cleanup

    fuzzer.run(time_per_iteration=time_seconds)


def main():
    parser = argparse.ArgumentParser(description="Fuzzer automatique pour tous les outils Serena")
    parser.add_argument("--time", type=int, default=1200, help="Durée du fuzzing par outil en secondes (défaut: 1200s = 20 min)")
    parser.add_argument("--tool", type=str, default=None, help="Mode sous-processus interne pour fuzzer un seul outil")
    args_cli = parser.parse_args()

    if args_cli.tool:
        # Mode execution mono-tool dans son propre sous-processus isoler
        run_single_tool_fuzzing(args_cli.tool, args_cli.time)
        return

    TIME_PER_TOOL_SECONDS = args_cli.time
    python_path = sys.executable
    script_path = os.path.abspath(__file__)
    corpus_base_dir = os.path.abspath(
        os.path.join(os.path.dirname(os.path.dirname(__file__)), "persistent_corpus")
    )
    os.makedirs(corpus_base_dir, exist_ok=True)

    tools = get_serena_tools()
    iteration = 1

    print("\n" + "🚀"*40, flush=True)
    print(f"  LANCEMENT DU FUZZER SERENA EN CONTINU (BOUCLE INFINIE)", flush=True)
    print(f"  ⏱️  Durée par outil  : {TIME_PER_TOOL_SECONDS // 60 if TIME_PER_TOOL_SECONDS >= 60 else TIME_PER_TOOL_SECONDS} {'minutes' if TIME_PER_TOOL_SECONDS >= 60 else 'secondes'} ({TIME_PER_TOOL_SECONDS}s)", flush=True)
    print(f"  🛠️  Nombre d'outils   : {len(tools)} outils enregistrés", flush=True)
    print(f"  📁 Liste des outils  : {', '.join(tools)}", flush=True)
    print(f"  💾 Corpus persistant : {corpus_base_dir}", flush=True)
    print(f"  📄 Fichiers rapports : serena_vulnerabilities_report.json & serena_vulnerabilities_summary.txt", flush=True)
    print("🚀"*40 + "\n", flush=True)

    env = os.environ.copy()
    env["PYTHONPATH"] = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))

    while True:
        print("\n" + "🔄"*40, flush=True)
        print(f"🔄 [CYCLE N°{iteration}] DÉBUT D'UN NOUVEAU TOUR SUR TOUS LES OUTILS SERENA", flush=True)
        print("🔄"*40 + "\n", flush=True)

        for idx, tool in enumerate(tools, 1):
            next_tool_name = tools[idx] if idx < len(tools) else tools[0]
            
            print("\n" + "⚡"*40, flush=True)
            print(f"▶️  [START TOOL {idx}/{len(tools)}] FUZZING SUR L'OUTIL : ---> '{tool}' <---", flush=True)
            print(f"⏰ Temps imparti : {TIME_PER_TOOL_SECONDS}s (jusqu'à {(datetime.datetime.now() + datetime.timedelta(seconds=TIME_PER_TOOL_SECONDS)).strftime('%H:%M:%S')})", flush=True)
            print("⚡"*40 + "\n", flush=True)

            cmd = [
                python_path, script_path,
                "--tool", tool,
                "--time", str(TIME_PER_TOOL_SECONDS)
            ]

            try:
                # Execution isolee dans un nouveau processus Python par outil
                subprocess.run(cmd, env=env)
            except Exception as e:
                print("\n" + "⚠️"*40, flush=True)
                print(f"⚠️  [EXCEPTION INTERCEPTÉE SUR '{tool}'] : {e}", flush=True)
                print("Le fuzzer poursuit son exécution vers l'outil suivant sans s'arrêter.", flush=True)
                print("⚠️"*40 + "\n", flush=True)

            print("\n" + "🔀"*40, flush=True)
            print(f"⏹️  [FIN DE SESSION DE FUZZING] Fuzzing terminé pour '{tool}'.", flush=True)
            print(f"🔀 [SWITCH] Passage au tool suivant : ---> '{next_tool_name}' <---", flush=True)
            print("🔀"*40 + "\n", flush=True)

            time.sleep(1)

        iteration += 1


if __name__ == "__main__":
    main()
