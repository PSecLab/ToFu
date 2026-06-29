import sys
import os
import shutil
import json
import asyncio
import threading
import atheris

# =====================================================================
# ÉTAPE CRITIQUE POUR LE COVERAGE : 
# On déclare à Atheris les packages Python cibles qu'il doit instrumenter.
# Remplacez 'votre_package_mcp_serveur' par le nom réel de votre module Python cible.
# =====================================================================
atheris.instrument_imports(include=["votre_package_mcp_serveur"])

# Les imports du serveur ou de l'application cible se font APRÈS l'instrumentation
# exemple: from votre_package_mcp_serveur.tools import la_fonction_de_mon_outil

from .llm import LLMHandler
from .client import MCPInspector
from . import sanitizers

import logging
logger = logging.getLogger(__name__)

_mcp_session = None
_event_loop = None
_selected_sanitizer_names = []
_session_ready = threading.Event()
_stop_mcp_event = None

def _start_asyncio_loop_with_mcp(loop, command, args):
    global _mcp_session, _stop_mcp_event
    asyncio.set_event_loop(loop)
    
    async def mcp_lifecycle():
        global _mcp_session, _stop_mcp_event
        _stop_mcp_event = asyncio.Event()
        
        # Note : On conserve la connexion stdio ou transport ici, 
        # mais le code sous-jacent est maintenant instrumenté en mémoire !
        from mcp.client.stdio import stdio_client
        from mcp import ClientSession, StdioServerParameters
        
        server_params = StdioServerParameters(command=command, args=args)
        
        try:
            async with stdio_client(server_params) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    _mcp_session = session
                    _session_ready.set()
                    await _stop_mcp_event.wait()
        except Exception as e:
            _mcp_session = e
            _session_ready.set()

    loop.create_task(mcp_lifecycle())
    loop.run_forever()


def _test_one_input_factory(queue, input_schema, tool_name):
    def test_one_input(data):
        global _mcp_session, _event_loop, _selected_sanitizer_names
        if _mcp_session is None or _event_loop is None:
            return

        # Données guidées par la couverture (Coverage-guided data generation)
        fdp = atheris.FuzzedDataProvider(data)
        properties = input_schema.get("properties", {})
        generated_arguments = {}

        if fdp.ConsumeBool():
            for prop_name, prop_attrs in properties.items():
                prop_type = prop_attrs.get("type")
                if prop_type == "string":
                    generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 100))
                elif prop_type == "integer":
                    generated_arguments[prop_name] = fdp.ConsumeInt(4)
                elif prop_type == "boolean":
                    generated_arguments[prop_name] = fdp.ConsumeBool()
                else:
                    generated_arguments[prop_name] = fdp.ConsumeUnicodeNoSurrogates(fdp.ConsumeIntInRange(0, 20))
        else:
            try:
                raw_string = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
                generated_arguments = json.loads(raw_string)
                if not isinstance(generated_arguments, dict):
                    generated_arguments = {"parasite_param": raw_string}
            except:
                generated_arguments = {"collection": fdp.ConsumeUnicodeNoSurrogates(10), "document": "invalid_json"}

        # Exécution des sanitizers
        sanitizer_triggered = False
        triggered_by = []
        
        for val in generated_arguments.values():
            if isinstance(val, str):
                for sanitizer_name in _selected_sanitizer_names:
                    sanitizer_fn = getattr(sanitizers, sanitizer_name, None)
                    if sanitizer_fn and sanitizer_fn(val):
                        sanitizer_triggered = True
                        if sanitizer_name not in triggered_by:
                            triggered_by.append(sanitizer_name)

        tool_crashed = False
        try:
            future = asyncio.run_coroutine_threadsafe(
                _mcp_session.call_tool(tool_name, arguments=generated_arguments), _event_loop
            )
            future.result()
        except Exception as e:
            # Atheris interceptera les crashs critiques (Segfaults, C-level crashes) 
            # Les exceptions Python classiques (ex: ValueError) mettent fin au fuzzing s'il s'agit d'un bug non géré.
            tool_crashed = True

        if sanitizer_triggered and not tool_crashed:
            err_details = (
                f"Silent Bug Alert: Sanitizers {triggered_by} flagged this input as malicious, "
                f"but the target tool executed successfully without raising any exception."
            )
            queue.put((generated_arguments, err_details))
            # Sortie propre pour lever l'alerte à Atheris
            sys.exit(1)

    return test_one_input


class MCPDifferentialFuzzer:
    def __init__(self, command: str, args: list, target_tool: str, api_key: str, corpus_dir: str = "./fuzz_corpus"):
        self.command = command
        self.args = args
        self.target_tool = target_tool
        self.corpus_dir = corpus_dir
        self.llm = LLMHandler(api_key=api_key)
        self.inspector = MCPInspector(command=command, args=args)

    def run(self, max_iterations: int = 5, time_per_iteration: int = 20):
        loop = asyncio.new_event_loop()
        
        if self.target_tool in ["*", None]:
            logger.info("Scanning MCP server to discover all tools")
            try:
                tools_to_fuzz = loop.run_until_complete(self.inspector.fetch_all_tools())
                logger.info(f"Found {len(tools_to_fuzz)} tools to fuzz: {tools_to_fuzz}")
            except Exception as e:
                logger.error(f"Failed to list tools from MCP server: {e}")
                return
        else:
            tools_to_fuzz = [self.target_tool]

        for tool in tools_to_fuzz:
            logger.info(f"\n{'='*20} STARTING COVERAGE-GUIDED FUZZING FOR TOOL: {tool} {'='*20}")
            
            try:
                t_name, t_desc, t_schema = loop.run_until_complete(self.inspector.fetch_tool_metadata(tool))
            except Exception as e:
                logger.error(f"Failed to inspect tool '{tool}': {e}. Skipping.")
                continue

            global _selected_sanitizer_names, _event_loop, _mcp_session, _stop_mcp_event
            _selected_sanitizer_names = self.llm.select_sanitizers(t_name, t_desc, t_schema, sanitizers.AVAILABLE_SANITIZERS)
            
            # Génération des seeds par LLM
            seeds = self.llm.generate_seeds(t_name, t_desc, t_schema)
            if os.path.exists(self.corpus_dir):
                shutil.rmtree(self.corpus_dir)
            os.makedirs(self.corpus_dir)

            for idx, seed in enumerate(seeds):
                with open(os.path.join(self.corpus_dir, f"seed_{idx}.json"), "w") as f:
                    json.dump(seed, f)

            # Démarrage du serveur MCP In-Process dans un thread d'arrière-plan
            _session_ready.clear()
            _mcp_session = None
            _event_loop = asyncio.new_event_loop()
            
            bg_thread = threading.Thread(
                target=_start_asyncio_loop_with_mcp, 
                args=(_event_loop, self.command, self.args), 
                daemon=True
            )
            bg_thread.start()
            _session_ready.wait()

            if isinstance(_mcp_session, Exception) or _mcp_session is None:
                logger.error(f"Failed to start MCP server inside process: {_mcp_session}")
                continue

            # Création d'une queue locale pour les résultats des vulnérabilités silencieuses
            import queue
            res_queue = queue.Queue()

            # Configuration d'Atheris sur le processus principal (Requis pour le tracking de couverture)
            logger.info(f"[{tool}] Starting Atheris engine...")
            atheris_args = [sys.argv[0], f"-max_total_time={time_per_iteration}", self.corpus_dir]
            
            atheris.Setup(atheris_args, _test_one_input_factory(res_queue, t_schema, tool))
            try:
                atheris.Fuzz()
            except SystemExit:
                pass # Déclenché intentionnellement lors d'une détection

            # Analyse des résultats post-fuzzing
            if not res_queue.empty():
                failed_input, error_details = res_queue.get()
                logger.warning(f"\n[POTENTIAL VULNERABILITY / SILENT BUG FOUND] in '{tool}' !")
                logger.warning(f"   -> Faulty Input : {repr(failed_input)}")
                logger.warning(f"   -> Analysis     : {error_details}")
            else:
                logger.info(f"Fuzzing session for '{tool}' completed. No silent bugs detected with current coverage.")

            # Nettoyage de la session et du thread
            if _stop_mcp_event and _event_loop.is_running():
                _event_loop.call_soon_threadsafe(_stop_mcp_event.set)
            import time
            time.sleep(0.2)
            if _event_loop.is_running():
                _event_loop.call_soon_threadsafe(_event_loop.stop)
            bg_thread.join()

            if os.path.exists(self.corpus_dir):
                shutil.rmtree(self.corpus_dir)
