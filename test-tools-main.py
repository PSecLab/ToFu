#!/usr/bin/env python3
import os
import sys
import subprocess
import shlex
from pathlib import Path

# Chemin vers le dossier contenant les outils python dans tools-main
BASE_DIR = Path(__file__).resolve().parent
TOOLS_DIR = BASE_DIR / "third_party" / "tools-main" / "python"

def list_available_tools():
    """Liste tous les fichiers .py disponibles dans le dossier des outils."""
    if not TOOLS_DIR.exists():
        print(f"❌ Le dossier {TOOLS_DIR} n'existe pas.")
        return []
    
    tools = [f.name for f in TOOLS_DIR.glob("*.py") if not f.name.startswith("__")]
    return sorted(tools)

def main():
    tools = list_available_tools()
    
    print("=" * 60)
    print(" 🛠️  Runner d'outils tools-main")
    print("=" * 60)
    print(f"Dossier des outils : {TOOLS_DIR}")
    print("Tapez 'quit' ou 'exit' à n'importe quel moment pour quitter.\n")

    if tools:
        print("Outils disponibles dans le dossier :")
        for tool in tools:
            print(f" - {tool}")
        print()

    while True:
        try:
            # 1. Demande le nom de l'outil Python
            tool_name = input("\nNom de l'outil (ex: all_gcp_buckets.py) : ").strip()
            
            if tool_name.lower() in ("quit", "exit", "q"):
                print("Au revoir !")
                break

            if not tool_name:
                continue

            # Ajoute l'extension .py si omise
            if not tool_name.endswith(".py"):
                tool_name += ".py"

            tool_path = TOOLS_DIR / tool_name

            if not tool_path.exists():
                print(f"❌ Erreur : L'outil '{tool_name}' est introuvable dans {TOOLS_DIR}")
                continue

            # 2. Demande les arguments / inputs pour cet outil
            args_input = input(f"Entrez les arguments/inputs pour {tool_name} (ex: test ou --help) : ").strip()

            if args_input.lower() in ("quit", "exit", "q"):
                print("Au revoir !")
                break

            # Découpage propre des arguments
            extra_args = shlex.split(args_input) if args_input else []

            # 3. Exécution du script et affichage du résultat
            cmd = [sys.executable, str(tool_path)] + extra_args
            print(f"\n🚀 Exécution : {' '.join(cmd)}")
            print("-" * 50)

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )

            if result.stdout:
                print("--- [STDOUT] ---")
                print(result.stdout)

            if result.stderr:
                print("--- [STDERR] ---")
                print(result.stderr)

            print(f"Code de sortie : {result.returncode}")
            print("-" * 50)

        except KeyboardInterrupt:
            print("\n\nInterruption par l'utilisateur. Au revoir !")
            break
        except Exception as e:
            print(f"❌ Erreur lors de l'exécution : {e}")

if __name__ == "__main__":
    main()
