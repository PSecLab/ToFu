#!/usr/bin/env python3
"""
Planificateur & Exécuteur de Fuzzing à distance pour PMB (Personal Memory Bank).

Calcule le temps total disponible entre l'instant présent et le Lundi 17 août 2026 à 06:00:00 (Heure de New York),
découvre l'intégralité des 68 outils MCP exposés par PMB, et alloue un temps égal à chaque outil.
"""

import os
import sys
import time
import argparse
import subprocess
from datetime import datetime
try:
    import zoneinfo
except ImportError:
    from backports import zoneinfo

# Ajout du chemin du module pmb au path python
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "third_party", "pmb", "src")))

def get_pmb_tools():
    """Extrait dynamiquement la liste complète des 68 outils de PMB."""
    try:
        from pmb.mcp.tools import register_all
        class DummyMCP:
            def __init__(self):
                self.tools = []
            def tool(self):
                def decorator(fn):
                    self.tools.append(fn.__name__)
                    return fn
                return decorator
        dummy = DummyMCP()
        register_all(dummy, engine=None)
        return sorted(dummy.tools)
    except Exception as e:
        print(f"[ERROR] Impossible de charger les outils PMB : {e}")
        sys.exit(1)

def get_remaining_seconds_until(target_dt: datetime) -> float:
    """Calcule le nombre de secondes restantes jusqu'à la date/heure cible (en tenant compte des fuseaux horaires)."""
    ny_tz = zoneinfo.ZoneInfo("America/New_York")
    now_ny = datetime.now(ny_tz)
    if target_dt.tzinfo is None:
        target_dt = target_dt.replace(tzinfo=ny_tz)
    return (target_dt - now_ny).total_seconds()

def main():
    parser = argparse.ArgumentParser(description="Planificateur et exécuteur de fuzzing pour PMB (68 outils)")
    parser.add_argument("--safety-margin-mins", type=int, default=15, help="Marge de sécurité en minutes (défaut: 15 min)")
    parser.add_argument("--target-date", type=str, default="2026-08-17 06:00:00", help="Date de fin au format YYYY-MM-DD HH:MM:SS (heure de NY)")
    parser.add_argument("--dry-run", action="store_true", help="Affiche le planning détaillé sans exécuter le fuzzing")
    args = parser.parse_args()

    ny_tz = zoneinfo.ZoneInfo("America/New_York")
    try:
        target_dt = datetime.strptime(args.target_date, "%Y-%m-%d %H:%M:%S").replace(tzinfo=ny_tz)
    except ValueError as e:
        print(f"[ERROR] Format de date invalide: {e}")
        sys.exit(1)

    rem_sec = get_remaining_seconds_until(target_dt)
    if rem_sec <= 0:
        print(f"[ERROR] La date cible ({target_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}) est déjà dépassée !")
        sys.exit(1)

    effective_sec = rem_sec - (args.safety_margin_mins * 60)
    if effective_sec <= 0:
        print(f"[ERROR] La marge de sécurité ({args.safety_margin_mins} min) dépasse le temps restant disponible.")
        sys.exit(1)

    tools = get_pmb_tools()
    total_tools = len(tools)

    sec_per_tool = effective_sec / total_tools
    mins_per_tool = sec_per_tool / 60.0
    hours_per_tool = mins_per_tool / 60.0

    now_ny = datetime.now(ny_tz)
    print("=" * 80)
    print("      PLANIFICATION DU FUZZING DISTANT POUR PMB (PERSONAL MEMORY BANK)")
    print("=" * 80)
    print(f"Heure de lancement (NY)  : {now_ny.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"Date/Heure de fin (NY)   : {target_dt.strftime('%Y-%m-%d %H:%M:%S %Z')}")
    print(f"Temps brut disponible    : {rem_sec/3600.0:.2f} heures ({rem_sec/86400.0:.2f} jours)")
    print(f"Marge de sécurité        : {args.safety_margin_mins} minutes")
    print(f"Nombre total d'outils PMB: {total_tools}")
    print(f"Temps alloué PAR OUTIL   : {sec_per_tool:.0f} secondes (~{mins_per_tool:.1f} min / {hours_per_tool:.2f}h)")
    print("=" * 80)

    print("\n--- Planning chronologique du fuzzing des 68 outils ---")
    cumul_sec = 0
    for idx, tool_name in enumerate(tools, 1):
        t_start = datetime.fromtimestamp(now_ny.timestamp() + cumul_sec, tz=ny_tz)
        cumul_sec += sec_per_tool
        t_end = datetime.fromtimestamp(now_ny.timestamp() + cumul_sec, tz=ny_tz)
        print(f" [{idx:02d}/{total_tools}] {tool_name:<32} : {t_start.strftime('%d/%m %H:%M')} -> {t_end.strftime('%d/%m %H:%M')} ({mins_per_tool:.1f} min)")

    if args.dry_run:
        print("\n[INFO] Mode --dry-run activé. Aucun fuzzing n'a été exécuté.")
        return

    print("\n[START] Lancement de la campagne de fuzzing sur PMB...")
    target_script = os.path.join(os.path.dirname(__file__), "targets", "fuzz_pmb.py")

    for idx, tool_name in enumerate(tools, 1):
        print("\n" + "#" * 80)
        print(f"   [{idx}/{total_tools}] DÉBUT FUZZING PMB OUTIL: '{tool_name}' ({sec_per_tool:.0f}s / ~{mins_per_tool:.1f}m)")
        print("#" * 80)

        cmd = [
            sys.executable,
            target_script if os.path.exists(target_script) else os.path.join("targets", "fuzz_pmb.py"),
            "--single-tool", tool_name,
            "--max-time-per-target-sec", str(int(sec_per_tool))
        ]

        try:
            start_t = time.time()
            res = subprocess.run(cmd, check=False)
            elapsed = time.time() - start_t
            print(f"[END] Outil '{tool_name}' terminé avec code de retour {res.returncode} en {elapsed:.1f}s.")
        except Exception as e:
            print(f"[ERROR] Échec lors de l'exécution pour l'outil '{tool_name}': {e}")

    print("\n[COMPLETED] Campagne de fuzzing pour l'intégralité des 68 outils de PMB terminée avec succès !")

if __name__ == "__main__":
    main()
