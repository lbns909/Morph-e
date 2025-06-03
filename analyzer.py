# analyzer.py
import re
from collections import defaultdict
from datetime import datetime
import os
import sys
import importlib.util

REPORT_FILE = "report.txt"


def import_utils():
    try:
        current_dir = os.path.dirname(__file__)
    except NameError:
        current_dir = os.getcwd()

    utils_path = os.path.join(current_dir, "utils.py")
    if not os.path.exists(utils_path):
        raise FileNotFoundError(f"Le fichier utils.py est introuvable à l'emplacement : {utils_path}")

    spec = importlib.util.spec_from_file_location("utils", utils_path)
    utils = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(utils)
    return utils


def explain_alerts(suspicious_activity):
    explanations = {
        "Brute Force": "Plusieurs tentatives de connexion avec des erreurs 401 indiquent une attaque par force brute.",
        "Scan": "Accès à plusieurs ressources différentes en peu de temps indique un scan de répertoire ou de vulnérabilité.",
        "Accès interdit": "Réponses 403 fréquentes : tentative d'accès à des ressources restreintes."
    }
    exp_text = "\nExplication des alertes:\n"
    for category in suspicious_activity:
        exp_text += f"- {category} : {explanations.get(category, 'Activité suspecte détectée.')}\n"
    return exp_text


def analyze_log(log_file):
    utils = import_utils()
    parse_log_line = utils.parse_log_line
    detect_suspicious_behavior = utils.detect_suspicious_behavior

    suspicious_activity = defaultdict(list)

    try:
        with open(log_file, 'r') as logfile:
            for line in logfile:
                data = parse_log_line(line)
                if not data:
                    continue
                alerts = detect_suspicious_behavior(data)
                for alert in alerts:
                    suspicious_activity[alert].append(data)
    except FileNotFoundError:
        print(f"Fichier non trouvé : {log_file}")
        return

    with open(REPORT_FILE, 'w') as report:
        report.write(f"Rapport de détection - {datetime.now()}\n\n")
        for category, entries in suspicious_activity.items():
            report.write(f"[ALERTE] {category} : {len(entries)} occurrences\n")
            for entry in entries:
                report.write(f"  - {entry['ip']} accède {entry['url']} (code {entry['status']})\n")
            report.write("\n")
        report.write(explain_alerts(suspicious_activity))

    print("\nContenu du rapport:\n")
    with open(REPORT_FILE, 'r') as report:
        print(report.read())


def archive_report():
    archive_dir = "archives"
    os.makedirs(archive_dir, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    archived_file = os.path.join(archive_dir, f"report_{timestamp}.txt")
    os.rename(REPORT_FILE, archived_file)
    print(f"Rapport archivé dans : {archived_file}")


def display_menu():
    menu = r"""
    ==========================
        A N A L Y Z E   L O G
    ==========================

    1. Analyser les logs
    2. Archiver le rapport
    3. Quitter
    """
    print(menu)


def main():
    analyzed = False
    while True:
        display_menu()
        choice = input("Choisissez une option (1-3) : ")

        if choice == "1":
            file_path = input("Entrez le chemin du fichier de log à analyser : ").strip()
            if not os.path.isfile(file_path):
                print("Erreur : le fichier spécifié n'existe pas\n")
                continue
            analyze_log(file_path)
            analyzed = True
        elif choice == "2":
            if not analyzed:
                print("Veuillez d'abord analyser un fichier de log avant d'archiver.\n")
            else:
                archive_report()
                print("Au revoir !")
                break
        elif choice == "3":
            print("Au revoir !")
            break
        else:
            print("Option invalide, veuillez réessayer.\n")


if __name__ == "__main__":
    main()
