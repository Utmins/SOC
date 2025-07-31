# ================================
# ByteScope — Binary File Analyzer
# Поддерживает PE-анализ, YARA, VT, экспорт отчётов
# ================================

import os
import sys
import hashlib
import pefile
import magic
import math
import yara
import requests
import mimetypes
import fnmatch
import shutil
import datetime
import random
import importlib.util
import subprocess
from datetime import date
from datetime import datetime
from pathlib import Path
from math import log2
from tkinter import filedialog, Tk
from typing import Union
from rich import print
from rich.prompt import Prompt, Confirm
from rich.console import Console
from rich.progress import track

# ========= БАННЕР =========
# Попытка загрузить pyfiglet и случайно выбрать шрифт, если не установлен — резервный ASCII
try:
    import pyfiglet
    figlet_fonts = pyfiglet.getFonts()
    font = random.choice(figlet_fonts) if figlet_fonts else "doh"
    banner = pyfiglet.figlet_format("ByteScope", font=font)
except ImportError:
    banner = r"""
  ____        _        ____                      
 | __ )  ___ | |_ __ _| __ )  ___  __ _ ___  ___ 
 |  _ \ / _ \| __/ _ |  _ \ / _ \/ _ / __|/ _ \
 | |_) | (_) | || (_| | |_) |  __/ (_| \__ \  __/
 |____/ \___/ \__\__,_|____/ \___|\__,_|___/\___|
"""

# ========= МОДУЛЬНАЯ ПРОВЕРКА =========
# Проверяет наличие модуля без импорта
def check_module(module_name):
    spec = importlib.util.find_spec(module_name)
    return spec is not None

# ========= ENTROPY CALCULATION =========
# Для байтов — классическая формула
def get_entropy(data):
    if not data:
        return 0.0
    entropy = 0
    for x in range(256):
        p_x = float(data.count(bytes([x]))) / len(data)
        if p_x > 0:
            entropy -= p_x * math.log2(p_x)
    return entropy

# Для строк — Шенноновская энтропия
def shannon_entropy(string):
    if not string:
        return 0.0
    entropy = 0
    length = len(string)
    symbols = set(string)
    for symbol in symbols:
        p = float(string.count(symbol)) / length
        entropy -= p * math.log2(p)
    return entropy

# Универсальная функция: автоматически выбирает способ расчета
def calculate_entropy(data):
    if isinstance(data, bytes):
        return get_entropy(data)
    elif isinstance(data, str):
        return shannon_entropy(data)
    return 0.0

# ========= FILE HASHING + ENTROPY =========
# Возвращает MD5, SHA256 и общую энтропию
def hash_file(path):
    with open(path, "rb") as f:
        data = f.read()
    return (
        hashlib.md5(data).hexdigest(),
        hashlib.sha256(data).hexdigest(),
        calculate_entropy(data),
    )

# ========= SECTION STRUCTURE =========
# Выводит хэши и энтропию каждой секции PE
def section_hashes(pe):
    result = ""
    for section in pe.sections:
        name = section.Name.decode().strip("\x00")
        md5 = hashlib.md5(section.get_data()).hexdigest()
        sha256 = hashlib.sha256(section.get_data()).hexdigest()
        entropy = calculate_entropy(section.get_data())
        result += f"[{name}]\n"
        result += f"\tMD5:\t\t{md5}\n"
        result += f"\tSHA256:\t\t{sha256}\n"
        result += f"\tEntropy:\t{entropy}\n"
    return result

# ========= PACKER CHECK =========
# Поиск секций с признаками упаковки (UPX и др.)
def check_packer(pe):
    known_packers = ["UPX", "MPRESS", "ASPack", "Themida", "FSG", "MEW"]
    packer_found = []
    for section in pe.sections:
        name = section.Name.decode(errors="ignore").strip("\x00")
        if any(packer.lower() in name.lower() for packer in known_packers):
            packer_found.append(name)
    return packer_found

# ========= IMPORTED FUNCTIONS =========
# Извлекает DLL и функции, импортируемые исполняемым файлом
def extract_imports(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return [], []
    dlls = [entry.dll.decode() for entry in pe.DIRECTORY_ENTRY_IMPORT]
    functions = []
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        for imp in entry.imports:
            if imp.name:
                functions.append(imp.name.decode())
    return dlls, functions

# ========= EXPORTED FUNCTIONS =========
# Извлекает экспортируемые функции (если есть)
def extract_exports(pe):
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return []
    return [exp.name.decode() for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols if exp.name]

# ========= YARA SCAN =========
# Выполняет сканирование по YARA правилам (автоматическое/ручное, файл/директория)
def check_yargen_installed():
    try:
        subprocess.run(["yarGen", "-h"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return True
    except FileNotFoundError:
        return False

def generate_yargen_rule(file_path, output_dir):
    base_name = os.path.basename(file_path)
    date = datetime.datetime.now().strftime("%Y-%m-%d")
    rule_filename = os.path.join(output_dir, f"{base_name}_yargen_rule_{date}.yar")
    subprocess.run(["yarGen", "-f", file_path, "-o", rule_filename], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return rule_filename

def run_yara_scan(rule_paths, target_file, output_path, tag, saved_reports):
    if isinstance(rule_paths, str):
        rule_paths = [rule_paths]
    matches = []
    
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Path to binary file")
    args = parser.parse_args()
    filepath = args.file
    filename = Path(filepath).stem
    
    for rule_file in rule_paths:
        try:
            rules = yara.compile(filepath=rule_file)
            match = rules.match(filepath=target_file)
            if match:
                matches.extend([str(m) for m in match])
        except Exception as e:
            print(f"[!] Error compiling {rule_file}: {e}")
    result_file = os.path.join(output_path, f"{filename}_yarascan_{tag}_{date.today().strftime('%d%m%Y')}.txt")
    with open(result_file, "w") as f:
        if matches:
            f.write(f"Matches found:\n" + "\t\n".join(matches) + "\n")
            saved_reports.append(str(result_file))
        else:
            f.write("No YARA rule matches found.")
    return matches


def find_yara_rules(path, category_filter=""):
    matched_files = []
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith((".yar", ".yara")):
                if category_filter.lower() in file.lower() or not category_filter:
                    matched_files.append(os.path.join(root, file))
    return matched_files

def yara_scan_interactive(file_path, output_dir, saved_reports):
    print("\n========== YARA SCAN ==========")
    choice = input("Do you want to use automatic YARA rule generation or your own rules? (for automatic type – yarGen, for personal type – own): ").strip().lower()
    
    if choice == "yargen":
        if check_yargen_installed():
            rule_file = generate_yargen_rule(file_path, output_dir)
            return run_yara_scan(rule_file, file_path, output_dir, "yargen")
            saved_reports.append(str(file_path))
        else:
            print("The utility for automatic generation of YARA rules was not found in the system. Please install it and try again later.")
            alt = input("Do you want to use your own YARA rules? (yes/no): ").strip().lower()
            if alt == "yes":
                own_rules_path = input("Enter the path to YARA rules (file or folder): ").strip()
                own_rules_path = os.path.expanduser(own_rules_path or ".")
                handle_own_yara_rules(own_rules_path, file_path, output_dir, saved_reports)
                saved_reports.append(str(file_path))
            else:
                print("No YARA rules provided")
    elif choice == "own":
        own_rules_path = input("Enter the path to YARA rules (file or folder): ").strip()
        own_rules_path = os.path.expanduser(own_rules_path or ".")
        return handle_own_yara_rules(own_rules_path, file_path, output_dir, saved_reports)
        saved_reports.append(str(file_path))
    else:
        print("Invalid choice. Skipping YARA scan.")
        print("No YARA rules provided")

def handle_own_yara_rules(path, file_path, output_dir, saved_reports):
    if os.path.isfile(path):
        return run_yara_scan(path, file_path, output_dir, "yarown", saved_reports)
    elif os.path.isdir(path):
        rule_files = find_yara_rules(path)
        print(f"Found {len(rule_files)} YARA rule files in the selected folder.")
        if rule_files:
            # Сбор категорий на основе имён файлов (без расширений)
            categories = sorted(set(Path(f).stem for f in rule_files))
            formatted = ", ".join(f"*{c}*" for c in categories)
            cat_filter = input(f"Please enter YARA rules category ({formatted} or press Enter to use all): ").strip()
            if cat_filter:
                filtered = find_yara_rules(path, cat_filter)
                if not filtered:
                    print(f"No matching YARA rules found for filter '{cat_filter}'. All rules will be used.")
                    filtered = rule_files
            else:
                filtered = rule_files
            return run_yara_scan(filtered, file_path, output_dir, "yarown", saved_reports)
        else:
            print("No valid YARA rule files found in the folder. Skipping.")
    else:
        print("Invalid YARA rule path provided.")
    return []

# ========= VIRUSTOTAL NOTICE =========
# Сообщение-заглушка при отсутствии API-ключа
def virustotal_scan_notice():
    return "To get results from VirusTotal, you must provide an API key."

# ========= ОТЧЁТЫ =========
# Создание директории для отчетов
def generate_report_dir(out_dir, file_name):
    report_dir = os.path.join(out_dir, f"{file_name}_CodeAnalysisReports")
    os.makedirs(report_dir, exist_ok=True)
    return report_dir

# Сохранение отчёта
def save_report(path, content):
    with open(path, "w") as f:
        f.write(content)

# ========= MAIN FUNCTION =========
def main():
    print(banner)
    check_module("yara")

    # Парсинг аргументов
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("-f", "--file", required=True, help="Path to binary file")
    args = parser.parse_args()
    filepath = args.file
    filename = Path(filepath).stem

    # Доступные функции
    options = [
        "FILE ANALYSIS",
        "SECTION STRUCTURE",
        "PACKER CHECK",
        "IMPORTED DLLS & FUNCTIONS",
        "EXPORTED FUNCTIONS",
        "API FUNCTIONS USED",
        "YARA SCAN",
        "VIRUSTOTAL SCAN",
    ]

    # Меню выбора функций
    print("Select the functions to perform (e.g., 1,3,5 or 2-4 or all):\n")
    for i, opt in enumerate(options, 1):
        print(f"{i}. {opt}")
    print()
    selection = input("Your selection: ").strip()

    # Обработка выбора пользователя
    selected = set()
    if selection.lower() == "all":
        selected = set(range(1, len(options) + 1))
    else:
        for part in selection.split(","):
            if "-" in part:
                start, end = map(int, part.split("-"))
                selected.update(range(start, end + 1))
            else:
                selected.add(int(part))

    # Ввод путей
    out_dir = input("\nWhere would you like to save the reports? (Leave empty to use current directory): ").strip()
    out_dir = os.path.expanduser(out_dir or ".")
    yara_path = input("Enter the path to YARA rules (file or folder): ").strip()
    yara_path = os.path.expanduser(yara_path or ".")
#    vt_key = input("Enter your VirusTotal API key: ").strip()

    report_dir = generate_report_dir(out_dir, filename)
    saved_reports = []
    pe = pefile.PE(filepath)
    full_report = ""

    # ========== FILE ANALYSIS ==========
    if 1 in selected:
        md5, sha256, entropy = hash_file(filepath)
        filetype = magic.from_file(filepath)
        imphash = pe.get_imphash()
        full_report += "\n=== FILE ANALYSIS ===\n"
        full_report += f"\nFile:\t\t{filepath}\n"
        full_report += f"Type:\t\t{filetype}\n"
        full_report += f"MD5:\t\t{md5}\n"
        full_report += f"SHA256:\t\t{sha256}\n"
        full_report += f"Imphash:\t{imphash}\n"
        full_report += f"Entropy:\t{entropy}\n\n"

    # ========== SECTION STRUCTURE ==========
    if 2 in selected:
        full_report += "=== SECTION STRUCTURE ===\n"
        full_report += section_hashes(pe) + "\n"

    # ========== PACKER CHECK ==========
    if 3 in selected:
        full_report += "=== PACKER CHECK ===\n"
        found = check_packer(pe)
        if found:
            full_report += "Possible packer-related sections found:\n"
            for f in found:
                full_report += f"- {f}\n"
        else:
            full_report += "No known packer signatures found.\n"

    # ========== IMPORTED FUNCTIONS ==========
    if 4 in selected:
        dlls, funcs = extract_imports(pe)
        full_report += "\n=== IMPORTED DLLS & FUNCTIONS ===\n"
        full_report += f"Imported DLLs: {len(dlls)}\n"
        full_report += f"Imported Functions: {len(funcs)}\n"

        # Стилистика отчета
        dlls_sorted = sorted(set(dlls))
        funcs_sorted = sorted(set(funcs))

        import_report_content = "DLLs:\n"
        import_report_content += "\n".join(f"    {dll}" for dll in dlls_sorted)
        import_report_content += "\n\nFunctions:\n"
        import_report_content += "\n".join(f"    {func}" for func in funcs_sorted)

        path = os.path.join(report_dir, f"{filename}_import_report_{date.today().strftime('%d%m%Y')}.txt")
        save_report(path, import_report_content)
        saved_reports.append(path)

    # ========== EXPORTED FUNCTIONS ==========
    if 5 in selected:
        exports = extract_exports(pe)
        full_report += "\n=== EXPORTED FUNCTIONS ===\n"
        full_report += f"Exported Functions: {len(exports)}\n"
        path = os.path.join(report_dir, f"{filename}_export_report_{date.today().strftime('%d%m%Y')}.txt")
        save_report(path, "\n".join(exports))
        saved_reports.append(path)

    # ========== API FUNCTIONS USED ==========
    if 6 in selected:
        _, funcs = extract_imports(pe)
        apis = sorted(set(funcs))
        full_report += "\n=== API FUNCTIONS USED ===\n"
        full_report += f"Unique API functions: {len(apis)}\n"
        path = os.path.join(report_dir, f"{filename}_api_report_{date.today().strftime('%d%m%Y')}.txt")
        save_report(path, "\n".join(apis))
        saved_reports.append(path)

    # ========== YARA SCAN ==========
    if 7 in selected:
        full_report += "\n=== YARA SCAN ===\n"
        if yara_path:
            if check_module("yara"):
                matches = yara_scan_interactive(filepath, report_dir, saved_reports)
                if matches:
                    full_report += f"YARA Matches: {len(matches)}\n"
                else:
                    full_report += "YARA Matches: None\n"
            else:
                full_report += "YARA module not installed.\n"
        else:
            full_report += "No YARA rules provided.\n"

    # ========== VIRUSTOTAL SCAN ==========
    if 8 in selected:
        full_report += "\n=== VIRUSTOTAL SCAN ===\n"
        vt_key = input("\nEnter your VirusTotal API key: ").strip()
        if vt_key:
            full_report += "VirusTotal integration not yet implemented.\n"
        else:
            full_report += virustotal_scan_notice() + "\n"

    # ========= СОХРАНЕНИЕ ПОЛНОГО ОТЧЁТА =========
    full_report_path = os.path.join(report_dir, f"{filename}_full_report_{date.today().strftime('%d%m%Y')}.txt")
    save_report(full_report_path, full_report)
    saved_reports.append(full_report_path)
    
    # ========= ОТЧЁТ О СОХРАНЕННЫХ ФАЙЛАХ =========
    if saved_reports:
        full_report += "\n=== SAVED REPORTS ===\n"
        for path in saved_reports:
            full_report += f"[+] {path}\n"

    # ========= ВЫВОД НА ЭКРАН =========
    print(full_report)

# ========= Точка входа =========
if __name__ == "__main__":
    main()


