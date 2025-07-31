import argparse
import math
import pefile
import hashlib
import os
from collections import Counter

# ======== Utility Functions ========
def shannon_entropy(data):
    """
    Calculate Shannon entropy of given data
    """
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    return -sum((count / length) * math.log2(count / length) for count in counter.values())

def get_hash_md5(data):
    """Return MD5 hash of data"""
    return hashlib.md5(data).hexdigest()

def get_hash_sha256(data):
    """Return SHA256 hash of data"""
    return hashlib.sha256(data).hexdigest()

# ======== File Analysis Functions ========
def analyze_file(path):
    with open(path, 'rb') as f:
        data = f.read()
        entropy = shannon_entropy(data)
    return data, entropy

# ======== Section Analysis ========
def analyze_sections(pe):
    sections_info = []
    for section in pe.sections:
        name = section.Name.decode('utf-8', errors='replace').strip('\x00')
        entropy = shannon_entropy(section.get_data())
        sections_info.append({
            'name': name,
            'md5': get_hash_md5(section.get_data()),
            'sha256': get_hash_sha256(section.get_data()),
            'entropy': entropy
        })
    return sections_info

# ======== Packer Check ========
def detect_packer(pe):
    packers = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore').lower()
            if 'upx' in dll or 'aspack' in dll:
                packers.append(dll)
    return packers

# ======== Import and Export Info ========
def get_imports(pe):
    imports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll = entry.dll.decode('utf-8', errors='ignore')
            for imp in entry.imports:
                if imp.name:
                    imports.append(f"{dll}:{imp.name.decode('utf-8', errors='ignore')}")
    return imports

def get_exports(pe):
    exports = []
    if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
            if exp.name:
                exports.append(exp.name.decode('utf-8', errors='ignore'))
    return exports

# ======== API Usage Detection ========
def detect_api_usage(pe):
    apis = set()
    if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            for imp in entry.imports:
                if imp.name:
                    apis.add(imp.name.decode('utf-8', errors='ignore'))
    return sorted(list(apis))

# ======== YARA Integration (Commented) ========
# def scan_with_yara(filepath):
#     import yara
#     rules = yara.compile(filepath='rules.yar')
#     matches = rules.match(filepath)
#     return matches

# ======== VirusTotal Integration (Commented) ========
# def virustotal_scan(filepath):
#     import requests
#     VT_API_KEY = 'YOUR_API_KEY'
#     with open(filepath, 'rb') as f:
#         files = {'file': (os.path.basename(filepath), f)}
#         headers = {'x-apikey': VT_API_KEY}
#         response = requests.post('https://www.virustotal.com/api/v3/files', files=files, headers=headers)
#     return response.json()

# ======== Main Report Generation ========
def generate_report(pe, path):
    filename = os.path.basename(path)
    base_name = os.path.splitext(filename)[0]

    data, file_entropy = analyze_file(path)
    sections_info = analyze_sections(pe)
    packers = detect_packer(pe)
    imports = get_imports(pe)
    exports = get_exports(pe)
    api_calls = detect_api_usage(pe)

    # YARA & VT placeholders
    yara_result = "[INFO] YARA scanning is disabled. Uncomment in code to enable."
    vt_result = "[INFO] VirusTotal scan is disabled. Uncomment in code to enable."

    # === Console Summary ===
    print("=== FILE ANALYSIS ===")
    print(f"MD5: {get_hash_md5(data)}")
    print(f"SHA256: {get_hash_sha256(data)}")
    print(f"Imphash: {pe.get_imphash()}")
    print(f"Entropy: {file_entropy:.4f}\n")

    print("=== SECTION STRUCTURE ===")
    for section in sections_info:
        print(f"{section['name']} => Imphash: {pe.get_imphash()} | MD5: {section['md5']} | SHA256: {section['sha256']} | Entropy: {section['entropy']:.4f}")
    # print(section.get_data())  # Uncomment to print raw data of section
    print()

    print("=== PACKER CHECK ===")
    if packers:
        print("Detected packer-related DLLs:", ", ".join(packers))
    else:
        print("No known packer signatures found")
    print()

    print("=== IMPORTED DLLS & FUNCTIONS ===")
    print(f"{len(set([imp.split(':')[0] for imp in imports]))} DLL(s) and {len(imports)} imported function(s)\n")

    print("=== EXPORTED FUNCTIONS ===")
    print(f"{len(exports)} exported function(s)\n")

    print("=== YARA SCAN ===")
    print(yara_result + "\n")

    print("=== VIRUSTOTAL SCAN ===")
    print(vt_result + "\n")

    print("=== SAVED Reports ===")
    print(f"[+] Saved full_report info to {base_name}_full_report.txt")
    print(f"[+] Saved sections info to {base_name}_sections.txt")
    print(f"[+] Saved imports info to {base_name}_imports.txt")
    print(f"[+] Saved exports info to {base_name}_exports.txt")
    print(f"[+] Saved virustotal info to {base_name}_virustotal.txt\n")

    # === Save Reports ===
    with open(f"{base_name}_full_report.txt", 'w') as f:
        f.write(f"FILE: {filename}\nMD5: {get_hash_md5(data)}\nSHA256: {get_hash_sha256(data)}\nImphash: {pe.get_imphash()}\nEntropy: {file_entropy:.4f}\n")

    with open(f"{base_name}_sections.txt", 'w') as f:
        for section in sections_info:
            f.write(f"{section['name']}\n")
            f.write(f"Available: ['md5', 'sha256', 'entropy']\n")

    with open(f"{base_name}_imports.txt", 'w') as f:
        for imp in imports:
            f.write(imp + "\n")

    with open(f"{base_name}_exports.txt", 'w') as f:
        for exp in exports:
            f.write(exp + "\n")

    with open(f"{base_name}_virustotal.txt", 'w') as f:
        f.write(vt_result + "\n")

# ======== Main Function ========
def main():
    parser = argparse.ArgumentParser(description="Comprehensive PE File Analyzer")
    parser.add_argument('-f', '--file', required=True, help="Path to PE file")
    args = parser.parse_args()

    try:
        pe = pefile.PE(args.file)
    except pefile.PEFormatError as e:
        print(f"Error: {e}")
        return

    generate_report(pe, args.file)

if __name__ == '__main__':
    main()
