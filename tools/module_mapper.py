import os
import re

PROJECT_ROOT = "."  # menjaš ako budeš hteo da pokrećeš iz drugog mesta
OUTPUT_FILE = "modules_summary.txt"

def extract_definitions_from_file(file_path):
    definitions = []
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        for line_num, line in enumerate(f, 1):
            match = re.match(r"\s*(async\s+def|def|class)\s+([a-zA-Z_][a-zA-Z0-9_]*)", line)
            if match:
                definitions.append((match.group(1), match.group(2), line_num))
    return definitions

def scan_project(root_dir):
    all_defs = []
    for dirpath, _, filenames in os.walk(root_dir):
        for file in filenames:
            if file.endswith(".py") and not file.startswith("__"):
                path = os.path.join(dirpath, file)
                module_path = os.path.relpath(path, root_dir).replace("/", ".").replace("\\", ".").rstrip(".py")
                defs = extract_definitions_from_file(path)
                for d in defs:
                    all_defs.append((module_path, d[0], d[1], d[2]))
    return all_defs

def write_summary(definitions):
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        for module, dtype, name, line in definitions:
            f.write(f"[{dtype.upper()}] {name} (line {line})  →  from {module} import {name}\n")
    print(f"[✓] Sačuvano u {OUTPUT_FILE} ({len(definitions)} elemenata)")

if __name__ == "__main__":
    defs = scan_project(PROJECT_ROOT)
    write_summary(defs)
