import os
import ast

def scan_python_structure(root_dir):
    results = []

    for subdir, _, files in os.walk(root_dir):
        for filename in files:
            if filename.endswith(".py"):
                full_path = os.path.join(subdir, filename)
                relative_path = os.path.relpath(full_path, root_dir)
                try:
                    with open(full_path, "r", encoding="utf-8") as f:
                        content = f.read()
                        tree = ast.parse(content)
                        classes, functions = extract_structure(tree)
                        if classes or functions:
                            results.append(format_output(relative_path, classes, functions))
                except Exception as e:
                    print(f"[!] Error reading {relative_path}: {e}")

    return results

def extract_structure(tree):
    classes = []
    functions = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            classes.append(node.name)
        elif isinstance(node, ast.FunctionDef):
            functions.append(node.name)

    return classes, functions

def format_output(path, classes, functions):
    out = f"\n📁 {path}\n"
    if classes:
        out += f"  🔹 Classes:\n"
        for cls in classes:
            out += f"    - {cls}\n"
    if functions:
        out += f"  🔸 Functions:\n"
        for func in functions:
            out += f"    - {func}\n"
    return out

if __name__ == "__main__":
    folder_to_scan = "./"  # ili npr: "shadowfox18"
    output_path = "scan_report.txt"

    structure = scan_python_structure(folder_to_scan)
    with open(output_path, "w", encoding="utf-8") as f:
        f.writelines(structure)

    print(f"[✓] Scan completed. Output saved to {output_path}")
