import os
import ast

SCAN_ROOTS = ["logic", "core", "agents", "ai_core", "tools", "recon", "dash", "db"]
OUTPUT_FILE = "dataflow_summary.txt"

DATAFLOW_KEYWORDS = {
    "open": "FILE_IO",
    "read": "FILE_IO",
    "write": "FILE_IO",
    "json.load": "JSON_IO",
    "json.dump": "JSON_IO",
    "sqlite3.connect": "SQLITE",
    "TinyDB": "TINYDB",
    "requests.get": "HTTP_REQUEST",
    "requests.post": "HTTP_REQUEST",
    "subprocess": "SHELL_EXEC",
    "os.system": "SHELL_EXEC",
    "ChatCompletion.create": "OPENAI_API",
    "get": "HTTP_REQUEST",
    "post": "HTTP_REQUEST"
}

def detect_dataflow(path):
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        try:
            tree = ast.parse(f.read(), filename=path)
        except SyntaxError:
            return []

    matches = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            if hasattr(node.func, 'attr'):
                try:
                    base = getattr(node.func.value, 'id', '') or getattr(node.func.value, 'attr', '')
                    full_name = f"{base}.{node.func.attr}"
                except:
                    continue
            else:
                full_name = getattr(node.func, 'id', '')
            for key in DATAFLOW_KEYWORDS:
                if key in full_name:
                    matches.append((path, key, DATAFLOW_KEYWORDS[key]))
    return matches

def main():
    results = []
    for folder in SCAN_ROOTS:
        for root, _, files in os.walk(folder):
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    findings = detect_dataflow(full_path)
                    results.extend(findings)

    with open(OUTPUT_FILE, "w") as out:
        grouped = {}
        for filepath, call, tag in results:
            if filepath not in grouped:
                grouped[filepath] = []
            grouped[filepath].append(f"{call} → [{tag}]")
        
        for file, calls in grouped.items():
            out.write(f"{file}:\n")
            for call in sorted(set(calls)):
                out.write(f"  {call}\n")
            out.write("\n")
    print(f"[✓] Dataflow završen → {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
