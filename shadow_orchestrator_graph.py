import importlib
import json
import sys

def dynamic_import(module_path, class_name=None):
    module = importlib.import_module(module_path)
    if class_name:
        return getattr(module, class_name)
    return module

def resolve_args(args, context):
    return [context.get(arg.strip("{}"), arg) for arg in args]

def run_mission(mission_file="mission_flow.json"):
    # Učitavanje toka misije
    with open(mission_file, "r") as f:
        mission_steps = json.load(f)

    context = {}
    for i, step in enumerate(mission_steps, 1):
        module_path = step["module"]
        func_name = step["function"]
        args = step.get("args", [])
        cls_name = step.get("class", None)

        try:
            # Import modula i funkcije ili metode iz klase
            if cls_name:
                cls = dynamic_import(module_path, cls_name)
                instance = cls()
                func = getattr(instance, func_name)
            else:
                mod = dynamic_import(module_path)
                func = getattr(mod, func_name)

            # Rešavanje argumenata iz konteksta
            resolved_args = resolve_args(args, context)

            print(f"[{i}] ▶️ Pokrećem {module_path}.{func_name}...")
            result = func(*resolved_args)

            # Ako je rezultat dict/list/string, sačuvaj ga u context
            if isinstance(result, (dict, list, str, int, float)):
                context[func_name] = result

        except Exception as e:
            print(f"[{i}] ❌ Greška u {module_path}.{func_name}: {e}")
            sys.exit(1)

    print("\n✅ Misija završena.")
    return context


if __name__ == "__main__":
    run_mission()
