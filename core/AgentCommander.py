# core/AgentCommander.py
import asyncio

def activate_agent(agent, target_data: dict):
    try:
        name = agent.__class__.__name__.lower()
        print(f"[⚡] Activating: {name}")

        url = target_data.get("target_url", "")
        mission_id = target_data.get("mission_id", "")

        if name == "smartshadowagent" and hasattr(agent, "attack_target"):
            agent.attack_target(target_data, ["SQLi", "SSRF", "XSS", "LFI", "CommandInjection"])

        elif name == "shadowxagent" and hasattr(agent, "analyze_and_attack"):
            agent.analyze_and_attack(url)

        elif name in ["mostadvanced", "cl0d_neural_core"] and hasattr(agent, "execute_adaptive_attack"):
            asyncio.run(agent.execute_adaptive_attack(url, mission_id))

        else:
            print(f"❌ No known method to activate agent: {name}")

    except Exception as e:
        print(f"💥 Error while executing agent {name}: {e}")
