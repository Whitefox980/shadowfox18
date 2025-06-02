"""
GENERAL_SHADOW - AI Commander for ShadowFox System
Advanced AI that orchestrates the entire ShadowFox ecosystem
"""

import json
import sqlite3
import time
import threading
import asyncio
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from enum import Enum
import logging
import hashlib
import random
import sqlite3
import os
from pathlib import Path
from datetime import datetime

from ai_core.advanced_shadow_intelligence import AdvancedShadowIntelligence, QuantumShadowCore
MODULES_FILE = "modules_summary.txt"
DB_PATH = "core/shadowfox_core.db"
from ai_core.shadow_operator import ShadowFoxOperator
from agents.smart_shadow_agent import SmartShadowAgent
from agents.shadowx_agent import ShadowXAgent
from agents.most_advanced import CL0D_Neural_Core

# Dinamički ulaz (može i iz fajla)
target_data = {
    "target_url": input("🎯 Unesi metu: ").strip(),
    "mission_id": input("🧠 Unesi Mission ID: ").strip()
}

for agent in agents:
    activate_agent(agent, target_data)
class MissionPhase(Enum):
    RECON = "recon"
    ANALYSIS = "analysis"
    ATTACK = "attack"
    EXPLOITATION = "exploitation"
    STEALTH = "stealth"
    REPORTING = "reporting"

class ThreatLevel(Enum):
    MINIMAL = 1
    LOW = 2
    MODERATE = 3
    HIGH = 4
    CRITICAL = 5

class ConfidenceLevel(Enum):
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    ABSOLUTE = 4
class LearningMode(Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    AGGRESSIVE = "aggressive"


@dataclass
class TacticalDecision:
    phase: str
    modules: List[str]
    reasoning: str
    confidence: float
    expected_outcomes: List[str]
    fallback_plan: Optional[str] = None

@dataclass
class RealTimeIntel:
    """Real-time intelligence updates"""
    timestamp: float
    source: str
    intel_type: str
    data: Dict[str, Any]
    confidence: float
    verified: bool = False

@dataclass
class ModuleKnowledge:
    """Knowledge base for each module"""
    name: str
    functions: List[str]
    dataflows: List[str]
    dependencies: List[str]
    capabilities: List[str]
    best_use_cases: List[str]


@dataclass
class OperationalContext:
    phase: Optional[MissionPhase] = None
    modules: Optional[List[str]] = None
    reasoning: Optional[str] = None
    confidence: Optional[ConfidenceLevel] = None
    expected_outcomes: Optional[List[str]] = None
    fallback_plan: Optional[str] = None


    
    time_constraints: Optional[int] = None
    stealth_requirements: ThreatLevel = ThreatLevel.MODERATE
    noise_tolerance: float = 0.5
    success_threshold: float = 0.7
    learning_mode: LearningMode = LearningMode.ACTIVE
    backup_strategies: List[str] = field(default_factory=list)


@dataclass
class MissionIntelligence:
    """Collected intelligence about the target"""
    target_url: str
    technologies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    attack_surfaces: List[str] = field(default_factory=list)
    security_measures: List[str] = field(default_factory=list)
    confidence_score: float = 0.0

class GENERAL_SHADOW:
    """
    AI Commander that orchestrates the entire ShadowFox operation
    - Analyzes targets intelligently
    - Selects optimal modules and strategies
    - Manages data flows between components
    - Makes tactical decisions based on intelligence
    """
    
    def __init__(self):
        self.operator = ShadowFoxOperator()
        self.knowledge_base = self._build_knowledge_base()
        self.advanced_ai = AdvancedShadowIntelligence(self.knowledge_base)
        self.quantum_core = QuantumShadowCore()
        self.mission_intelligence = None
        self.active_modules = []
        self.tactical_history = []
        self.stealth_mode = True
        self.operational_context = OperationalContext()
        self.real_time_intel = []
        self.learning_database = {}
        self.threat_assessment = {}
        self.module_performance = {}
        self.adaptive_memory = {}
        self.mission_id = None
        self._setup_logging()
        self._init_adaptive_learning()
        self._start_intelligence_monitoring()
        
    def init_db():
        if not os.path.exists(DB_PATH):
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            c.execute('''
                CREATE TABLE mission_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    command TEXT,
                    result TEXT
                )
            ''')
            conn.commit()
            conn.close()
            print("🗄️  [DB] Kreirana nova baza shadowfox_core.db")
        else:
            print("✅ [DB] Baza već postoji.")

    def _init_adaptive_learning(self):
        print("[i] Adaptive learning init placeholder")
    def activate_agents(self):
        for agent in self.available_agents:
            self.operator.activate_agent(agent, self.target_url)
    def _start_intelligence_monitoring(self):
        print("[i] Intelligence monitoring placeholder aktiviran")
    def _setup_logging(self):
        """Setup logging for the AI commander"""
        logging.basicConfig(
            level=logging.INFO,
            format='[GENERAL_SHADOW] %(asctime)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger('GENERAL_SHADOW')
    def run(self):
        while True:
            command = input("🧠 GENERAL_SHADOW >> Unesi komandu (exit za kraj): ")
            if command.lower() == "exit":
                print("[-] Izlaz iz GENERAL_SHADOW moda.")
                break
            else:
                print(f"[~] Komanda '{command}' još nije implementirana.") 
    def load_modules():
        if not os.path.exists(MODULES_FILE):
            print(f"[!] Nema fajla {MODULES_FILE}")
            return []
        with open(MODULES_FILE, "r") as f:
            modules = [line.strip() for line in f.readlines() if line.strip()]
        print(f"📦 [LOADER] Učitano {len(modules)} modula.")
        return modules

    def process_command(cmd):
        print(f"🧠 [GENERAL] Izvršavam komandu: {cmd}")
        if cmd.startswith("moduli"):
            mods = load_modules()
            for m in mods:
                print(" -", m)
            log_command(cmd, f"{len(mods)} modula prikazano")
        elif cmd.startswith("log"):
            print("📜 [LOGOVI]")
            conn = sqlite3.connect(DB_PATH)
            c = conn.cursor()
            for row in c.execute('SELECT * FROM mission_log ORDER BY id DESC LIMIT 10'):
                print(f"[{row[0]}] {row[1]} => {row[2]}")
            conn.close()
            log_command(cmd, "Pregled logova")
        else:
            print("❓ Nepoznata komanda")
            log_command(cmd, "Nepoznata komanda")
    def log_command(command, result="OK"):
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute('''
            INSERT INTO mission_log (timestamp, command, result)
            VALUES (?, ?, ?)
        ''', (datetime.now().isoformat(), command, result))
        conn.commit()
        conn.close()
    
    def _build_knowledge_base(self) -> Dict[str, ModuleKnowledge]:
        """Build comprehensive knowledge base from scan reports"""
        knowledge = {}
        
        # Core System Modules
        knowledge['shadowfox_db'] = ModuleKnowledge(
            name="ShadowFox Database",
            functions=['log_recon_result', 'log_mutation', 'log_jwt_attack', 'log_ai_decision'],
            dataflows=['JSON_IO', 'SQLITE'],
            dependencies=['sqlite3'],
            capabilities=['data_persistence', 'mission_logging', 'intelligence_storage'],
            best_use_cases=['mission_tracking', 'result_correlation', 'learning_data']
        )
        
        knowledge['payload_library'] = ModuleKnowledge(
            name="Payload Library",
            functions=['get_payloads_by_type', 'add_custom_payload', 'get_top_payloads_by_success'],
            dataflows=['HTTP_REQUEST', 'JSON_IO', 'SQLITE'],
            dependencies=['sqlite3'],
            capabilities=['payload_management', 'success_tracking', 'adaptive_learning'],
            best_use_cases=['attack_optimization', 'payload_selection', 'success_analysis']
        )
        
        # Intelligence & Recon
        knowledge['recon_agent'] = ModuleKnowledge(
            name="Reconnaissance Agent", 
            functions=['analyze_target', '_detect_technologies', '_scan_common_ports', '_discover_endpoints'],
            dataflows=['HTTP_REQUEST', 'JSON_IO', 'FILE_IO'],
            dependencies=['requests'],
            capabilities=['target_analysis', 'technology_detection', 'surface_mapping'],
            best_use_cases=['initial_recon', 'target_profiling', 'attack_surface_discovery']
        )
        
        knowledge['pathfinder'] = ModuleKnowledge(
            name="AI Pathfinder",
            functions=['analyze_site_map', '_discover_all_urls', '_formulate_attack_strategy'],
            dataflows=['HTTP_REQUEST', 'JSON_IO', 'FILE_IO'],
            dependencies=['requests', 'beautifulsoup'],
            capabilities=['url_discovery', 'attack_surface_analysis', 'strategy_formulation'],
            best_use_cases=['comprehensive_mapping', 'strategic_planning', 'target_prioritization']
        )
        
        # Attack Modules
        knowledge['smart_shadow_agent'] = ModuleKnowledge(
            name="Smart Shadow Agent",
            functions=['attack_target', '_generate_smart_payloads', '_adapt_strategy'],
            dataflows=['HTTP_REQUEST', 'JSON_IO'],
            dependencies=['requests'],
            capabilities=['intelligent_attacks', 'adaptive_strategy', 'success_learning'],
            best_use_cases=['automated_exploitation', 'adaptive_attacks', 'intelligent_fuzzing']
        )
        
        knowledge['jwt_attack'] = ModuleKnowledge(
            name="JWT Attack Module",
            functions=['run_jwt_attack', 'attempt_none_algorithm', 'attempt_algorithm_confusion'],
            dataflows=['HTTP_REQUEST', 'JSON_IO', 'FILE_IO', 'SHELL_EXEC'],
            dependencies=['pyjwt', 'cryptography'],
            capabilities=['jwt_exploitation', 'algorithm_confusion', 'key_attacks'],
            best_use_cases=['jwt_vulnerabilities', 'token_manipulation', 'authentication_bypass']
        )
        
        knowledge['genetic_engine'] = ModuleKnowledge(
            name="Genetic WAF Bypass",
            functions=['create_initial_population', 'evolve_generation', 'adaptive_evolution'],
            dataflows=['HTTP_REQUEST'],
            dependencies=['genetic_algorithms'],
            capabilities=['waf_bypass', 'payload_evolution', 'adaptive_mutations'],
            best_use_cases=['waf_protected_targets', 'payload_optimization', 'evasion_techniques']
        )
        
        # Advanced AI Modules
        knowledge['cl0d_core'] = ModuleKnowledge(
            name="CL0D Neural Core",
            functions=['analyze_defense_response', 'calculate_adaptation_strategy', 'learn_from_response'],
            dataflows=['HTTP_REQUEST'],
            dependencies=['neural_networks'],
            capabilities=['defense_analysis', 'adaptive_learning', 'neural_mutations'],
            best_use_cases=['advanced_evasion', 'defense_adaptation', 'intelligent_mutations']
        )
        
        knowledge['xse_engine'] = ModuleKnowledge(
            name="XSE Strategic Engine",
            functions=['analyze_and_strategize', '_analyze_technology_risks', '_prioritize_strategies'],
            dataflows=['HTTP_REQUEST'],
            dependencies=['strategy_analysis'],
            capabilities=['strategic_analysis', 'risk_assessment', 'strategy_optimization'],
            best_use_cases=['mission_planning', 'risk_analysis', 'strategic_decisions']
        )
        
        # Stealth & Evasion
        knowledge['traffic_shaper'] = ModuleKnowledge(
            name="Traffic Shaper",
            functions=['make_stealthy_request', '_apply_rate_limiting', '_add_random_delay'],
            dataflows=['HTTP_REQUEST', 'FILE_IO'],
            dependencies=['requests', 'proxies'],
            capabilities=['stealth_requests', 'rate_limiting', 'proxy_rotation'],
            best_use_cases=['stealth_operations', 'evasion', 'traffic_obfuscation']
        )
        
        knowledge['shadow_proxy_master'] = ModuleKnowledge(
            name="Shadow Proxy Master",
            functions=['mutate_payload', '_ai_guided_mutations', '_waf_bypass_mutations'],
            dataflows=['HTTP_REQUEST', 'JSON_IO', 'FILE_IO'],
            dependencies=['proxy_systems'],
            capabilities=['proxy_management', 'payload_mutation', 'interception'],
            best_use_cases=['proxy_attacks', 'payload_modification', 'traffic_interception']
        )
        
        return knowledge
    
    def print_banner(self):
        """Display the AI Commander banner"""
        banner = """
╔═══════════════════════════════════════════════════════════════╗
║                      GENERAL_SHADOW                           ║
║                  AI Commander System                          ║
║                                                               ║
║  ┌─────────────────────────────────────────────────────────┐  ║
║  │  "I see all, I know all, I command all"                │  ║
║  │                                                         │  ║
║  │  • Strategic Intelligence Engine                       │  ║
║  │  • Autonomous Module Orchestration                     │  ║
║  │  • Adaptive Tactical Decision Making                   │  ║
║  └─────────────────────────────────────────────────────────┘  ║
╚═══════════════════════════════════════════════════════════════╝
"""
        print(banner)
        
    def analyze_target_intelligence(self, target_url: str) -> MissionIntelligence:
        """Conduct comprehensive target analysis using multiple intelligence sources"""
        self.logger.info(f"🔍 Analyzing target: {target_url}")
        
        # Initialize mission intelligence
        intelligence = MissionIntelligence(target_url=target_url)
        
        print(f"\n🎯 TARGET ANALYSIS: {target_url}")
        print("=" * 60)
        
        # Phase 1: Basic Reconnaissance
        print("\n📡 Phase 1: Basic Reconnaissance")
        recon_plan = self._plan_reconnaissance(target_url)
        print(f"   Strategy: {recon_plan.reasoning}")
        print(f"   Modules: {', '.join(recon_plan.modules)}")
        
        # Simulate recon results
        intelligence.technologies = ['nginx', 'php', 'mysql', 'wordpress']
        intelligence.attack_surfaces = ['web_forms', 'api_endpoints', 'file_uploads', 'admin_panel']
        intelligence.security_measures = ['basic_waf', 'rate_limiting']
        
        # Phase 2: Deep Analysis
        print("\n🧠 Phase 2: Deep Intelligence Analysis")
        analysis_plan = self._plan_deep_analysis(intelligence)
        print(f"   Strategy: {analysis_plan.reasoning}")
        print(f"   Modules: {', '.join(analysis_plan.modules)}")
        
        # Simulate vulnerability discovery
        intelligence.vulnerabilities = ['sql_injection', 'xss_reflected', 'file_inclusion']
        intelligence.confidence_score = 0.85
        
        # Phase 3: Strategic Assessment
        print("\n⚡ Phase 3: Strategic Assessment")
        self._display_intelligence_summary(intelligence)
        
        self.mission_intelligence = intelligence
        return intelligence
        
    def _plan_reconnaissance(self, target_url: str) -> TacticalDecision:
        """Plan reconnaissance phase using AI reasoning"""
        modules = ['recon_agent', 'pathfinder']
        
        reasoning = (
            "Initiating multi-vector reconnaissance. ReconAgent will perform basic "
            "target profiling and technology detection. Pathfinder will conduct "
            "comprehensive URL discovery and attack surface mapping."
        )
        
        return TacticalDecision(
            phase=MissionPhase.RECON,
            modules=modules,
            reasoning=reasoning,
            confidence=ConfidenceLevel.HIGH,
            expected_outcomes=['target_profile', 'technology_stack', 'attack_surfaces']
        )
        
    def _plan_deep_analysis(self, intelligence: MissionIntelligence) -> TacticalDecision:
        """Plan deep analysis based on initial intelligence"""
        modules = ['xse_engine']
        
        # AI reasoning based on discovered technologies
        if 'wordpress' in intelligence.technologies:
            modules.append('smart_shadow_agent')
        if 'php' in intelligence.technologies:
            modules.extend(['genetic_engine', 'cl0d_core'])
            
        reasoning = (
            f"Target runs {', '.join(intelligence.technologies)}. XSE Engine will "
            f"formulate strategic approach. Additional modules selected based on "
            f"technology stack analysis and attack surface assessment."
        )
        
        return TacticalDecision(
            phase=MissionPhase.ANALYSIS,
            modules=modules,
            reasoning=reasoning,
            confidence=ConfidenceLevel.HIGH,
            expected_outcomes=['vulnerability_assessment', 'attack_strategy', 'payload_recommendations']
        )
    
    def _display_intelligence_summary(self, intelligence: MissionIntelligence):
        """Display comprehensive intelligence summary"""
        print(f"\n📊 INTELLIGENCE SUMMARY")
        print(f"   Target: {intelligence.target_url}")
        print(f"   Confidence: {intelligence.confidence_score:.0%}")
        print(f"   Technologies: {', '.join(intelligence.technologies)}")
        print(f"   Attack Surfaces: {', '.join(intelligence.attack_surfaces)}")
        print(f"   Vulnerabilities: {', '.join(intelligence.vulnerabilities)}")
        print(f"   Security Measures: {', '.join(intelligence.security_measures)}")
        
    def formulate_attack_strategy(self) -> TacticalDecision:
        """Formulate comprehensive attack strategy based on intelligence"""
        if not self.mission_intelligence:
            raise ValueError("No mission intelligence available. Run target analysis first.")
            
        print(f"\n🎯 ATTACK STRATEGY FORMULATION")
        print("=" * 60)
        
        intelligence = self.mission_intelligence
        
        # AI strategic reasoning
        attack_modules = []
        reasoning_parts = []
        
        # Analyze vulnerabilities and select modules
        if 'sql_injection' in intelligence.vulnerabilities:
            attack_modules.extend(['smart_shadow_agent', 'genetic_engine'])
            reasoning_parts.append("SQL injection detected - deploying smart fuzzing with genetic evolution")
            
        if 'xss_reflected' in intelligence.vulnerabilities:
            attack_modules.append('cl0d_core')
            reasoning_parts.append("XSS vectors found - activating neural mutation engine")
            
        if 'basic_waf' in intelligence.security_measures:
            attack_modules.extend(['genetic_engine', 'traffic_shaper'])
            reasoning_parts.append("WAF detected - implementing genetic bypass with stealth traffic shaping")
            
        # JWT specific attacks
        if any('jwt' in tech.lower() for tech in intelligence.technologies):
            attack_modules.append('jwt_attack')
            reasoning_parts.append("JWT implementation detected - deploying specialized token attacks")
            
        # Remove duplicates while preserving order
        attack_modules = list(dict.fromkeys(attack_modules))
        
        reasoning = ". ".join(reasoning_parts)
        
        strategy = TacticalDecision(
            phase=MissionPhase.ATTACK,
            modules=attack_modules,
            reasoning=reasoning,
            confidence=ConfidenceLevel.HIGH,
            expected_outcomes=['vulnerability_exploitation', 'payload_success', 'access_gained'],
            fallback_plan="If primary attack fails, activate CL0D adaptive engine for defense analysis"
        )
        
        print(f"\n🧠 AI STRATEGIC REASONING:")
        print(f"   {strategy.reasoning}")
        print(f"\n⚔️  SELECTED ATTACK MODULES:")
        for module in strategy.modules:
            knowledge = self.knowledge_base.get(module, {})
            print(f"   • {knowledge.name if hasattr(knowledge, 'name') else module}")
            
        print(f"\n🎲 CONFIDENCE LEVEL: {strategy.confidence.name}")
        print(f"🔄 FALLBACK PLAN: {strategy.fallback_plan}")
        
        return strategy
    def execute_attack(self):
        self.set_strategy()  # postojeća funkcija
        self.activate_agents()  # nova linija
    def execute_stealth_operations(self) -> TacticalDecision:
        """Plan and execute stealth operations"""
        print(f"\n🥷 STEALTH OPERATIONS PLANNING")
        print("=" * 60)
        
        stealth_modules = ['traffic_shaper', 'shadow_proxy_master']
        
        reasoning = (
            "Activating comprehensive stealth protocol. Traffic Shaper will implement "
            "rate limiting, random delays, and proxy rotation. Shadow Proxy Master "
            "will handle payload obfuscation and traffic interception."
        )
        
        strategy = TacticalDecision(
            phase=MissionPhase.STEALTH,
            modules=stealth_modules,
            reasoning=reasoning,
            confidence=ConfidenceLevel.HIGH,
            expected_outcomes=['traffic_obfuscation', 'detection_evasion', 'stealth_persistence']
        )
        
        print(f"\n🧠 STEALTH REASONING:")
        print(f"   {strategy.reasoning}")
        print(f"\n🥷 STEALTH MODULES:")
        for module in strategy.modules:
            knowledge = self.knowledge_base.get(module, {})
            print(f"   • {knowledge.name if hasattr(knowledge, 'name') else module}")
            
        return strategy
        
    def generate_mission_report(self) -> Dict[str, Any]:
        """Generate comprehensive mission report"""
        print(f"\n📋 MISSION REPORT GENERATION")
        print("=" * 60)
        
        if not self.mission_intelligence:
            print("❌ No mission data available for reporting")
            return {}
            
        report = {
            'mission_id': f"SHADOW_{int(time.time())}",
            'target': self.mission_intelligence.target_url,
            'intelligence': {
                'technologies': self.mission_intelligence.technologies,
                'vulnerabilities': self.mission_intelligence.vulnerabilities,
                'attack_surfaces': self.mission_intelligence.attack_surfaces,
                'confidence_score': self.mission_intelligence.confidence_score
            },
            'tactical_decisions': len(self.tactical_history),
            'modules_deployed': len(set(sum([d.modules for d in self.tactical_history], []))),
            'success_indicators': ['vulnerability_confirmed', 'payload_executed', 'access_achieved'],
            'recommendations': [
                'Implement input validation',
                'Deploy advanced WAF rules',
                'Enable comprehensive logging',
                'Regular security assessments'
            ]
        }
        
        print(f"📊 MISSION STATISTICS:")
        print(f"   Mission ID: {report['mission_id']}")
        print(f"   Target: {report['target']}")
        print(f"   Confidence: {report['intelligence']['confidence_score']:.0%}")
        print(f"   Tactical Decisions: {report['tactical_decisions']}")
        print(f"   Modules Deployed: {report['modules_deployed']}")
        
        return report
        
    def interactive_command_mode(self):
        """Interactive command mode for user interaction"""
        self.print_banner()
        
        while True:
            print(f"\n🎯 GENERAL_SHADOW COMMAND CENTER")
            print("=" * 50)
            print("1. 🔍 Analyze Target")
            print("2. ⚔️  Formulate Attack Strategy") 
            print("3. 🥷 Execute Stealth Operations")
            print("4. 📋 Generate Mission Report")
            print("5. 🧠 Show Knowledge Base")
            print("6. 📊 Mission Status")
            print("0. 🚪 Exit")
            
            choice = input(f"\n👤 Commander, your orders: ").strip()
            
            if choice == '1':
                target = input("🎯 Enter target URL: ").strip()
                if target:
                    intelligence = self.analyze_target_intelligence(target)
                    decision = input(f"\n🤔 Proceed with analysis? (y/n): ").strip().lower()
                    if decision == 'y':
                        self.tactical_history.append(self._plan_reconnaissance(target))
                        print("✅ Analysis completed and logged")
            elif choice == '2':
                if self.mission_intelligence:
                    self.strategy = self.formulate_attack_strategy()
                    decision = input(f"\n⚔️  Execute attack strategy? (y/n): ").strip().lower()
                    if decision == 'y':
            # POZOVI OPERATORA
                        from ai_core.shadow_operator import ShadowFoxOperator
                        operator = ShadowFoxOperator()
                        mission_id = operator.create_mission(
                           self.mission_intelligence['target_url'],
                           "Napad preko GENERALA"
                        )
                        operator.execute_mission(mission_id)

                        self.tactical_history.append(self.strategy)
                        print("✅ Attack strategy deployed via Shadow Operator")
                else:
                    print("❌ No target analyzed. Run target analysis first.")        
                    
            elif choice == '3':
                stealth_strategy = self.execute_stealth_operations()
                decision = input(f"\n🤔 Activate stealth operations? (y/n): ").strip().lower()
                if decision == 'y':
                    self.tactical_history.append(stealth_strategy)
                    print("✅ Stealth operations activated")
                    
            elif choice == '4':
                report = self.generate_mission_report()
                if report:
                    save_report = input(f"\n💾 Save report to file? (y/n): ").strip().lower()
                    if save_report == 'y':
                        with open(f"mission_report_{report['mission_id']}.json", 'w') as f:
                            json.dump(report, f, indent=2)
                        print(f"✅ Report saved as mission_report_{report['mission_id']}.json")
                        
            elif choice == '5':
                self._display_knowledge_base()
                
            elif choice == '6':
                self._display_mission_status()
                
            elif choice == '0':
                print("🫡 GENERAL_SHADOW signing off. Mission complete.")
                break
            elif choice == '7':
                self._display_mission_report_summary()    
            else:
                print("❌ Invalid command. Try again.")
                
    def _display_knowledge_base(self):
        """Display knowledge base summary"""
        print(f"\n🧠 KNOWLEDGE BASE SUMMARY")
        print("=" * 60)
        for name, knowledge in self.knowledge_base.items():
            print(f"\n📦 {knowledge.name}")
            print(f"   Capabilities: {', '.join(knowledge.capabilities)}")
            print(f"   Best Use: {', '.join(knowledge.best_use_cases)}")

    def _display_mission_report_summary(self):
        import json
        import glob

        print("\n🧠 MISSION REPORT SUMMARY")
        try:
            report_files = sorted(glob.glob("mission_report_*.json"), reverse=True)
            if not report_files:
                print("⚠️  No reports found.")
                return

            with open(report_files[0], "r") as f:
                report = json.load(f)

            print(f"\n📄 Mission ID: {report['mission_id']}")
            print(f"🎯 Target: {report['target']}")
            print(f"📊 Confidence: {int(report['intelligence']['confidence_score'] * 100)}%")
            print(f"🧠 Technologies: {', '.join(report['intelligence']['technologies'])}")
            print(f"💥 Vulnerabilities: {', '.join(report['intelligence']['vulnerabilities'])}")
            print(f"🎯 Attack Surfaces: {', '.join(report['intelligence']['attack_surfaces'])}")
            print(f"🧰 Modules Deployed: {report['modules_deployed']}")
            print(f"📌 Tactical Decisions: {report['tactical_decisions']}")
            print(f"✅ Success Indicators: {', '.join(report.get('success_indicators', []))}")
            print(f"🛡️ Recommendations: {', '.join(report.get('recommendations', []))}")

        except Exception as e:
            print(f"❌ Error reading report: {e}")

    def _display_mission_status(self):
        """Display current mission status"""
        print(f"\n📊 MISSION STATUS")
        print("=" * 60)
        
        if self.mission_intelligence:
            print(f"🎯 Current Target: {self.mission_intelligence.target_url}")
            print(f"📈 Intelligence Confidence: {self.mission_intelligence.confidence_score:.0%}")
        else:
            print("🎯 No active mission")
            
        print(f"⚔️  Tactical Decisions Made: {len(self.tactical_history)}")
        print(f"🔧 Active Modules: {len(self.active_modules)}")
        print(f"🥷 Stealth Mode: {'ACTIVE' if self.stealth_mode else 'INACTIVE'}")
def start_console():
    print("🧠 [GENERAL] Konzola pokrenuta. Kucaj komandu (moduli, log, exit):")
    while True:
        try:
            cmd = input(">> ").strip()
            if cmd.lower() in ("exit", "quit"):
                print("👋 Zatvaram konzolu...")
                break
            process_command(cmd)
        except Exception as e:
            print(f"[ERROR] {e}")
from ai_core.GENERAL_SHADOW import GENERAL_SHADOW
def main():
    """Main entry point"""
    general = GENERAL_SHADOW()
    general.interactive_command_mode()

if __name__ == "__main__":
    main()
    print("🧠 [GENERAL SHADOW] Pokrećem komandni centar...")
    init_db()
    load_modules()
    monitor_missions()
    start_console()
