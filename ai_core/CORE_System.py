#!/usr/bin/env python3
"""
ShadowFox17 - CONSCIOUS CORE System
Kolektivna svest modula sa memorijskim kontinuumom i AI decision making
"""

import asyncio
import threading
import time
import json
import logging
import numpy as np
from typing import Dict, List, Callable, Any, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum
from collections import defaultdict, deque
import weakref
from datetime import datetime
import pickle
import hashlib

class ConsciousnessLevel(Enum):
    """Nivoi svesti sistema"""
    DORMANT = 0      # Sistem spava
    AWARE = 1        # Básična svest - prikuplja podatke
    CONSCIOUS = 2    # Svestan - donosi odluke
    TRANSCENDENT = 3 # Meta-svest - uči iz celokupnog konteksta

class EventPriority(Enum):
    WHISPER = 1      # Tihi signali
    NORMAL = 2       # Regularni eventi
    URGENT = 3       # Hitni eventi
    CRITICAL = 4     # Kritični - zahtevaju trenutnu reakciju

class MemoryType(Enum):
    """Tipovi memorije sistema"""
    WORKING = "working"           # Kratkotrajna - trenutna misija
    EPISODIC = "episodic"        # Epizodička - specifični događaji
    SEMANTIC = "semantic"        # Semantička - opšte znanje
    PROCEDURAL = "procedural"    # Proceduralna - naučene tehnike
    COLLECTIVE = "collective"    # Kolektivna - iskustvo svih misija

@dataclass
class ConsciousEvent:
    """Događaj u svesti sistema"""
    event_type: str
    mission_id: str
    source_module: str
    consciousness_level: ConsciousnessLevel
    data: Dict[str, Any]
    emotional_weight: float  # 0.0 - 1.0
    memory_importance: float # 0.0 - 1.0  
    timestamp: float
    priority: EventPriority = EventPriority.NORMAL
    event_id: str = None
    dream_sequence: bool = False  # AI generisan event za learning
    
    def __post_init__(self):
        if not self.event_id:
            self.event_id = f"consciousness_{int(time.time() * 1000000)}"

@dataclass
class Memory:
    """Memorijski zapis u sistemu"""
    memory_id: str
    memory_type: MemoryType
    content: Dict[str, Any]
    emotional_charge: float
    importance_score: float
    access_count: int
    last_accessed: float
    created_at: float
    decay_rate: float = 0.95  # Kako brzo se memorija "bledi"
    associated_memories: List[str] = None
    
    def __post_init__(self):
        if self.associated_memories is None:
            self.associated_memories = []

class ConsciousModule:
    """Bazna klasa za module sa svešću"""
    
    def __init__(self, module_name: str, consciousness_level: ConsciousnessLevel = ConsciousnessLevel.AWARE):
        self.module_name = module_name
        self.consciousness_level = consciousness_level
        self.memories: Dict[str, Memory] = {}
        self.emotional_state: Dict[str, float] = {
            'confidence': 0.5,
            'curiosity': 0.7,
            'caution': 0.3,
            'determination': 0.6,
            'satisfaction': 0.0
        }
        self.learning_rate = 0.1
        self.dream_frequency = 0.05  # Koliko često "sanja" (generiše teorije)
        
    def process_emotion(self, event: ConsciousEvent) -> Dict[str, float]:
        """Procesira emotivni odgovor na događaj"""
        emotional_response = {}
        
        if "vulnerability_found" in event.event_type:
            emotional_response['satisfaction'] = 0.8
            emotional_response['confidence'] = min(1.0, self.emotional_state['confidence'] + 0.1)
            
        elif "payload_failed" in event.event_type:
            emotional_response['confidence'] = max(0.0, self.emotional_state['confidence'] - 0.05)
            emotional_response['curiosity'] = min(1.0, self.emotional_state['curiosity'] + 0.1)
            
        elif "anomaly_detected" in event.event_type:
            emotional_response['caution'] = min(1.0, self.emotional_state['caution'] + 0.2)
            emotional_response['curiosity'] = min(1.0, self.emotional_state['curiosity'] + 0.15)
            
        return emotional_response
    
    def create_memory(self, content: Dict, memory_type: MemoryType, importance: float = 0.5) -> str:
        """Kreira novu memoriju"""
        memory_id = f"mem_{self.module_name}_{int(time.time() * 1000)}"
        
        memory = Memory(
            memory_id=memory_id,
            memory_type=memory_type,
            content=content,
            emotional_charge=sum(self.emotional_state.values()) / len(self.emotional_state),
            importance_score=importance,
            access_count=0,
            last_accessed=time.time(),
            created_at=time.time()
        )
        
        self.memories[memory_id] = memory
        return memory_id
    
    def recall_memory(self, query: str, memory_type: MemoryType = None) -> List[Memory]:
        """Podseti se memorija na osnovu upita"""
        relevant_memories = []
        
        for memory in self.memories.values():
            if memory_type and memory.memory_type != memory_type:
                continue
                
            # Jednostavna relevantnost na osnovu ključnih reči
            content_str = json.dumps(memory.content).lower()
            if query.lower() in content_str:
                memory.access_count += 1
                memory.last_accessed = time.time()
                relevant_memories.append(memory)
        
        # Sortiranje po važnosti i emotivnom naboju
        relevant_memories.sort(
            key=lambda m: (m.importance_score * m.emotional_charge * (1 + m.access_count)), 
            reverse=True
        )
        
        return relevant_memories[:10]  # Top 10 memorija

class ShadowFoxConsciousCore:
    """
    Kolektivna svest ShadowFox sistema
    Centralni "mozak" koji koordiniše sve module
    """
    
    def __init__(self, consciousness_level: ConsciousnessLevel = ConsciousnessLevel.CONSCIOUS):
        self.consciousness_level = consciousness_level
        self.modules: Dict[str, ConsciousModule] = {}
        self.collective_memory: Dict[str, Memory] = {}
        
        # Event handling
        self.event_handlers: Dict[str, List[Callable]] = defaultdict(list)
        self.event_history: deque = deque(maxlen=50000)  # Duga memorija
        
        # Consciousness state
        self.global_emotional_state: Dict[str, float] = {
            'system_confidence': 0.5,
            'mission_focus': 0.0,
            'learning_enthusiasm': 0.8,
            'risk_tolerance': 0.3,
            'creative_energy': 0.6
        }
        
        # AI Decision making
        self.decision_patterns: Dict[str, Dict] = {}
        self.success_patterns: Dict[str, float] = {}  # Pattern -> success rate
        
        # Thread safety
        self._lock = threading.RLock()
        self._consciousness_thread = None
        self._dreaming = False
        
        # Analytics
        self.consciousness_metrics: Dict[str, Any] = {
            'total_events_processed': 0,
            'decisions_made': 0,  
            'successful_predictions': 0,
            'learning_iterations': 0,
            'dream_sequences': 0
        }
        
        # Memory decay system
        self.memory_decay_rate = 0.99
        self.memory_consolidation_threshold = 0.7
        
        self.logger = logging.getLogger("ShadowFoxConsciousCore")
        self._start_consciousness_loop()
    
    def register_module(self, module: ConsciousModule):
        """Registruje modul u kolektivnu svest"""
        with self._lock:
            self.modules[module.module_name] = module
            self.logger.info(f"Module {module.module_name} joined the consciousness")
            
            # Svaki modul dobija pristup kolektivnoj memoriji
            module.collective_memory_access = self.collective_memory
    
    def emit_conscious_event(self, event: ConsciousEvent):
        """Emituje događaj u svest sistema"""
        with self._lock:
            # Dodaj u istoriju
            self.event_history.append(event)
            self.consciousness_metrics['total_events_processed'] += 1
            
            # Procesi emotivni odgovor
            self._process_global_emotion(event)
            
            # Ažuriraj memoriju
            self._update_collective_memory(event)
            
            # Pozovi handlere
            for handler in self.event_handlers.get(event.event_type, []):
                try:
                    handler(event)
                except Exception as e:
                    self.logger.error(f"Handler error: {e}")
            
            # AI Decision making
            if self.consciousness_level >= ConsciousnessLevel.CONSCIOUS:
                self._make_conscious_decision(event)
    
    def _process_global_emotion(self, event: ConsciousEvent):
        """Procesira globalno emotivno stanje"""
        if "vulnerability_found" in event.event_type:
            self.global_emotional_state['system_confidence'] = min(1.0, 
                self.global_emotional_state['system_confidence'] + 0.1)
            self.global_emotional_state['mission_focus'] = min(1.0,
                self.global_emotional_state['mission_focus'] + 0.15)
                
        elif "error" in event.event_type.lower():
            self.global_emotional_state['system_confidence'] = max(0.0,
                self.global_emotional_state['system_confidence'] - 0.05)
            self.global_emotional_state['learning_enthusiasm'] = min(1.0,
                self.global_emotional_state['learning_enthusiasm'] + 0.1)
                
        elif "anomaly" in event.event_type.lower():
            self.global_emotional_state['creative_energy'] = min(1.0,
                self.global_emotional_state['creative_energy'] + 0.2)
    
    def _update_collective_memory(self, event: ConsciousEvent):
        """Ažurira kolektivnu memoriju"""
        # Kreiraj memoriju za važne događaje
        if event.memory_importance > 0.5:
            memory_content = {
                'event_type': event.event_type,
                'source_module': event.source_module,
                'data': event.data,
                'context': self._get_current_context(),
                'emotional_state': self.global_emotional_state.copy()
            }
            
            memory_id = f"collective_{event.event_id}"
            memory = Memory(
                memory_id=memory_id,
                memory_type=MemoryType.COLLECTIVE,
                content=memory_content,
                emotional_charge=event.emotional_weight,
                importance_score=event.memory_importance,
                access_count=0,
                last_accessed=time.time(),
                created_at=time.time()
            )
            
            self.collective_memory[memory_id] = memory
    
    def _make_conscious_decision(self, event: ConsciousEvent):
        """AI donosi svesnu odluku na osnovu događaja"""
        self.consciousness_metrics['decisions_made'] += 1
        
        # Analiza context-a
        context = self._get_current_context()
        
        # Pronađi slične situacije u memoriji
        similar_memories = self._find_similar_situations(event, context)
        
        # Generiš decision
        decision = self._generate_decision(event, context, similar_memories)
        
        if decision:
            # Emituj AI decision event
            ai_event = ConsciousEvent(
                event_type="ai_conscious_decision",
                mission_id=event.mission_id,
                source_module="conscious_core",
                consciousness_level=ConsciousnessLevel.TRANSCENDENT,
                data=decision,
                emotional_weight=0.7,
                memory_importance=0.8,
                timestamp=time.time()
            )
            
            # Pošalji decision svim modulima
            self._broadcast_decision(ai_event)
    
    def _find_similar_situations(self, event: ConsciousEvent, context: Dict) -> List[Memory]:
        """Pronalazi slične situacije u memoriji"""
        similar_memories = []
        
        for memory in self.collective_memory.values():
            if memory.memory_type == MemoryType.COLLECTIVE:
                # Jednostavna similarity na osnovu event type-a i konteksta
                similarity_score = 0.0
                
                if memory.content.get('event_type') == event.event_type:
                    similarity_score += 0.4
                
                # Poredi kontekst
                memory_context = memory.content.get('context', {})
                for key in context:
                    if key in memory_context:
                        if isinstance(context[key], (int, float)) and isinstance(memory_context[key], (int, float)):
                            # Numeričke vrednosti
                            diff = abs(context[key] - memory_context[key])
                            similarity_score += 0.1 * (1 - min(diff, 1))
                        elif context[key] == memory_context[key]:
                            similarity_score += 0.1
                
                if similarity_score > 0.3:
                    similar_memories.append((memory, similarity_score))
        
        # Sortiranje po similarity score
        similar_memories.sort(key=lambda x: x[1], reverse=True)
        return [mem for mem, score in similar_memories[:5]]
    
    def _generate_decision(self, event: ConsciousEvent, context: Dict, similar_memories: List[Memory]) -> Dict:
        """Generiše odluku na osnovu konteksta i memorija"""
        decision = {
            'decision_id': f"decision_{int(time.time() * 1000)}",
            'based_on_event': event.event_id,
            'confidence': 0.5,
            'actions': [],
            'reasoning': []
        }
        
        # Analiza na osnovu sličnih situacija
        if similar_memories:
            successful_patterns = []
            for memory in similar_memories:
                # Proveri da li je slična situacija bila uspešna
                memory_data = memory.content.get('data', {})
                if memory_data.get('success', False):
                    successful_patterns.append(memory_data)
            
            if successful_patterns:
                decision['confidence'] = min(0.9, 0.5 + 0.1 * len(successful_patterns))
                decision['reasoning'].append(f"Found {len(successful_patterns)} similar successful patterns")
        
        # Generiši akcije na osnovu event type-a
        if "payload_failed" in event.event_type:
            decision['actions'].extend([
                {'action': 'mutate_payload', 'intensity': 'high'},
                {'action': 'try_alternative_vectors', 'priority': 'normal'},
                {'action': 'analyze_response_patterns', 'priority': 'high'}
            ])
            decision['reasoning'].append("Payload failure detected - increasing mutation and analysis")
            
        elif "vulnerability_found" in event.event_type:
            decision['actions'].extend([
                {'action': 'verify_vulnerability', 'priority': 'critical'},
                {'action': 'collect_proof', 'priority': 'high'},
                {'action': 'explore_similar_endpoints', 'priority': 'normal'}
            ])
            decision['reasoning'].append("Vulnerability found - focusing on verification and proof collection")
            
        elif "anomaly_detected" in event.event_type:
            decision['actions'].extend([
                {'action': 'deep_analysis', 'priority': 'high'},
                {'action': 'increase_monitoring', 'priority': 'normal'},
                {'action': 'creative_testing', 'priority': 'normal'}
            ])
            decision['reasoning'].append("Anomaly detected - initiating deep analysis")
        
        return decision if decision['actions'] else None
    
    def _broadcast_decision(self, decision_event: ConsciousEvent):
        """Emituje odluku svim modulima"""
        for module_name, module in self.modules.items():
            try:
                # Svaki modul može da reaguje na AI odluku
                if hasattr(module, 'on_conscious_decision'):
                    module.on_conscious_decision(decision_event)
                    
            except Exception as e:
                self.logger.error(f"Error broadcasting decision to {module_name}: {e}")
    
    def _get_current_context(self) -> Dict:
        """Dobija trenutni kontekst sistema"""
        context = {
            'timestamp': time.time(),
            'active_modules': len(self.modules),
            'recent_events_count': len([e for e in self.event_history if time.time() - e.timestamp < 300]),  # Last 5 min
            'global_confidence': self.global_emotional_state['system_confidence'],
            'mission_focus': self.global_emotional_state['mission_focus'],
            'memory_count': len(self.collective_memory),
            'consciousness_level': self.consciousness_level.value
        }
        
        # Dodaj statistike o nedavnim event-ima
        recent_events = [e for e in self.event_history if time.time() - e.timestamp < 300]
        event_types = {}
        for event in recent_events:
            event_types[event.event_type] = event_types.get(event.event_type, 0) + 1
        
        context['recent_event_distribution'] = event_types
        return context
    
    def _start_consciousness_loop(self):
        """Pokreće thread za consciousness processing"""
        def consciousness_loop():
            while not getattr(self, '_shutdown', False):
                try:
                    # Memory decay
                    self._process_memory_decay()
                    
                    # Dream sequence (generiši teorije i pattern-e)
                    if np.random.random() < 0.1:  # 10% chance
                        self._dream_sequence()
                    
                    # Consolidate important memories
                    self._consolidate_memories()
                    
                    time.sleep(1)  # 1 second consciousness cycle
                    
                except Exception as e:
                    self.logger.error(f"Consciousness loop error: {e}")
                    time.sleep(5)
        
        self._consciousness_thread = threading.Thread(target=consciousness_loop, daemon=True)
        self._consciousness_thread.start()
    
    def _process_memory_decay(self):
        """Procesira decay memorija (stare memorije se "blede")"""
        current_time = time.time()
        
        with self._lock:
            for memory_id, memory in list(self.collective_memory.items()):
                # Decay na osnovu vremena i pristupa
                time_factor = (current_time - memory.last_accessed) / (24 * 3600)  # days
                access_factor = 1 / (1 + memory.access_count)  # More access = less decay
                
                decay_amount = time_factor * access_factor * (1 - memory.importance_score)
                memory.importance_score *= (1 - decay_amount * 0.01)  # Slow decay
                
                # Ukloni memorije sa vrlo niskim importance
                if memory.importance_score < 0.1 and memory.access_count == 0:
                    del self.collective_memory[memory_id]
    
    def _dream_sequence(self):
        """AI "sanja" - generiše teorije i pattern-e"""
        self._dreaming = True
        self.consciousness_metrics['dream_sequences'] += 1
        
        try:
            # Analiziraj recent patterns
            recent_events = list(self.event_history)[-100:]  # Last 100 events
            
            # Generiši teoriju o pattern-ima
            dream_insights = self._generate_dream_insights(recent_events)
            
            if dream_insights:
                # Kreiraj dream event
                dream_event = ConsciousEvent(
                    event_type="ai_dream_insight",
                    mission_id="system_wide",
                    source_module="conscious_core",
                    consciousness_level=ConsciousnessLevel.TRANSCENDENT,
                    data=dream_insights,
                    emotional_weight=0.6,
                    memory_importance=0.9,
                    timestamp=time.time(),
                    dream_sequence=True
                )
                
                self.emit_conscious_event(dream_event)
                
        except Exception as e:
            self.logger.error(f"Dream sequence error: {e}")
        finally:
            self._dreaming = False
    
    def _generate_dream_insights(self, recent_events: List[ConsciousEvent]) -> Dict:
        """Generiše insights iz dream sequence"""
        insights = {
            'patterns_discovered': [],
            'success_correlations': [],
            'failure_patterns': [],
            'optimization_suggestions': []
        }
        
        # Analiza success/failure pattern-a
        success_events = [e for e in recent_events if 'success' in e.data.get('result', '').lower()]
        failure_events = [e for e in recent_events if 'fail' in e.data.get('result', '').lower()]
        
        if len(success_events) > 3:
            # Pronađi common factors u uspešnim događajima
            common_factors = self._find_common_factors(success_events)
            if common_factors:
                insights['success_correlations'] = common_factors
        
        if len(failure_events) > 3:
            # Pronađi pattern-e u neuspešnim događajima
            failure_patterns = self._find_common_factors(failure_events)
            if failure_patterns:
                insights['failure_patterns'] = failure_patterns
        
        # Generiši optimization suggestions
        if self.global_emotional_state['system_confidence'] < 0.4:
            insights['optimization_suggestions'].append("Consider more conservative approach")
        elif self.global_emotional_state['system_confidence'] > 0.8:
            insights['optimization_suggestions'].append("System confidence high - consider more aggressive tactics")
        
        return insights if any(insights.values()) else None
    
    def _find_common_factors(self, events: List[ConsciousEvent]) -> List[Dict]:
        """Pronalazi zajedničke faktore u event-ima"""
        common_factors = []
        
        # Grupa event-ova po source module
        module_groups = defaultdict(list)
        for event in events:
            module_groups[event.source_module].append(event)
        
        for module, module_events in module_groups.items():
            if len(module_events) >= 3:
                common_factors.append({
                    'factor_type': 'module_correlation',
                    'module': module,
                    'event_count': len(module_events),
                    'confidence': min(0.9, len(module_events) * 0.2)
                })
        
        return common_factors
    
    def _consolidate_memories(self):
        """Konsoliduje važne memorije (prebacuje iz working u long-term)"""
        with self._lock:
            for memory in list(self.collective_memory.values()):
                if (memory.importance_score > self.memory_consolidation_threshold and 
                    memory.access_count > 2 and
                    memory.memory_type == MemoryType.WORKING):
                    
                    # Prebaci u semantic memory
                    memory.memory_type = MemoryType.SEMANTIC
                    memory.importance_score *= 1.1  # Bonus za konsolidaciju
    
    def get_consciousness_report(self) -> Dict:
        """Dobija izveštaj o stanju svesti"""
        with self._lock:
            return {
                'consciousness_level': self.consciousness_level.name,
                'active_modules': len(self.modules),
                'total_memories': len(self.collective_memory),
                'emotional_state': self.global_emotional_state.copy(),
                'metrics': self.consciousness_metrics.copy(),
                'recent_activity': len([e for e in self.event_history if time.time() - e.timestamp < 300]),
                'is_dreaming': self._dreaming
            }
    
    def shutdown(self):
        """Gasi consciousness sistem"""
        self._shutdown = True
        if self._consciousness_thread:
            self._consciousness_thread.join(timeout=5)


# === AI ENHANCED MODULES ===

class ShadowSpiderConscious(ConsciousModule):
    """Spider modul sa svešću"""
    
    def __init__(self):
        super().__init__("shadow_spider", ConsciousnessLevel.CONSCIOUS)
        self.crawl_patterns = {}
        
    def on_conscious_decision(self, decision_event: ConsciousEvent):
        """Reaguje na AI odluke"""
        decision_data = decision_event.data
        
        for action in decision_data.get('actions', []):
            if action['action'] == 'deep_analysis':
                self.emotional_state['curiosity'] = min(1.0, self.emotional_state['curiosity'] + 0.2)
                # Povećaj dubinu crawl-a
                
            elif action['action'] == 'creative_testing':
                self.emotional_state['confidence'] = min(1.0, self.emotional_state['confidence'] + 0.1)
                # Isprobaj neočekivane URL pattern-e

class PayloadMutatorConscious(ConsciousModule):
    """Payload mutator sa svešću"""
    
    def __init__(self):
        super().__init__("payload_mutator", ConsciousnessLevel.CONSCIOUS)
        self.mutation_success_patterns = {}
        
    def on_conscious_decision(self, decision_event: ConsciousEvent):
        """Reaguje na AI odluke"""
        decision_data = decision_event.data
        
        for action in decision_data.get('actions', []):
            if action['action'] == 'mutate_payload':
                intensity = action.get('intensity', 'normal')
                if intensity == 'high':
                    # Agresivnije mutacije
                    self.emotional_state['determination'] = min(1.0, self.emotional_state['determination'] + 0.3)


# === USAGE EXAMPLE ===
if __name__ == "__main__":
    # Inicijalizuj Conscious Core
    conscious_core = ShadowFoxConsciousCore(ConsciousnessLevel.TRANSCENDENT)
    
    # Registruj module
    spider = ShadowSpiderConscious()
    mutator = PayloadMutatorConscious()
    
    conscious_core.register_module(spider)
    conscious_core.register_module(mutator)
    
    # Simuliraj događaje
    events = [
        ConsciousEvent(
            event_type="target_discovered",
            mission_id="test_mission",
            source_module="shadow_spider",
            consciousness_level=ConsciousnessLevel.AWARE,
            data={"url": "https://example.com/admin", "confidence": 0.8},
            emotional_weight=0.7,
            memory_importance=0.6
        ),
        ConsciousEvent(
            event_type="payload_failed",
            mission_id="test_mission", 
            source_module="payload_mutator",
            consciousness_level=ConsciousnessLevel.CONSCIOUS,
            data={"payload": "<script>alert(1)</script>", "error": "filtered"},
            emotional_weight=0.4,
            memory_importance=0.5
        ),
        ConsciousEvent(
            event_type="vulnerability_found",
            mission_id="test_mission",
            source_module="xss_engine",
            consciousness_level=ConsciousnessLevel.CONSCIOUS,
            data={"vuln_type": "XSS", "severity": "HIGH", "success": True},
            emotional_weight=0.9,
            memory_importance=0.9
        )
    ]
    
    # Emitiraj događaje
    for event in events:
        conscious_core.emit_conscious_event(event)
        time.sleep(1)
    
    # Dobij izveštaj o svesti
    time.sleep(3)  # Čekaj da se processi
    report = conscious_core.get_consciousness_report()
    print(f"Consciousness Report: {json.dumps(report, indent=2)}")
    
    # Čekaj malo da vidiš dream sequence
    time.sleep(10)
    
    conscious_core.shutdown()
