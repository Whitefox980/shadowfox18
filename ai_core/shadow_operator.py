#!/usr/bin/env python3
"""
ShadowFox17 - Shadow Operator
Centralna komanda za upravljanje agentima i taskovima sa AI orchestration
"""

import asyncio
import threading
import time
import json
import uuid
import logging
from typing import Dict, List, Any, Optional, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
from collections import defaultdict, deque
from queue import Queue, PriorityQueue
import concurrent.futures
import weakref
from agents.smart_shadow_agent import agent_callback as smart_shadow_callback
from agents.shadowx_agent import agent_callback as shadowx_callback
from agents.most_advanced import agent_callback as advanced_callback

class TaskStatus(Enum):
    PENDING = "pending"
    ASSIGNED = "assigned"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"

class TaskPriority(Enum):
    LOW = 1
    NORMAL = 2
    HIGH = 3
    CRITICAL = 4

class AgentStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    OFFLINE = "offline"
    INITIALIZING = "initializing"

class TaskType(Enum):
    RECON = "recon"
    FUZZ = "fuzz"
    EXPLOIT = "exploit"
    MUTATION = "mutation"
    ANALYSIS = "analysis"
    PROXY = "proxy"
    INTELLIGENCE = "intelligence"
    PAYLOAD_GEN = "payload_generation"
    VULNERABILITY_SCAN = "vulnerability_scan"

@dataclass
class ShadowTask:
    task_id: str
    task_type: TaskType
    mission_id: str
    priority: TaskPriority
    payload: Dict[str, Any]
    requirements: Dict[str, Any] = field(default_factory=dict)
    timeout: float = 300.0  # 5 minuta default
    retry_count: int = 0
    max_retries: int = 3
    created_at: float = field(default_factory=time.time)
    assigned_at: Optional[float] = None
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    status: TaskStatus = TaskStatus.PENDING
    assigned_agent: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    dependencies: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    
    def __lt__(self, other):
        # Za PriorityQueue - viši prioritet ide prvi
        return self.priority.value > other.priority.value

@dataclass
class ShadowAgent:
    agent_id: str
    agent_type: str
    module_name: str
    capabilities: List[TaskType]
    status: AgentStatus = AgentStatus.INITIALIZING
    current_task: Optional[str] = None
    total_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    avg_execution_time: float = 0.0
    last_heartbeat: float = field(default_factory=time.time)
    max_concurrent_tasks: int = 1
    current_load: int = 0
    specialization_score: Dict[TaskType, float] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    callback_handler: Optional[Callable] = None
    
    def can_handle_task(self, task: ShadowTask) -> bool:
        """Proverava da li agent može da izvršava task"""
        return (task.task_type in self.capabilities and 
                self.status == AgentStatus.IDLE and
                self.current_load < self.max_concurrent_tasks)
    
    def get_fitness_score(self, task: ShadowTask) -> float:
        """Računa fitness score za task assignment"""
        base_score = self.specialization_score.get(task.task_type, 0.5)
        
        # Bonus za success rate
        success_rate = self.successful_tasks / max(self.total_tasks, 1)
        success_bonus = success_rate * 0.3
        
        # Penalizacija za load
        load_penalty = (self.current_load / self.max_concurrent_tasks) * 0.2
        
        # Bonus za brzinu izvršavanja
        speed_bonus = max(0, (60.0 - self.avg_execution_time) / 60.0) * 0.2
        
        return base_score + success_bonus - load_penalty + speed_bonus

class ShadowFoxOperator:
    """
    Centralni operator za upravljanje ShadowFox agentima
    Koordinira taskove, agente i AI decision making
    """
    
    def __init__(self, shadowfox_db=None, event_bus=None, max_concurrent_tasks: int = 50):
        self.agents: Dict[str, ShadowAgent] = {}
        self.tasks: Dict[str, ShadowTask] = {}
        self.task_queue = PriorityQueue()
        self.completed_tasks: deque = deque(maxlen=1000)
        
        # Threading
        self._lock = threading.RLock()
        self._shutdown = False
        self._worker_threads: List[threading.Thread] = []
        self.max_concurrent_tasks = max_concurrent_tasks
        
        # Integrations
        self.db = shadowfox_db
        self.event_bus = event_bus
        
        # Task scheduling
        self.task_scheduler = threading.Thread(target=self._task_scheduler_loop, daemon=True)
        self.heartbeat_monitor = threading.Thread(target=self._heartbeat_monitor_loop, daemon=True)
        
        # AI Decision System
        self.ai_orchestrator = {
            'load_balancer': self._ai_load_balancer,
            'task_optimizer': self._ai_task_optimizer,
            'failure_handler': self._ai_failure_handler
        }
        
        # Statistics
        self.stats = {
            'total_tasks': 0,
            'completed_tasks': 0,
            'failed_tasks': 0,
            'active_agents': 0,
            'avg_task_time': 0.0,
            'throughput_per_minute': 0.0
        }
        
        # Task dependencies
        self.dependency_graph: Dict[str, List[str]] = defaultdict(list)
        self.waiting_tasks: Dict[str, List[str]] = defaultdict(list)
        
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger("ShadowFoxOperator")
        
        self._start_worker_threads()
    
    def _start_worker_threads(self):
        """Pokretanje worker thread-ova"""
        self.task_scheduler.start()
        self.heartbeat_monitor.start()
        
        # Worker threads za task execution
        for i in range(min(4, self.max_concurrent_tasks)):
            worker = threading.Thread(target=self._task_worker_loop, daemon=True, name=f"TaskWorker-{i}")
            worker.start()
            self._worker_threads.append(worker)
    
    # === AGENT MANAGEMENT ===
    
    def register_agent(self, agent_type: str, module_name: str, capabilities: List[TaskType], 
                      callback_handler: Callable, max_concurrent: int = 1, 
                      metadata: Dict[str, Any] = None) -> str:
        """Registruje novog agenta u sistem"""
        agent_id = f"agent_{module_name}_{uuid.uuid4().hex[:8]}"
        
        # Inicijalni specialization score
        specialization = {}
        for cap in capabilities:
            specialization[cap] = 0.7  # Početni score
        
        agent = ShadowAgent(
            agent_id=agent_id,
            agent_type=agent_type,
            module_name=module_name,
            capabilities=capabilities,
            max_concurrent_tasks=max_concurrent,
            specialization_score=specialization,
            metadata=metadata or {},
            callback_handler=callback_handler
        )
        
        with self._lock:
            self.agents[agent_id] = agent
            agent.status = AgentStatus.IDLE
            self.stats['active_agents'] += 1
        
        self.logger.info(f"Registered agent {agent_id} ({module_name}) with capabilities: {capabilities}")
        
        if self.event_bus:
            from shadowfox_event_bus import ShadowFoxEvent, EventType
            self.event_bus.publish(ShadowFoxEvent(
                event_type=EventType.MODULE_STARTED,
                mission_id="system",
                source_module="operator",
                data={"agent_id": agent_id, "module_name": module_name, "capabilities": [c.value for c in capabilities]}
            ))
        
        return agent_id
    
    def release_agent(self, agent_id: str, reason: str = "normal") -> bool:
        """Oslobađa agenta iz sistema"""
        with self._lock:
            if agent_id not in self.agents:
                self.logger.warning(f"Attempted to release unknown agent: {agent_id}")
                return False
            
            agent = self.agents[agent_id]
            
            # Ako agent ima aktivan task, cancel ga
            if agent.current_task:
                self._cancel_task(agent.current_task, f"Agent {agent_id} released: {reason}")
            
            # Ukloni agenta
            del self.agents[agent_id]
            self.stats['active_agents'] -= 1
            
            self.logger.info(f"Released agent {agent_id} - {reason}")
            
            if self.event_bus:
                from shadowfox_event_bus import ShadowFoxEvent, EventType
                self.event_bus.publish(ShadowFoxEvent(
                    event_type=EventType.MODULE_STOPPED,
                    mission_id="system",
                    source_module="operator",
                    data={"agent_id": agent_id, "reason": reason}
                ))
            
            return True
    
    def get_agent_status(self, agent_id: str) -> Optional[Dict[str, Any]]:
        """Dobija status agenta"""
        with self._lock:
            agent = self.agents.get(agent_id)
            if agent:
                return {
                    'agent_id': agent.agent_id,
                    'status': agent.status.value,
                    'current_task': agent.current_task,
                    'total_tasks': agent.total_tasks,
                    'success_rate': agent.successful_tasks / max(agent.total_tasks, 1),
                    'avg_execution_time': agent.avg_execution_time,
                    'current_load': agent.current_load,
                    'capabilities': [cap.value for cap in agent.capabilities]
                }
        return None
    
    # === TASK MANAGEMENT ===
    
    def receive_task(self, task_type: TaskType, mission_id: str, payload: Dict[str, Any],
                    priority: TaskPriority = TaskPriority.NORMAL, timeout: float = 300.0,
                    requirements: Dict[str, Any] = None, dependencies: List[str] = None,
                    correlation_id: str = None) -> str:
        """Prima novi task za izvršavanje"""
        task_id = f"task_{mission_id}_{uuid.uuid4().hex[:12]}"
        
        task = ShadowTask(
            task_id=task_id,
            task_type=task_type,
            mission_id=mission_id,
            priority=priority,
            payload=payload,
            requirements=requirements or {},
            timeout=timeout,
            dependencies=dependencies or [],
            correlation_id=correlation_id
        )
        
        with self._lock:
            self.tasks[task_id] = task
            self.stats['total_tasks'] += 1
            
            # Dodaj u dependency graph
            if dependencies:
                for dep in dependencies:
                    self.dependency_graph[dep].append(task_id)
                    self.waiting_tasks[task_id] = dependencies.copy()
            else:
                # Nema dependencies, može odmah u queue
                self.task_queue.put(task)
        
        self.logger.info(f"Received task {task_id} ({task_type.value}) for mission {mission_id}")
        
        if self.db:
            self.db.log_module_activity(mission_id, "operator", "task_received", 
                                      {"task_id": task_id, "task_type": task_type.value})
        
        return task_id
    
    def assign_task(self, task_id: str, agent_id: str = None) -> bool:
        """Dodeljivanje taska agentu (manual ili auto)"""
        with self._lock:
            task = self.tasks.get(task_id)
            if not task or task.status != TaskStatus.PENDING:
                return False
            
            if agent_id:
                # Manual assignment
                agent = self.agents.get(agent_id)
                if not agent or not agent.can_handle_task(task):
                    return False
                selected_agent = agent
            else:
                # Auto assignment - AI decision
                selected_agent = self._ai_select_best_agent(task)
                if not selected_agent:
                    return False
            
            # Dodeli task
            task.assigned_agent = selected_agent.agent_id
            task.assigned_at = time.time()
            task.status = TaskStatus.ASSIGNED
            
            selected_agent.current_task = task_id
            selected_agent.current_load += 1
            selected_agent.status = AgentStatus.BUSY
            
            self.logger.info(f"Assigned task {task_id} to agent {selected_agent.agent_id}")
            
            return True
    
    def get_task_status(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Dobija status taska"""
        with self._lock:
            task = self.tasks.get(task_id)
            if task:
                return {
                    'task_id': task.task_id,
                    'status': task.status.value,
                    'assigned_agent': task.assigned_agent,
                    'progress': self._calculate_task_progress(task),
                    'created_at': task.created_at,
                    'estimated_completion': self._estimate_completion_time(task),
                    'retry_count': task.retry_count
                }
        return None
    
    def cancel_task(self, task_id: str, reason: str = "user_request") -> bool:
        """Otkazuje task"""
        return self._cancel_task(task_id, reason)
    
    def _cancel_task(self, task_id: str, reason: str) -> bool:
        """Interno otkazivanje taska"""
        with self._lock:
            task = self.tasks.get(task_id)
            if not task:
                return False
            
            if task.status in [TaskStatus.COMPLETED, TaskStatus.CANCELLED]:
                return False
            
            # Oslobodi agenta ako je dodeljen
            if task.assigned_agent:
                agent = self.agents.get(task.assigned_agent)
                if agent:
                    agent.current_task = None
                    agent.current_load = max(0, agent.current_load - 1)
                    if agent.current_load == 0:
                        agent.status = AgentStatus.IDLE
            
            task.status = TaskStatus.CANCELLED
            task.error = reason
            task.completed_at = time.time()
            
            self.completed_tasks.append(task)
            
            self.logger.info(f"Cancelled task {task_id}: {reason}")
            return True
    
    # === AI DECISION MAKING ===
    
    def _ai_select_best_agent(self, task: ShadowTask) -> Optional[ShadowAgent]:
        """AI algoritam za selekciju najboljeg agenta"""
        available_agents = [agent for agent in self.agents.values() 
                          if agent.can_handle_task(task)]
        
        if not available_agents:
            return None
        
        # Računaj fitness score za svakog agenta
        scored_agents = []
        for agent in available_agents:
            fitness = agent.get_fitness_score(task)
            scored_agents.append((fitness, agent))
        
        # Sortiraj po score-u
        scored_agents.sort(key=lambda x: x[0], reverse=True)
        
        # Top 3 agenta - dodaj randomness za load balancing
        import random
        top_agents = scored_agents[:min(3, len(scored_agents))]
        
        # Weighted random selection
        weights = [score for score, _ in top_agents]
        selected = random.choices(top_agents, weights=weights, k=1)[0]
        
        return selected[1]
    
    def _ai_load_balancer(self) -> Dict[str, Any]:
        """AI load balancing algoritam"""
        with self._lock:
            total_load = sum(agent.current_load for agent in self.agents.values())
            agent_count = len([a for a in self.agents.values() if a.status != AgentStatus.OFFLINE])
            
            if agent_count == 0:
                return {"status": "no_agents", "action": "wait"}
            
            avg_load = total_load / agent_count
            overloaded = [a for a in self.agents.values() if a.current_load > avg_load * 1.5]
            underloaded = [a for a in self.agents.values() if a.current_load < avg_load * 0.5]
            
            return {
                "total_load": total_load,
                "avg_load": avg_load,
                "overloaded_agents": len(overloaded),
                "underloaded_agents": len(underloaded),
                "recommendation": "redistribute" if overloaded and underloaded else "balanced"
            }
    
    def _ai_task_optimizer(self, task: ShadowTask) -> Dict[str, Any]:
        """AI task optimization"""
        # Analiziraj historical performance za ovaj tip taska
        similar_tasks = [t for t in self.completed_tasks 
                        if t.task_type == task.task_type and t.status == TaskStatus.COMPLETED]
        
        if similar_tasks:
            avg_time = sum(t.completed_at - t.started_at for t in similar_tasks) / len(similar_tasks)
            success_rate = len([t for t in similar_tasks if t.result]) / len(similar_tasks)
            
            # Optimizuj timeout na osnovu historical data
            recommended_timeout = avg_time * 1.5
            
            return {
                "recommended_timeout": recommended_timeout,
                "success_rate": success_rate,
                "sample_size": len(similar_tasks),
                "optimization": "timeout_adjusted" if recommended_timeout < task.timeout else "timeout_optimal"
            }
        
        return {"optimization": "no_data", "recommendation": "use_defaults"}
    
    def _ai_failure_handler(self, task: ShadowTask, error: str) -> str:
        """AI failure handling decision"""
        # Analiza tipa greške
        if "timeout" in error.lower():
            return "increase_timeout"
        elif "connection" in error.lower():
            return "retry_different_agent"
        elif "authentication" in error.lower():
            return "escalate_to_human"
        elif task.retry_count >= task.max_retries:
            return "mark_failed"
        else:
            return "retry_same_agent"
    
    # === WORKER LOOPS ===
    
    def _task_scheduler_loop(self):
        """Main task scheduling loop"""
        while not self._shutdown:
            try:
                # Procesiranje dependency-ja
                self._process_dependencies()
                
                # Proverava da li ima pending taskova za auto-assignment
                with self._lock:
                    pending_tasks = [t for t in self.tasks.values() 
                                   if t.status == TaskStatus.PENDING]
                
                for task in pending_tasks:
                    if self.assign_task(task.task_id):
                        break  # Assign jedan po jedan da se load rasporedi
                
                time.sleep(1)  # 1 second scheduling interval
                
            except Exception as e:
                self.logger.error(f"Task scheduler error: {e}")
                time.sleep(5)
    
    def _heartbeat_monitor_loop(self):
        """Monitor agent heartbeats"""
        while not self._shutdown:
            try:
                current_time = time.time()
                
                with self._lock:
                    for agent in list(self.agents.values()):
                        # Ako agent nije poslao heartbeat 60s
                        if current_time - agent.last_heartbeat > 60:
                            self.logger.warning(f"Agent {agent.agent_id} heartbeat timeout")
                            
                            # Cancel trenutni task
                            if agent.current_task:
                                self._cancel_task(agent.current_task, "agent_timeout")
                            
                            agent.status = AgentStatus.OFFLINE
                
                time.sleep(30)  # Check svakih 30 sekundi
                
            except Exception as e:
                self.logger.error(f"Heartbeat monitor error: {e}")
                time.sleep(30)
    
    def _task_worker_loop(self):
        """Worker thread za task execution"""
        while not self._shutdown:
            try:
                # Uzmi task iz queue-a
                try:
                    task = self.task_queue.get(timeout=5)
                except:
                    continue
                
                # Izvršavanje taska
                self._execute_task(task)
                
            except Exception as e:
                self.logger.error(f"Task worker error: {e}")
                time.sleep(1)
    
    def _execute_task(self, task: ShadowTask):
        """Izvršava task"""
        try:
            # Pronađi agenta
            agent = self.agents.get(task.assigned_agent)
            if not agent or not agent.callback_handler:
                task.status = TaskStatus.FAILED
                task.error = "Agent not available"
                return
            
            task.status = TaskStatus.RUNNING
            task.started_at = time.time()
            
            self.logger.info(f"Executing task {task.task_id} with agent {agent.agent_id}")
            
            # Pozovi agent callback
            start_time = time.time()
            try:
                result = agent.callback_handler(task)
                execution_time = time.time() - start_time
                
                # Update agent statistics
                agent.total_tasks += 1
                agent.successful_tasks += 1
                agent.avg_execution_time = ((agent.avg_execution_time * (agent.total_tasks - 1)) + execution_time) / agent.total_tasks
                agent.specialization_score[task.task_type] = min(1.0, agent.specialization_score.get(task.task_type, 0.5) + 0.1)
                
                # Task completed
                task.status = TaskStatus.COMPLETED
                task.result = result
                task.completed_at = time.time()
                
                self.stats['completed_tasks'] += 1
                
            except Exception as e:
                execution_time = time.time() - start_time
                
                # Update agent statistics
                agent.total_tasks += 1
                agent.failed_tasks += 1
                agent.specialization_score[task.task_type] = max(0.1, agent.specialization_score.get(task.task_type, 0.5) - 0.05)
                
                # Handle failure with AI
                action = self._ai_failure_handler(task, str(e))
                
                if action == "retry_same_agent" and task.retry_count < task.max_retries:
                    task.retry_count += 1
                    task.status = TaskStatus.PENDING
                    self.task_queue.put(task)
                    return
                elif action == "retry_different_agent" and task.retry_count < task.max_retries:
                    task.retry_count += 1
                    task.assigned_agent = None
                    task.status = TaskStatus.PENDING
                    self.task_queue.put(task)
                    return
                else:
                    task.status = TaskStatus.FAILED
                    task.error = str(e)
                    task.completed_at = time.time()
                    self.stats['failed_tasks'] += 1
            
            finally:
                # Oslobodi agenta
                agent.current_task = None
                agent.current_load = max(0, agent.current_load - 1)
                if agent.current_load == 0:
                    agent.status = AgentStatus.IDLE
                
                # Dodaj u completed tasks
                self.completed_tasks.append(task)
                
                # Process dependencies
                self._resolve_task_dependencies(task.task_id)
                
        except Exception as e:
            self.logger.error(f"Task execution error: {e}")
            task.status = TaskStatus.FAILED
            task.error = str(e)
    
    def _process_dependencies(self):
        """Procesira task dependencies"""
        with self._lock:
            ready_tasks = []
            
            for task_id, deps in list(self.waiting_tasks.items()):
                # Proverava da li su svi dependencies završeni
                completed_deps = []
                for dep_id in deps:
                    dep_task = self.tasks.get(dep_id)
                    if dep_task and dep_task.status == TaskStatus.COMPLETED:
                        completed_deps.append(dep_id)
                
                # Ukloni completed dependencies
                for dep_id in completed_deps:
                    deps.remove(dep_id)
                
                # Ako nema više dependencies, dodaj u queue
                if not deps:
                    task = self.tasks.get(task_id)
                    if task and task.status == TaskStatus.PENDING:
                        ready_tasks.append(task)
                    del self.waiting_tasks[task_id]
            
            # Dodaj ready tasks u queue
            for task in ready_tasks:
                self.task_queue.put(task)
    
    def _resolve_task_dependencies(self, completed_task_id: str):
        """Resolve dependencies kada se task završi"""
        if completed_task_id in self.dependency_graph:
            dependent_tasks = self.dependency_graph[completed_task_id]
            
            for task_id in dependent_tasks:
                if task_id in self.waiting_tasks:
                    if completed_task_id in self.waiting_tasks[task_id]:
                        self.waiting_tasks[task_id].remove(completed_task_id)
    
    # === UTILITY METHODS ===
    
    def _calculate_task_progress(self, task: ShadowTask) -> float:
        """Računa progress taska"""
        if task.status == TaskStatus.COMPLETED:
            return 1.0
        elif task.status == TaskStatus.RUNNING:
            elapsed = time.time() - task.started_at
            return min(0.9, elapsed / task.timeout)
        elif task.status in [TaskStatus.ASSIGNED, TaskStatus.PENDING]:
            return 0.0
        else:
            return 0.0
    
    def _estimate_completion_time(self, task: ShadowTask) -> Optional[float]:
        """Procenjuje vreme završetka taska"""
        if task.status == TaskStatus.COMPLETED:
            return task.completed_at
        elif task.status == TaskStatus.RUNNING and task.assigned_agent:
            agent = self.agents.get(task.assigned_agent)
            if agent and agent.avg_execution_time > 0:
                elapsed = time.time() - task.started_at
                remaining = agent.avg_execution_time - elapsed
                return time.time() + max(0, remaining)
        
        return None
    
    def agent_heartbeat(self, agent_id: str, metadata: Dict[str, Any] = None):
        """Prima heartbeat od agenta"""
        with self._lock:
            agent = self.agents.get(agent_id)
            if agent:
                agent.last_heartbeat = time.time()
                if metadata:
                    agent.metadata.update(metadata)
                
                if agent.status == AgentStatus.OFFLINE:
                    agent.status = AgentStatus.IDLE
    
    def get_system_stats(self) -> Dict[str, Any]:
        """Vraća statistike sistema"""
        with self._lock:
            active_tasks = len([t for t in self.tasks.values() 
                              if t.status in [TaskStatus.ASSIGNED, TaskStatus.RUNNING]])
            
            pending_tasks = len([t for t in self.tasks.values() 
                               if t.status == TaskStatus.PENDING])
            
            # Throughput calculation
            recent_completions = [t for t in self.completed_tasks 
                                if time.time() - t.completed_at < 60]  # Last minute
            
            return {
                **self.stats,
                'active_tasks': active_tasks,
                'pending_tasks': pending_tasks,
                'queue_size': self.task_queue.qsize(),
                'agent_count': len(self.agents),
                'active_agents': len([a for a in self.agents.values() if a.status != AgentStatus.OFFLINE]),
                'recent_throughput': len(recent_completions),
                'load_balance': self._ai_load_balancer()
            }
    
    def shutdown(self):
        """Gasi operator"""
        self.logger.info("Shutting down ShadowFox Operator...")
        self._shutdown = True
        
        # Cancel sve pending taskove
        with self._lock:
            for task in self.tasks.values():
                if task.status in [TaskStatus.PENDING, TaskStatus.ASSIGNED, TaskStatus.RUNNING]:
                    self._cancel_task(task.task_id, "system_shutdown")


# === USAGE EXAMPLE ===
if __name__ == "__main__":
    def dummy_agent_callback(task):
        """Dummy agent callback za testiranje"""
        import time
        time.sleep(2)  # Simulira rad
        return {"result": f"Task {task.task_id} completed", "data": task.payload}
    
    # Kreiraj operator
    operator = ShadowFoxOperator()
    
    # Registruj agente
    agent1 = operator.register_agent("fuzzer", "smart_shadow_agent", 
                                   [TaskType.FUZZ, TaskType.EXPLOIT], 
                                   dummy_agent_callback)
    
    agent2 = operator.register_agent("recon", "shadow_spider", 
                                   [TaskType.RECON, TaskType.INTELLIGENCE], 
                                   dummy_agent_callback)
    agent3 = operator.register_agent("penetrator", "shadowx_agent", [TaskType.EXPLOIT, TaskType.MUTATION], shadowx_callback)

    agent4 = operator.register_agent("ai_core", "most_advanced", [TaskType.FUZZ, TaskType.EXPLOIT], advanced_callback)

    # Pošalji taskove

    task1 = operator.receive_task(TaskType.RECON, "mission_001", 
                                {"target": "https://example.com"}, 
                                TaskPriority.HIGH)
