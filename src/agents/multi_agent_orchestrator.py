"""
BreachPilot Multi-Agent Attack Chain Orchestrator
攻撃チェーンの自動オーケストレーションと可視化 (Enhanced)
"""
import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum
from concurrent.futures import ThreadPoolExecutor
import threading
import queue
import logging

from .attack_chain_models import AttackChain, AttackTask, AgentState, TaskStatus, AttackStage, AgentRole
from .shared_knowledge import SharedKnowledgeBase
from .attack_chain_visualizer import AttackChainVisualizer

# Setup enhanced logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class MultiAgentOrchestrator:
    """マルチエージェント攻撃チェーンオーケストレーター (Enhanced)"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.knowledge_base = SharedKnowledgeBase()
        self.active_chains: Dict[str, AttackChain] = {}
        self.task_queue = queue.PriorityQueue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.running = False
        self._lock = threading.Lock()
        self.execution_logs: Dict[str, List[Dict[str, Any]]] = {}
        
        logger.info(f"MultiAgentOrchestrator initialized with {max_workers} workers")
    
    def create_attack_chain(self, target: str, objective: str) -> AttackChain:
        """攻撃チェーンを作成"""
        chain = AttackChain(
            name=f"Attack on {target}",
            target=target,
            objective=objective
        )
        
        logger.info(f"Creating attack chain for target: {target}, objective: {objective}")
        
        chain.tasks = self._generate_default_attack_tasks(target, objective)
        chain.agent_states = self._initialize_agents()
        
        # Initialize execution logs for this chain
        self.execution_logs[chain.id] = []
        self._log_to_chain(chain.id, "info", f"Attack chain created with {len(chain.tasks)} tasks")
        
        self.active_chains[chain.id] = chain
        logger.info(f"Attack chain {chain.id} created successfully")
        return chain
    
    def _log_to_chain(self, chain_id: str, level: str, message: str):
        """チェーン固有のログを追加"""
        if chain_id not in self.execution_logs:
            self.execution_logs[chain_id] = []
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        
        self.execution_logs[chain_id].append(log_entry)
        
        # Keep only last 200 log entries per chain
        if len(self.execution_logs[chain_id]) > 200:
            self.execution_logs[chain_id] = self.execution_logs[chain_id][-200:]
        
        # Also log to console
        getattr(logger, level, logger.info)(f"[{chain_id[:8]}] {message}")
    
    def _generate_default_attack_tasks(self, target: str, objective: str) -> List[AttackTask]:
        """デフォルトの攻撃タスクを生成"""
        tasks = []
        
        # 偵察タスク
        recon_task = AttackTask(
            name="Network Reconnaissance",
            stage=AttackStage.RECONNAISSANCE,
            agent_role=AgentRole.RECON_SPECIALIST,
            priority=10,
            estimated_duration=15,  # Shorter durations for demo
            metadata={"target": target}
        )
        tasks.append(recon_task)
        
        # スキャンタスク
        scan_task = AttackTask(
            name="Port and Service Scanning",
            stage=AttackStage.SCANNING,
            agent_role=AgentRole.RECON_SPECIALIST,
            dependencies=[recon_task.id],
            priority=9,
            estimated_duration=20,
            metadata={"target": target}
        )
        tasks.append(scan_task)
        
        # 脆弱性分析
        vuln_task = AttackTask(
            name="Vulnerability Analysis",
            stage=AttackStage.VULNERABILITY_ANALYSIS,
            agent_role=AgentRole.VULNERABILITY_ANALYST,
            dependencies=[scan_task.id],
            priority=8,
            estimated_duration=25,
            metadata={"focus": "CVE-2020-1472, SMB, Kerberos"}
        )
        tasks.append(vuln_task)
        
        # エクスプロイト
        exploit_task = AttackTask(
            name="Exploit Execution",
            stage=AttackStage.EXPLOITATION,
            agent_role=AgentRole.EXPLOIT_ENGINEER,
            dependencies=[vuln_task.id],
            priority=7,
            estimated_duration=30,
            metadata={"target": target}
        )
        tasks.append(exploit_task)
        
        # ポストエクスプロイト
        post_exploit_task = AttackTask(
            name="Post-Exploitation Analysis",
            stage=AttackStage.POST_EXPLOITATION,
            agent_role=AgentRole.POST_EXPLOIT_SPECIALIST,
            dependencies=[exploit_task.id],
            priority=6,
            estimated_duration=20,
            metadata={"focus": "privilege, persistence, lateral movement"}
        )
        tasks.append(post_exploit_task)
        
        logger.info(f"Generated {len(tasks)} default attack tasks")
        return tasks
    
    def _initialize_agents(self) -> Dict[str, AgentState]:
        """エージェント状態を初期化"""
        agents = {}
        capabilities_map = {
            AgentRole.RECON_SPECIALIST: ["nmap_scanning", "service_enumeration", "osint"],
            AgentRole.VULNERABILITY_ANALYST: ["cve_analysis", "exploit_research", "risk_assessment"],
            AgentRole.EXPLOIT_ENGINEER: ["exploit_execution", "payload_generation", "custom_exploits"],
            AgentRole.POST_EXPLOIT_SPECIALIST: ["privilege_escalation", "persistence", "lateral_movement"],
            AgentRole.PERSISTENCE_EXPERT: ["backdoor_installation", "scheduled_tasks"],
            AgentRole.COMMAND_CONTROLLER: ["c2_communication", "payload_delivery", "exfiltration"]
        }
        
        for role in AgentRole:
            agent_id = f"agent_{role.value}_{int(time.time())}"
            agent = AgentState(
                id=agent_id,
                role=role,
                capabilities=capabilities_map.get(role, [])
            )
            agents[agent_id] = agent
        
        logger.info(f"Initialized {len(agents)} agents")
        return agents
    
    async def execute_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """攻撃チェーンを実行"""
        if chain_id not in self.active_chains:
            return {"error": "Attack chain not found"}
        
        chain = self.active_chains[chain_id]
        chain.status = "running"
        chain.started_at = datetime.now()
        self.running = True
        
        self._log_to_chain(chain_id, "info", "Starting attack chain execution")
        
        try:
            self._enqueue_ready_tasks(chain)
            
            futures = []
            while self.running and (not self.task_queue.empty() or futures):
                # 新しいタスクを開始
                while len(futures) < self.max_workers and not self.task_queue.empty():
                    try:
                        priority, task_id, current_chain_id = self.task_queue.get_nowait()
                        if current_chain_id != chain_id:
                            continue
                            
                        task = self._find_task_by_id(chain, task_id)
                        if task and task.status == TaskStatus.PENDING:
                            self._log_to_chain(chain_id, "debug", f"Starting task: {task.name}")
                            future = self.executor.submit(self._execute_task, task, chain)
                            futures.append((future, task))
                    except queue.Empty:
                        break
                
                # 完了したタスクを処理
                completed_futures = []
                for future, task in futures:
                    if future.done():
                        try:
                            result = future.result()
                            await self._handle_task_completion(task, result, chain)
                            completed_futures.append((future, task))
                        except Exception as e:
                            await self._handle_task_error(task, str(e), chain)
                            completed_futures.append((future, task))
                
                for completed in completed_futures:
                    futures.remove(completed)
                
                self._enqueue_ready_tasks(chain)
                await asyncio.sleep(0.5)  # Check more frequently
            
            if all(task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] for task in chain.tasks):
                chain.status = "completed"
                chain.completed_at = datetime.now()
                self._log_to_chain(chain_id, "success", "Attack chain completed successfully")
            
            return self._generate_execution_summary(chain)
            
        except Exception as e:
            chain.status = "failed"
            self._log_to_chain(chain_id, "error", f"Attack chain execution failed: {str(e)}")
            return {"error": str(e)}
        finally:
            self.running = False
    
    def _enqueue_ready_tasks(self, chain: AttackChain):
        """実行可能なタスクをキューに追加"""
        for task in chain.tasks:
            if (task.status == TaskStatus.PENDING and 
                self._are_dependencies_met(task, chain)):
                priority = -task.priority
                self.task_queue.put((priority, task.id, chain.id))
    
    def _are_dependencies_met(self, task: AttackTask, chain: AttackChain) -> bool:
        """タスクの依存関係が満たされているかチェック"""
        for dep_id in task.dependencies:
            dep_task = self._find_task_by_id(chain, dep_id)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False
        return True
    
    def _find_task_by_id(self, chain: AttackChain, task_id: str) -> Optional[AttackTask]:
        """IDでタスクを検索"""
        for task in chain.tasks:
            if task.id == task_id:
                return task
        return None
    
    def _execute_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """タスクを実行"""
        task.status = TaskStatus.RUNNING
        task.start_time = datetime.now()
        
        agent = self._assign_agent(task, chain)
        if agent:
            agent.status = "busy"
            agent.current_task = task.id
            agent.last_activity = datetime.now()
        
        self._add_timeline_event(chain, f"Task started: {task.name}", task.id)
        self._log_to_chain(chain.id, "info", f"Executing task: {task.name} (Agent: {agent.role.value if agent else 'None'})")
        
        try:
            result = self._run_task_logic(task, chain)
            
            task.status = TaskStatus.COMPLETED
            task.result = result
            task.end_time = datetime.now()
            task.actual_duration = int((task.end_time - task.start_time).total_seconds())
            
            self.knowledge_base.store(f"task_result_{task.stage.value}", result, agent.id if agent else "system")
            self._log_to_chain(chain.id, "success", f"Task completed: {task.name} (Duration: {task.actual_duration}s)")
            
            return result
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.end_time = datetime.now()
            self._log_to_chain(chain.id, "error", f"Task failed: {task.name} - {str(e)}")
            raise e
        finally:
            if agent:
                agent.status = "idle"
                agent.current_task = None
                agent.completed_tasks.append(task.id)
    
    def _assign_agent(self, task: AttackTask, chain: AttackChain) -> Optional[AgentState]:
        """タスクにエージェントを割り当て"""
        for agent in chain.agent_states.values():
            if agent.role == task.agent_role and agent.status == "idle":
                return agent
        return None
    
    def _run_task_logic(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """実際のタスク実行ロジック"""
        target = task.metadata.get("target")
        
        # Simulate realistic task execution with logs
        if task.stage == AttackStage.RECONNAISSANCE:
            self._log_to_chain(chain.id, "debug", f"Gathering OSINT data for {target}")
            time.sleep(3)
            self._log_to_chain(chain.id, "info", f"DNS enumeration completed for {target}")
            time.sleep(2)
            return {
                "status": "success", 
                "data": {
                    "target": target,
                    "domain_info": f"Analysis of {target}",
                    "records": ["DNS", "WHOIS", "Certificate transparency"],
                    "subdomains": ["mail", "www", "ftp"]
                }
            }
        elif task.stage == AttackStage.SCANNING:
            self._log_to_chain(chain.id, "debug", f"Starting Nmap scan of {target}")
            time.sleep(4)
            self._log_to_chain(chain.id, "info", "Port 88/tcp open - Kerberos detected")
            time.sleep(2)
            self._log_to_chain(chain.id, "info", "Port 389/tcp open - LDAP detected")
            time.sleep(1)
            self._log_to_chain(chain.id, "warning", "Target appears to be a Domain Controller")
            return {
                "status": "success", 
                "data": {
                    "target": target,
                    "ports": [
                        {"port": 88, "service": "kerberos", "state": "open"},
                        {"port": 389, "service": "ldap", "state": "open"},
                        {"port": 445, "service": "microsoft-ds", "state": "open"},
                        {"port": 53, "service": "domain", "state": "open"}
                    ],
                    "domain_controller": True,
                    "os_detection": "Windows Server 2016-2019"
                }
            }
        elif task.stage == AttackStage.VULNERABILITY_ANALYSIS:
            self._log_to_chain(chain.id, "debug", "Analyzing detected services for vulnerabilities")
            time.sleep(3)
            self._log_to_chain(chain.id, "warning", "Netlogon service detected - checking for CVE-2020-1472")
            time.sleep(2)
            self._log_to_chain(chain.id, "error", "CRITICAL: Target vulnerable to Zerologon attack!")
            return {
                "status": "success", 
                "data": {
                    "vulnerabilities": [{
                        "cve": "CVE-2020-1472",
                        "name": "Zerologon",
                        "severity": "critical",
                        "cvss": 10.0,
                        "description": "Netlogon elevation of privilege vulnerability",
                        "exploitable": True
                    }],
                    "risk_level": "critical",
                    "recommendation": "Immediate patching required"
                }
            }
        elif task.stage == AttackStage.EXPLOITATION:
            self._log_to_chain(chain.id, "debug", "Preparing Zerologon exploit")
            time.sleep(2)
            self._log_to_chain(chain.id, "info", "Establishing secure channel to target DC")
            time.sleep(3)
            self._log_to_chain(chain.id, "warning", "Attempting authentication bypass...")
            time.sleep(4)
            self._log_to_chain(chain.id, "success", "Zerologon exploit successful! Domain Admin privileges obtained")
            return {
                "status": "success", 
                "data": {
                    "exploit_name": "CVE-2020-1472 Zerologon",
                    "success": True,
                    "privileges_gained": "Domain Administrator",
                    "access_level": "SYSTEM",
                    "next_steps": ["Persistence", "Lateral movement", "Data collection"]
                }
            }
        elif task.stage == AttackStage.POST_EXPLOITATION:
            self._log_to_chain(chain.id, "debug", "Analyzing post-exploitation opportunities")
            time.sleep(2)
            self._log_to_chain(chain.id, "info", "Enumerating domain users and computers")
            time.sleep(3)
            self._log_to_chain(chain.id, "info", "Identifying high-value targets for lateral movement")
            time.sleep(2)
            self._log_to_chain(chain.id, "warning", "Sensitive data repositories discovered")
            return {
                "status": "success", 
                "data": {
                    "domain_users": 150,
                    "domain_computers": 75,
                    "admin_accounts": 8,
                    "sensitive_shares": ["\\\\DC\\SYSVOL", "\\\\FileServer\\Finance"],
                    "persistence_methods": ["Golden ticket", "Silver ticket", "Scheduled tasks"]
                }
            }
        else:
            time.sleep(2)
            return {"status": "completed", "message": f"Task {task.name} completed"}
    
    async def _handle_task_completion(self, task: AttackTask, result: Dict[str, Any], chain: AttackChain):
        """タスク完了処理"""
        self._add_timeline_event(chain, f"Task completed: {task.name}", task.id)
        self._share_task_results(task, result, chain)
    
    async def _handle_task_error(self, task: AttackTask, error: str, chain: AttackChain):
        """タスクエラー処理"""
        task.status = TaskStatus.FAILED
        task.error = error
        task.end_time = datetime.now()
        self._add_timeline_event(chain, f"Task failed: {task.name} - {error}", task.id)
    
    def _share_task_results(self, task: AttackTask, result: Dict[str, Any], chain: AttackChain):
        """タスク結果をエージェント間で共有"""
        key = f"task_result_{task.stage.value}"
        agent_id = next((aid for aid, agent in chain.agent_states.items() 
                        if agent.current_task == task.id), "unknown")
        self.knowledge_base.store(key, result, agent_id)
    
    def _add_timeline_event(self, chain: AttackChain, message: str, task_id: Optional[str] = None):
        """タイムラインイベントを追加"""
        event = {
            "timestamp": datetime.now().isoformat(),
            "message": message,
            "task_id": task_id
        }
        chain.timeline.append(event)
    
    def _generate_execution_summary(self, chain: AttackChain) -> Dict[str, Any]:
        """実行サマリーを生成"""
        total_tasks = len(chain.tasks)
        completed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        failed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.FAILED])
        
        total_duration = 0
        if chain.started_at and chain.completed_at:
            total_duration = int((chain.completed_at - chain.started_at).total_seconds())
        
        return {
            "chain_id": chain.id,
            "status": chain.status,
            "target": chain.target,
            "summary": {
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "failed_tasks": failed_tasks,
                "success_rate": (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0,
                "total_duration": total_duration
            },
            "timeline": chain.timeline,
            "final_results": {task.stage.value: task.result for task in chain.tasks 
                            if task.status == TaskStatus.COMPLETED and task.result}
        }
    
    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        """攻撃チェーンの現在のステータスを取得"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        visualization_data = AttackChainVisualizer.generate_chain_graph(chain)
        
        # Calculate progress based on completed tasks
        total_tasks = len(chain.tasks)
        completed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        return {
            "chain_id": chain.id,
            "name": chain.name,
            "target": chain.target,
            "status": chain.status,
            "progress": progress,
            "agent_states": [
                {
                    "id": agent.id,
                    "role": agent.role.value,
                    "status": agent.status,
                    "current_task": agent.current_task,
                    "completed_tasks_count": len(agent.completed_tasks)
                }
                for agent in chain.agent_states.values()
            ],
            "visualization": visualization_data,
            "recent_timeline": chain.timeline[-20:] if chain.timeline else [],
            "logs": self.execution_logs.get(chain_id, [])[-50:]  # Return last 50 logs
        }
    
    def stop_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """攻撃チェーンを停止"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        self.running = False
        chain = self.active_chains[chain_id]
        chain.status = "stopped"
        
        for task in chain.tasks:
            if task.status == TaskStatus.RUNNING:
                task.status = TaskStatus.FAILED
                task.error = "Manually stopped"
                task.end_time = datetime.now()
        
        self._add_timeline_event(chain, "Attack chain manually stopped")
        self._log_to_chain(chain_id, "warning", "Attack chain stopped by user")
        return {"status": "stopped", "chain_id": chain_id}


# グローバルインスタンス
_orchestrator = None

def get_multi_agent_orchestrator() -> MultiAgentOrchestrator:
    """グローバルマルチエージェントオーケストレーターインスタンスを取得"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = MultiAgentOrchestrator()
    return _orchestrator
