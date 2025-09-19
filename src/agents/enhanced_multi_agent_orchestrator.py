"""
Enhanced Multi-Agent Orchestrator with Real Tool Execution and AI-powered Agents
真のマルチエージェントシステム - 実際のツール実行とAI推論 (Fixed)
"""
import asyncio
import json
import subprocess
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
import shlex
import re

from .attack_chain_models import AttackChain, AttackTask, AgentState, TaskStatus, AttackStage, AgentRole
from .shared_knowledge import SharedKnowledgeBase

# AI Integration
try:
    from anthropic import Anthropic
    from openai import OpenAI
    AI_AVAILABLE = True
except ImportError:
    AI_AVAILABLE = False

# Setup enhanced logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)


class EnhancedAgent:
    """強化されたAIエージェント - 実際のツール実行とAI推論"""
    
    def __init__(self, agent_id: str, role: AgentRole, anthropic_client=None, openai_client=None):
        self.id = agent_id
        self.role = role
        self.status = "idle"
        self.current_task = None
        self.completed_tasks = []
        self.knowledge_base = {}
        self.anthropic_client = anthropic_client
        self.openai_client = openai_client
        self.capabilities = self._define_capabilities()
        self.tools = self._define_tools()
        
        logger.info(f"Enhanced Agent {self.id} ({self.role.value}) initialized with {len(self.tools)} tools")
    
    def _define_capabilities(self) -> List[str]:
        """エージェントの能力を定義"""
        capability_map = {
            AgentRole.RECON_SPECIALIST: [
                "network_scanning", "dns_enumeration", "subdomain_discovery", 
                "whois_lookup", "osint_gathering", "port_scanning", "service_detection"
            ],
            AgentRole.VULNERABILITY_ANALYST: [
                "vulnerability_scanning", "cve_analysis", "exploit_research",
                "risk_assessment", "security_audit", "compliance_check"
            ],
            AgentRole.EXPLOIT_ENGINEER: [
                "exploit_execution", "payload_generation", "buffer_overflow",
                "sql_injection", "xss_exploitation", "metasploit_operation"
            ],
            AgentRole.POST_EXPLOIT_SPECIALIST: [
                "privilege_escalation", "system_enumeration", "credential_harvesting",
                "lateral_movement", "persistence_mechanisms", "data_discovery"
            ],
            AgentRole.PERSISTENCE_EXPERT: [
                "backdoor_installation", "scheduled_tasks", "registry_modification",
                "service_creation", "startup_persistence", "dll_hijacking"
            ],
            AgentRole.COMMAND_CONTROLLER: [
                "c2_communication", "payload_delivery", "data_exfiltration",
                "remote_access", "tunnel_establishment", "covert_channels"
            ]
        }
        return capability_map.get(self.role, [])
    
    def _define_tools(self) -> Dict[str, Dict[str, Any]]:
        """エージェントが使用できるツールを定義"""
        if self.role == AgentRole.RECON_SPECIALIST:
            return {
                "nmap_scan": {
                    "cmd": "nmap -sS -O -sV -p 1-1000 {target}",
                    "description": "Comprehensive port and service scan",
                    "timeout": 120
                },
                "nmap_quick": {
                    "cmd": "nmap -T4 -F {target}",
                    "description": "Quick port scan",
                    "timeout": 60
                },
                "dns_enum": {
                    "cmd": "nslookup {target}",
                    "description": "DNS lookup",
                    "timeout": 30
                },
                "whois_lookup": {
                    "cmd": "whois {target}",
                    "description": "WHOIS information gathering",
                    "timeout": 30
                }
            }
        elif self.role == AgentRole.VULNERABILITY_ANALYST:
            return {
                "nmap_vuln_scan": {
                    "cmd": "nmap --script vuln {target}",
                    "description": "Vulnerability detection scan",
                    "timeout": 180
                },
                "nikto_scan": {
                    "cmd": "nikto -h {target}",
                    "description": "Web vulnerability scanner",
                    "timeout": 300
                }
            }
        else:
            return {}
    
    async def execute_tool(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """ツールを実行し結果を返す"""
        if tool_name not in self.tools:
            return {"error": f"Tool {tool_name} not available for {self.role.value}"}
        
        tool = self.tools[tool_name]
        cmd = tool["cmd"].format(**kwargs)
        timeout = tool.get("timeout", 60)
        
        logger.info(f"Agent {self.id} executing: {cmd}")
        
        # デモモードではシミュレーション、プロダクションでは実際実行
        import os
        if os.getenv("BREACHPILOT_DEMO_MODE", "true").lower() == "true":
            result = await self._simulate_tool_execution(tool_name, **kwargs)
        else:
            result = await self._execute_real_command(cmd, timeout)
        
        self.knowledge_base[f"tool_result_{tool_name}_{int(time.time())}"] = result
        return result
    
    async def _execute_real_command(self, cmd: str, timeout: int) -> Dict[str, Any]:
        """実際のコマンド実行"""
        try:
            process = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=timeout
            )
            
            return {
                "status": "success",
                "stdout": stdout.decode(),
                "stderr": stderr.decode(),
                "returncode": process.returncode,
                "command": cmd
            }
            
        except asyncio.TimeoutError:
            return {"status": "timeout", "error": f"Command timed out after {timeout}s"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _simulate_tool_execution(self, tool_name: str, **kwargs) -> Dict[str, Any]:
        """リアルなツール実行シミュレーション"""
        target = kwargs.get("target", "unknown")
        await asyncio.sleep(2)  # シミュレーション待機
        
        if self.role == AgentRole.RECON_SPECIALIST:
            if tool_name == "nmap_scan":
                return {
                    "status": "success",
                    "scan_results": {
                        "target": target,
                        "open_ports": [
                            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                            {"port": 80, "service": "http", "version": "Apache 2.4.6"},
                            {"port": 443, "service": "https", "version": "Apache 2.4.6"}
                        ],
                        "os_detection": "Linux 3.X|4.X"
                    }
                }
            elif tool_name == "dns_enum":
                return {
                    "status": "success",
                    "dns_records": {
                        "A": [target],
                        "MX": ["mail.example.com"]
                    }
                }
        elif self.role == AgentRole.VULNERABILITY_ANALYST:
            if tool_name == "nmap_vuln_scan":
                return {
                    "status": "success",
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2021-44228",
                            "name": "Log4Shell",
                            "severity": "critical",
                            "port": 80
                        }
                    ]
                }
        
        return {"status": "completed", "message": f"Tool {tool_name} executed"}
    
    async def ai_analyze(self, task_context: str, data: Dict[str, Any]) -> str:
        """AI推論による結果分析"""
        if not AI_AVAILABLE or not (self.anthropic_client or self.openai_client):
            return f"Analysis: {task_context} completed successfully"
        
        prompt = f"""
        As a {self.role.value} cybersecurity expert, analyze the following data:
        
        Data: {json.dumps(data, indent=2)}
        
        Provide key findings and next steps (keep concise).
        """
        
        try:
            if self.anthropic_client:
                response = self.anthropic_client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            elif self.openai_client:
                response = self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    max_tokens=300,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return f"Analysis completed for {task_context}"
        
        return "AI analysis not available"


class EnhancedMultiAgentOrchestrator:
    """強化されたマルチエージェントオーケストレーター"""
    
    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self.knowledge_base = SharedKnowledgeBase()
        self.active_chains: Dict[str, AttackChain] = {}
        self.agents: Dict[str, EnhancedAgent] = {}
        self.task_queue = queue.PriorityQueue()
        self.executor = ThreadPoolExecutor(max_workers=max_workers)
        self.running = False
        self._lock = threading.Lock()
        self.execution_logs: Dict[str, List[Dict[str, Any]]] = {}
        
        # AI Clients initialization
        self.anthropic_client = None
        self.openai_client = None
        self._init_ai_clients()
        
        logger.info(f"Enhanced MultiAgentOrchestrator initialized with {max_workers} workers")
    
    def _init_ai_clients(self):
        """AI クライアントを初期化"""
        try:
            import os
            if os.getenv("ANTHROPIC_API_KEY"):
                self.anthropic_client = Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))
                logger.info("Anthropic Claude client initialized")
            
            if os.getenv("OPENAI_API_KEY"):
                self.openai_client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
                logger.info("OpenAI client initialized")
                
        except Exception as e:
            logger.warning(f"AI client initialization failed: {e}")
    
    def create_attack_chain(self, target: str, objective: str) -> AttackChain:
        """攻撃チェーンを作成"""
        chain = AttackChain(
            name=f"Enhanced Attack on {target}",
            target=target,
            objective=objective
        )
        
        logger.info(f"Creating enhanced attack chain for target: {target}, objective: {objective}")
        
        chain.tasks = self._generate_enhanced_attack_tasks(target, objective)
        chain.agent_states = self._initialize_enhanced_agents()
        
        self.execution_logs[chain.id] = []
        self._log_to_chain(chain.id, "info", f"Enhanced attack chain created with {len(chain.tasks)} tasks")
        
        self.active_chains[chain.id] = chain
        logger.info(f"Enhanced attack chain {chain.id} created successfully")
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
        
        if len(self.execution_logs[chain_id]) > 200:
            self.execution_logs[chain_id] = self.execution_logs[chain_id][-200:]
        
        getattr(logger, level, logger.info)(f"[{chain_id[:8]}] {message}")
    
    def _generate_enhanced_attack_tasks(self, target: str, objective: str) -> List[AttackTask]:
        """強化された攻撃タスクを生成"""
        tasks = []
        
        recon_task = AttackTask(
            name="Network Reconnaissance",
            stage=AttackStage.RECONNAISSANCE,
            agent_role=AgentRole.RECON_SPECIALIST,
            priority=10,
            estimated_duration=30,
            metadata={
                "target": target,
                "tools": ["nmap_quick", "dns_enum", "whois_lookup"]
            }
        )
        tasks.append(recon_task)
        
        scan_task = AttackTask(
            name="Detailed Scanning",
            stage=AttackStage.SCANNING,
            agent_role=AgentRole.RECON_SPECIALIST,
            dependencies=[recon_task.id],
            priority=9,
            estimated_duration=45,
            metadata={
                "target": target,
                "tools": ["nmap_scan"]
            }
        )
        tasks.append(scan_task)
        
        vuln_task = AttackTask(
            name="Vulnerability Analysis",
            stage=AttackStage.VULNERABILITY_ANALYSIS,
            agent_role=AgentRole.VULNERABILITY_ANALYST,
            dependencies=[scan_task.id],
            priority=8,
            estimated_duration=60,
            metadata={
                "target": target,
                "tools": ["nmap_vuln_scan"]
            }
        )
        tasks.append(vuln_task)
        
        logger.info(f"Generated {len(tasks)} enhanced attack tasks")
        return tasks
    
    def _initialize_enhanced_agents(self) -> Dict[str, AgentState]:
        """強化されたエージェントを初期化"""
        agents = {}
        
        for role in [AgentRole.RECON_SPECIALIST, AgentRole.VULNERABILITY_ANALYST, AgentRole.EXPLOIT_ENGINEER]:
            agent_id = f"enhanced_agent_{role.value}_{int(time.time())}"
            
            enhanced_agent = EnhancedAgent(
                agent_id, 
                role, 
                self.anthropic_client, 
                self.openai_client
            )
            
            agent_state = AgentState(
                id=agent_id,
                role=role,
                capabilities=enhanced_agent.capabilities
            )
            
            agents[agent_id] = agent_state
            self.agents[agent_id] = enhanced_agent
        
        logger.info(f"Initialized {len(agents)} enhanced agents")
        return agents
    
    async def execute_enhanced_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """強化された攻撃チェーンを実行"""
        if chain_id not in self.active_chains:
            return {"error": "Attack chain not found"}
        
        chain = self.active_chains[chain_id]
        chain.status = "running"
        chain.started_at = datetime.now()
        self.running = True
        
        self._log_to_chain(chain_id, "info", "Starting enhanced attack chain execution")
        
        try:
            self._enqueue_ready_tasks(chain)
            
            futures = []
            while self.running and (not self.task_queue.empty() or futures):
                while len(futures) < self.max_workers and not self.task_queue.empty():
                    try:
                        priority, task_id, current_chain_id = self.task_queue.get_nowait()
                        if current_chain_id != chain_id:
                            continue
                            
                        task = self._find_task_by_id(chain, task_id)
                        if task and task.status == TaskStatus.PENDING:
                            self._log_to_chain(chain_id, "debug", f"Starting enhanced task: {task.name}")
                            future = self.executor.submit(self._run_async_task, task, chain)
                            futures.append((future, task))
                    except queue.Empty:
                        break
                
                completed_futures = []
                for future, task in futures:
                    if future.done():
                        try:
                            result = future.result()
                            await self._handle_enhanced_task_completion(task, result, chain)
                            completed_futures.append((future, task))
                        except Exception as e:
                            await self._handle_task_error(task, str(e), chain)
                            completed_futures.append((future, task))
                
                for completed in completed_futures:
                    futures.remove(completed)
                
                self._enqueue_ready_tasks(chain)
                await asyncio.sleep(0.5)
            
            if all(task.status in [TaskStatus.COMPLETED, TaskStatus.FAILED] for task in chain.tasks):
                chain.status = "completed"
                chain.completed_at = datetime.now()
                self._log_to_chain(chain_id, "success", "Enhanced attack chain completed successfully")
            
            return self._generate_execution_summary(chain)
            
        except Exception as e:
            chain.status = "failed"
            self._log_to_chain(chain_id, "error", f"Enhanced attack chain execution failed: {str(e)}")
            return {"error": str(e)}
        finally:
            self.running = False
    
    def _run_async_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """非同期タスクを同期的に実行するラッパー"""
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(self.execute_enhanced_task(task, chain))
        finally:
            loop.close()
    
    async def execute_enhanced_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """強化されたタスク実行"""
        task.status = TaskStatus.RUNNING
        task.start_time = datetime.now()
        
        agent_state = self._assign_agent(task, chain)
        if not agent_state:
            raise Exception(f"No available agent for role {task.agent_role.value}")
        
        enhanced_agent = self.agents[agent_state.id]
        agent_state.status = "busy"
        agent_state.current_task = task.id
        agent_state.last_activity = datetime.now()
        
        self._log_to_chain(chain.id, "info", f"Agent {enhanced_agent.id} starting task: {task.name}")
        
        try:
            results = {}
            
            tools_to_run = task.metadata.get("tools", [])
            
            for tool_name in tools_to_run:
                self._log_to_chain(chain.id, "debug", f"Executing tool: {tool_name}")
                
                tool_result = await enhanced_agent.execute_tool(
                    tool_name, 
                    target=task.metadata.get("target", chain.target)
                )
                
                results[tool_name] = tool_result
                
                if "error" in tool_result:
                    self._log_to_chain(chain.id, "error", f"Tool {tool_name} failed: {tool_result['error']}")
                else:
                    self._log_to_chain(chain.id, "success", f"Tool {tool_name} completed successfully")
            
            analysis = await enhanced_agent.ai_analyze(task.name, results)
            results["ai_analysis"] = analysis
            
            task.status = TaskStatus.COMPLETED
            task.result = results
            task.end_time = datetime.now()
            task.actual_duration = int((task.end_time - task.start_time).total_seconds())
            
            self.knowledge_base.store(
                f"task_result_{task.stage.value}", 
                results, 
                enhanced_agent.id
            )
            
            self._log_to_chain(chain.id, "success", f"Task completed: {task.name} (Duration: {task.actual_duration}s)")
            
            return results
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            task.end_time = datetime.now()
            self._log_to_chain(chain.id, "error", f"Task failed: {task.name} - {str(e)}")
            raise e
        finally:
            agent_state.status = "idle"
            agent_state.current_task = None
            agent_state.completed_tasks.append(task.id)
    
    def _assign_agent(self, task: AttackTask, chain: AttackChain) -> Optional[AgentState]:
        """タスクにエージェントを割り当て"""
        for agent in chain.agent_states.values():
            if agent.role == task.agent_role and agent.status == "idle":
                return agent
        return None
    
    async def _handle_enhanced_task_completion(self, task: AttackTask, result: Dict[str, Any], chain: AttackChain):
        """強化されたタスク完了処理"""
        self._add_timeline_event(chain, f"Enhanced task completed: {task.name}", task.id)
    
    async def _handle_task_error(self, task: AttackTask, error: str, chain: AttackChain):
        """タスクエラー処理"""
        task.status = TaskStatus.FAILED
        task.error = error
        task.end_time = datetime.now()
        self._add_timeline_event(chain, f"Task failed: {task.name} - {error}", task.id)
    
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
            "enhanced": True,
            "summary": {
                "total_tasks": total_tasks,
                "completed_tasks": completed_tasks,
                "failed_tasks": failed_tasks,
                "success_rate": (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0,
                "total_duration": total_duration
            },
            "timeline": chain.timeline
        }
    
    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        """強化された攻撃チェーンの現在のステータスを取得"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        
        # 簡単な可視化データ
        visualization_data = {
            "nodes": [
                {
                    "id": task.id,
                    "name": task.name,
                    "stage": task.stage.value,
                    "agent": task.agent_role.value,
                    "status": task.status.value,
                    "position": {"x": i * 100, "y": 0}
                }
                for i, task in enumerate(chain.tasks)
            ],
            "edges": [
                {"from": dep_id, "to": task.id}
                for task in chain.tasks
                for dep_id in task.dependencies
            ]
        }
        
        total_tasks = len(chain.tasks)
        completed_tasks = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed_tasks / total_tasks * 100) if total_tasks > 0 else 0
        
        agent_states = []
        for agent_state in chain.agent_states.values():
            enhanced_agent = self.agents.get(agent_state.id)
            agent_info = {
                "id": agent_state.id,
                "role": agent_state.role.value,
                "status": agent_state.status,
                "current_task": agent_state.current_task,
                "completed_tasks_count": len(agent_state.completed_tasks),
                "capabilities": enhanced_agent.capabilities if enhanced_agent else [],
                "tools_available": len(enhanced_agent.tools) if enhanced_agent else 0
            }
            agent_states.append(agent_info)
        
        return {
            "chain_id": chain.id,
            "name": chain.name,
            "target": chain.target,
            "status": chain.status,
            "progress": progress,
            "enhanced": True,
            "agent_states": agent_states,
            "visualization": visualization_data,
            "recent_timeline": chain.timeline[-20:] if chain.timeline else [],
            "logs": self.execution_logs.get(chain_id, [])[-50:]
        }
    
    def stop_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """強化された攻撃チェーンを停止"""
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
        
        for agent_state in chain.agent_states.values():
            if agent_state.status == "busy":
                agent_state.status = "idle"
                agent_state.current_task = None
        
        self._add_timeline_event(chain, "Enhanced attack chain manually stopped")
        self._log_to_chain(chain_id, "warning", "Enhanced attack chain stopped by user")
        
        return {
            "status": "stopped", 
            "chain_id": chain_id,
            "enhanced": True,
            "message": "Enhanced attack chain stopped successfully"
        }


# グローバルインスタンス
_enhanced_orchestrator = None

def get_enhanced_multi_agent_orchestrator() -> EnhancedMultiAgentOrchestrator:
    """強化されたマルチエージェントオーケストレーターインスタンスを取得"""
    global _enhanced_orchestrator
    if _enhanced_orchestrator is None:
        _enhanced_orchestrator = EnhancedMultiAgentOrchestrator()
    return _enhanced_orchestrator
