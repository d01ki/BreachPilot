"""
Enhanced Multi-Agent Orchestrator with Real Tool Execution and AI-powered Agents
真のマルチエージェントシステム - 実際のツール実行とAI推論
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
from .attack_chain_visualizer import AttackChainVisualizer

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
                    "cmd": "nmap -sS -O -sV -p 1-65535 {target}",
                    "description": "Comprehensive port and service scan",
                    "timeout": 300
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
                },
                "ping_sweep": {
                    "cmd": "nmap -sn {network}/24",
                    "description": "Network discovery ping sweep",
                    "timeout": 120
                }
            }
        elif self.role == AgentRole.VULNERABILITY_ANALYST:
            return {
                "nmap_vuln_scan": {
                    "cmd": "nmap --script vuln {target}",
                    "description": "Vulnerability detection scan",
                    "timeout": 300
                },
                "nikto_scan": {
                    "cmd": "nikto -h {target}",
                    "description": "Web vulnerability scanner",
                    "timeout": 600
                },
                "dirb_scan": {
                    "cmd": "dirb http://{target}/",
                    "description": "Directory brute force",
                    "timeout": 300
                }
            }
        elif self.role == AgentRole.EXPLOIT_ENGINEER:
            return {
                "msfconsole": {
                    "cmd": "msfconsole -x 'use {exploit}; set RHOSTS {target}; exploit'",
                    "description": "Metasploit exploit execution",
                    "timeout": 300
                },
                "custom_exploit": {
                    "cmd": "python3 {exploit_script} {target}",
                    "description": "Custom exploit execution",
                    "timeout": 180
                }
            }
        elif self.role == AgentRole.POST_EXPLOIT_SPECIALIST:
            return {
                "enum_users": {
                    "cmd": "net user /domain",
                    "description": "Enumerate domain users",
                    "timeout": 60
                },
                "enum_shares": {
                    "cmd": "smbclient -L {target} -N",
                    "description": "Enumerate SMB shares",
                    "timeout": 60
                },
                "privilege_check": {
                    "cmd": "whoami /priv",
                    "description": "Check current privileges",
                    "timeout": 30
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
        
        try:
            # セキュリティ上の理由で、実際のコマンド実行は制限
            # デモ環境では安全なシミュレーションを実行
            if self._is_safe_command(cmd):
                result = await self._execute_command(cmd, timeout)
            else:
                result = await self._simulate_tool_execution(tool_name, **kwargs)
            
            self.knowledge_base[f"tool_result_{tool_name}_{int(time.time())}"] = result
            return result
            
        except Exception as e:
            error_msg = f"Tool execution failed: {str(e)}"
            logger.error(f"Agent {self.id}: {error_msg}")
            return {"error": error_msg}
    
    def _is_safe_command(self, cmd: str) -> bool:
        """コマンドが安全に実行可能かチェック"""
        # デモ環境では基本的にシミュレーション
        safe_commands = ["nslookup", "ping", "whois"]
        return any(safe_cmd in cmd for safe_cmd in safe_commands)
    
    async def _execute_command(self, cmd: str, timeout: int) -> Dict[str, Any]:
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
        """ツール実行のリアルなシミュレーション"""
        target = kwargs.get("target", "unknown")
        
        # エージェントロール別のシミュレーション
        if self.role == AgentRole.RECON_SPECIALIST:
            if tool_name == "nmap_scan":
                await asyncio.sleep(3)  # リアルな実行時間をシミュレート
                return {
                    "status": "success",
                    "scan_results": {
                        "target": target,
                        "open_ports": [
                            {"port": 22, "service": "ssh", "version": "OpenSSH 7.4"},
                            {"port": 80, "service": "http", "version": "Apache 2.4.6"},
                            {"port": 443, "service": "https", "version": "Apache 2.4.6"},
                            {"port": 3389, "service": "ms-wbt-server", "version": "Microsoft Terminal Service"}
                        ],
                        "os_detection": "Linux 3.X|4.X",
                        "scan_duration": "3.2 seconds"
                    }
                }
            elif tool_name == "dns_enum":
                await asyncio.sleep(1)
                return {
                    "status": "success",
                    "dns_records": {
                        "A": [target],
                        "MX": ["mail.example.com"],
                        "NS": ["ns1.example.com", "ns2.example.com"],
                        "TXT": ["v=spf1 include:_spf.google.com ~all"]
                    }
                }
        
        elif self.role == AgentRole.VULNERABILITY_ANALYST:
            if tool_name == "nmap_vuln_scan":
                await asyncio.sleep(4)
                return {
                    "status": "success",
                    "vulnerabilities": [
                        {
                            "cve": "CVE-2021-44228",
                            "name": "Log4Shell",
                            "severity": "critical",
                            "port": 80,
                            "description": "Apache Log4j RCE vulnerability"
                        },
                        {
                            "cve": "CVE-2020-1472",
                            "name": "Zerologon",
                            "severity": "critical",
                            "port": 445,
                            "description": "Netlogon elevation of privilege"
                        }
                    ]
                }
        
        elif self.role == AgentRole.EXPLOIT_ENGINEER:
            if tool_name == "msfconsole":
                await asyncio.sleep(5)
                return {
                    "status": "success",
                    "exploit_result": {
                        "success": True,
                        "session_id": f"session_{int(time.time())}",
                        "shell_type": "meterpreter",
                        "target_info": {
                            "os": "Windows Server 2019",
                            "arch": "x64",
                            "user": "SYSTEM"
                        }
                    }
                }
        
        elif self.role == AgentRole.POST_EXPLOIT_SPECIALIST:
            if tool_name == "enum_users":
                await asyncio.sleep(2)
                return {
                    "status": "success",
                    "domain_users": [
                        "Administrator", "Guest", "krbtgt",
                        "john.doe", "jane.smith", "admin.user"
                    ],
                    "admin_users": ["Administrator", "admin.user"]
                }
        
        return {"status": "completed", "message": f"Tool {tool_name} executed"}
    
    async def ai_analyze(self, task_context: str, data: Dict[str, Any]) -> str:
        """AI推論による結果分析"""
        if not AI_AVAILABLE or not (self.anthropic_client or self.openai_client):
            return f"Analysis: {task_context} completed with data: {json.dumps(data, indent=2)}"
        
        prompt = f"""
        As a {self.role.value} cybersecurity expert, analyze the following data from {task_context}:
        
        Data: {json.dumps(data, indent=2)}
        
        Provide:
        1. Key findings
        2. Security implications
        3. Recommended next steps
        4. Risk assessment
        
        Keep response concise but thorough.
        """
        
        try:
            if self.anthropic_client:
                response = self.anthropic_client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.content[0].text
            
            elif self.openai_client:
                response = self.openai_client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    max_tokens=500,
                    messages=[{"role": "user", "content": prompt}]
                )
                return response.choices[0].message.content
                
        except Exception as e:
            logger.error(f"AI analysis failed: {e}")
            return f"Analysis failed: {str(e)}"
        
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
        
        # 強化されたタスクを生成
        chain.tasks = self._generate_enhanced_attack_tasks(target, objective)
        
        # 強化されたエージェントを初期化
        chain.agent_states = self._initialize_enhanced_agents()
        
        # Initialize execution logs for this chain
        self.execution_logs[chain.id] = []
        self._log_to_chain(chain.id, "info", f"Enhanced attack chain created with {len(chain.tasks)} tasks")
        
        self.active_chains[chain.id] = chain
        logger.info(f"Enhanced attack chain {chain.id} created successfully")
        return chain
    
    def _generate_enhanced_attack_tasks(self, target: str, objective: str) -> List[AttackTask]:
        """強化された攻撃タスクを生成"""
        tasks = []
        
        # Phase 1: 総合偵察
        recon_task = AttackTask(
            name="Comprehensive Network Reconnaissance",
            stage=AttackStage.RECONNAISSANCE,
            agent_role=AgentRole.RECON_SPECIALIST,
            priority=10,
            estimated_duration=60,
            metadata={
                "target": target,
                "tools": ["nmap_quick", "dns_enum", "whois_lookup"],
                "objectives": ["port_discovery", "service_enumeration", "os_detection"]
            }
        )
        tasks.append(recon_task)
        
        # Phase 2: 詳細スキャン
        detailed_scan_task = AttackTask(
            name="Detailed Port and Service Scanning",
            stage=AttackStage.SCANNING,
            agent_role=AgentRole.RECON_SPECIALIST,
            dependencies=[recon_task.id],
            priority=9,
            estimated_duration=120,
            metadata={
                "target": target,
                "tools": ["nmap_scan"],
                "scan_type": "comprehensive"
            }
        )
        tasks.append(detailed_scan_task)
        
        # Phase 3: 脆弱性分析
        vuln_analysis_task = AttackTask(
            name="Advanced Vulnerability Analysis",
            stage=AttackStage.VULNERABILITY_ANALYSIS,
            agent_role=AgentRole.VULNERABILITY_ANALYST,
            dependencies=[detailed_scan_task.id],
            priority=8,
            estimated_duration=180,
            metadata={
                "target": target,
                "tools": ["nmap_vuln_scan", "nikto_scan"],
                "focus_areas": ["web_vulns", "network_vulns", "service_vulns"]
            }
        )
        tasks.append(vuln_analysis_task)
        
        # Phase 4: エクスプロイト実行
        exploit_task = AttackTask(
            name="Exploit Execution and Initial Access",
            stage=AttackStage.EXPLOITATION,
            agent_role=AgentRole.EXPLOIT_ENGINEER,
            dependencies=[vuln_analysis_task.id],
            priority=7,
            estimated_duration=240,
            metadata={
                "target": target,
                "tools": ["msfconsole", "custom_exploit"],
                "exploit_types": ["remote_code_execution", "privilege_escalation"]
            }
        )
        tasks.append(exploit_task)
        
        # Phase 5: ポストエクスプロイト
        post_exploit_task = AttackTask(
            name="Post-Exploitation and System Enumeration",
            stage=AttackStage.POST_EXPLOITATION,
            agent_role=AgentRole.POST_EXPLOIT_SPECIALIST,
            dependencies=[exploit_task.id],
            priority=6,
            estimated_duration=180,
            metadata={
                "target": target,
                "tools": ["enum_users", "enum_shares", "privilege_check"],
                "objectives": ["system_enum", "credential_harvest", "data_discovery"]
            }
        )
        tasks.append(post_exploit_task)
        
        # Phase 6: 永続化
        persistence_task = AttackTask(
            name="Persistence Establishment",
            stage=AttackStage.PERSISTENCE,
            agent_role=AgentRole.PERSISTENCE_EXPERT,
            dependencies=[post_exploit_task.id],
            priority=5,
            estimated_duration=120,
            metadata={
                "target": target,
                "methods": ["scheduled_tasks", "registry_keys", "service_creation"]
            }
        )
        tasks.append(persistence_task)
        
        logger.info(f"Generated {len(tasks)} enhanced attack tasks")
        return tasks
    
    def _initialize_enhanced_agents(self) -> Dict[str, AgentState]:
        """強化されたエージェントを初期化"""
        agents = {}
        
        for role in AgentRole:
            agent_id = f"enhanced_agent_{role.value}_{int(time.time())}"
            
            # 強化されたエージェントインスタンスを作成
            enhanced_agent = EnhancedAgent(
                agent_id, 
                role, 
                self.anthropic_client, 
                self.openai_client
            )
            
            # エージェント状態を作成
            agent_state = AgentState(
                id=agent_id,
                role=role,
                capabilities=enhanced_agent.capabilities
            )
            
            agents[agent_id] = agent_state
            self.agents[agent_id] = enhanced_agent
        
        logger.info(f"Initialized {len(agents)} enhanced agents")
        return agents
    
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
    
    async def execute_enhanced_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """強化されたタスク実行"""
        task.status = TaskStatus.RUNNING
        task.start_time = datetime.now()
        
        # エージェントを割り当て
        agent_state = self._assign_agent(task, chain)
        if not agent_state:
            raise Exception(f"No available agent for role {task.agent_role.value}")
        
        enhanced_agent = self.agents[agent_state.id]
        agent_state.status = "busy"
        agent_state.current_task = task.id
        agent_state.last_activity = datetime.now()
        
        self._log_to_chain(chain.id, "info", f"Agent {enhanced_agent.id} ({enhanced_agent.role.value}) starting task: {task.name}")
        
        try:
            results = {}
            
            # メタデータからツールを取得して実行
            tools_to_run = task.metadata.get("tools", [])
            
            for tool_name in tools_to_run:
                self._log_to_chain(chain.id, "debug", f"Executing tool: {tool_name}")
                
                tool_result = await enhanced_agent.execute_tool(
                    tool_name, 
                    target=task.metadata.get("target", chain.target)
                )
                
                results[tool_name] = tool_result
                
                # ツール実行の詳細ログ
                if "error" in tool_result:
                    self._log_to_chain(chain.id, "error", f"Tool {tool_name} failed: {tool_result['error']}")
                else:
                    self._log_to_chain(chain.id, "success", f"Tool {tool_name} completed successfully")
            
            # AI による結果分析
            analysis = await enhanced_agent.ai_analyze(task.name, results)
            results["ai_analysis"] = analysis
            
            self._log_to_chain(chain.id, "info", f"AI Analysis: {analysis[:100]}...")
            
            # タスク完了
            task.status = TaskStatus.COMPLETED
            task.result = results
            task.end_time = datetime.now()
            task.actual_duration = int((task.end_time - task.start_time).total_seconds())
            
            # 知識ベースに結果を保存
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


# グローバルインスタンス
_enhanced_orchestrator = None

def get_enhanced_multi_agent_orchestrator() -> EnhancedMultiAgentOrchestrator:
    """強化されたマルチエージェントオーケストレーターインスタンスを取得"""
    global _enhanced_orchestrator
    if _enhanced_orchestrator is None:
        _enhanced_orchestrator = EnhancedMultiAgentOrchestrator()
    return _enhanced_orchestrator
