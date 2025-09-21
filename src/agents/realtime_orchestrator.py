"""
Real-time Multi-Agent Orchestrator with actual tool execution
リアルタイム実行とWebUI表示対応
"""
import asyncio
import json
import time
import uuid
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional
import logging

from .attack_chain_models import AttackChain, AttackTask, AgentState, TaskStatus, AttackStage, AgentRole
from .shared_knowledge import SharedKnowledgeBase
from ..tools.real_scanning_tools import run_osint, run_nmap_scan, identify_vulnerabilities

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class RealTimeOrchestrator:
    """Real-time orchestrator with actual tool execution"""
    
    def __init__(self):
        self.knowledge_base = SharedKnowledgeBase()
        self.active_chains: Dict[str, AttackChain] = {}
        self.execution_logs: Dict[str, List[Dict[str, Any]]] = {}
        self.scan_results: Dict[str, Dict[str, Any]] = {}  # Store results by chain_id
        
        logger.info("RealTimeOrchestrator initialized")
    
    def create_attack_chain(self, target: str, objective: str) -> AttackChain:
        """Create attack chain with real tools"""
        chain = AttackChain(
            name=f"Pentest: {target}",
            target=target,
            objective=objective
        )
        
        # Define real attack tasks
        chain.tasks = [
            AttackTask(
                name="OSINT Reconnaissance",
                stage=AttackStage.RECONNAISSANCE,
                agent_role=AgentRole.RECON_SPECIALIST,
                priority=10,
                estimated_duration=30,
                metadata={"target": target, "tool": "osint"}
            ),
            AttackTask(
                name="Nmap Port Scan",
                stage=AttackStage.SCANNING,
                agent_role=AgentRole.RECON_SPECIALIST,
                dependencies=[],  # Will be set after first task
                priority=9,
                estimated_duration=60,
                metadata={"target": target, "tool": "nmap", "scan_type": "quick"}
            ),
            AttackTask(
                name="Vulnerability Analysis",
                stage=AttackStage.VULNERABILITY_ANALYSIS,
                agent_role=AgentRole.VULNERABILITY_ANALYST,
                dependencies=[],  # Will be set after scan
                priority=8,
                estimated_duration=30,
                metadata={"target": target, "tool": "vuln_scan"}
            )
        ]
        
        # Set dependencies
        chain.tasks[1].dependencies = [chain.tasks[0].id]
        chain.tasks[2].dependencies = [chain.tasks[1].id]
        
        chain.agent_states = self._initialize_agents()
        
        self.execution_logs[chain.id] = []
        self.scan_results[chain.id] = {
            "osint": {},
            "nmap": {},
            "vulnerabilities": {}
        }
        
        self._log(chain.id, "info", f"Attack chain created for {target}")
        self.active_chains[chain.id] = chain
        
        return chain
    
    def _initialize_agents(self) -> Dict[str, AgentState]:
        """Initialize agents"""
        agents = {}
        for role in [AgentRole.RECON_SPECIALIST, AgentRole.VULNERABILITY_ANALYST]:
            agent_id = f"agent_{role.value}_{uuid.uuid4().hex[:8]}"
            agents[agent_id] = AgentState(
                id=agent_id,
                role=role,
                capabilities=["osint", "nmap", "vuln_scan"] if role == AgentRole.RECON_SPECIALIST else ["cve_analysis"]
            )
        return agents
    
    def _log(self, chain_id: str, level: str, message: str):
        """Add log entry"""
        if chain_id not in self.execution_logs:
            self.execution_logs[chain_id] = []
        
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        
        self.execution_logs[chain_id].append(log_entry)
        logger.info(f"[{chain_id[:8]}] {message}")
    
    async def execute_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """Execute attack chain with real tools"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        chain.status = "running"
        chain.started_at = datetime.now()
        
        self._log(chain_id, "info", "Starting real-time attack chain execution")
        
        try:
            for task in chain.tasks:
                # Check dependencies
                if not self._are_dependencies_met(task, chain):
                    continue
                
                task.status = TaskStatus.RUNNING
                task.start_time = datetime.now()
                
                self._log(chain_id, "info", f"Executing: {task.name}")
                
                # Execute task with real tools
                result = await self._execute_real_task(task, chain)
                
                task.status = TaskStatus.COMPLETED
                task.result = result
                task.end_time = datetime.now()
                task.actual_duration = int((task.end_time - task.start_time).total_seconds())
                
                # Store results
                tool = task.metadata.get("tool")
                if tool == "osint":
                    self.scan_results[chain_id]["osint"] = result
                    self._save_results(chain_id, "osint", result)
                elif tool == "nmap":
                    self.scan_results[chain_id]["nmap"] = result
                    self._save_results(chain_id, "nmap", result)
                elif tool == "vuln_scan":
                    self.scan_results[chain_id]["vulnerabilities"] = result
                    self._save_results(chain_id, "vulnerabilities", result)
                
                self._log(chain_id, "success", f"Completed: {task.name} ({task.actual_duration}s)")
            
            chain.status = "completed"
            chain.completed_at = datetime.now()
            self._log(chain_id, "success", "Attack chain completed")
            
            return self._generate_summary(chain)
            
        except Exception as e:
            chain.status = "failed"
            self._log(chain_id, "error", f"Execution failed: {str(e)}")
            return {"error": str(e)}
    
    async def _execute_real_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """Execute task with real tools"""
        target = task.metadata.get("target")
        tool = task.metadata.get("tool")
        
        try:
            if tool == "osint":
                self._log(chain.id, "info", f"Running OSINT reconnaissance on {target}")
                result = await run_osint(target)
                self._log(chain.id, "info", f"OSINT found {len(result.get('subdomains', []))} subdomains")
                return result
            
            elif tool == "nmap":
                scan_type = task.metadata.get("scan_type", "quick")
                self._log(chain.id, "info", f"Starting Nmap {scan_type} scan on {target}")
                result = await run_nmap_scan(target, scan_type)
                ports_found = len(result.get("ports", []))
                self._log(chain.id, "info", f"Nmap scan found {ports_found} open ports")
                return result
            
            elif tool == "vuln_scan":
                self._log(chain.id, "info", "Analyzing services for vulnerabilities")
                nmap_results = self.scan_results.get(chain.id, {}).get("nmap", {})
                result = await identify_vulnerabilities(nmap_results)
                vulns_found = len(result.get("vulnerabilities", []))
                self._log(chain.id, "warning" if vulns_found > 0 else "info", 
                         f"Found {vulns_found} potential vulnerabilities")
                return result
            
            else:
                return {"error": f"Unknown tool: {tool}"}
                
        except Exception as e:
            self._log(chain.id, "error", f"Tool execution failed: {str(e)}")
            return {"error": str(e)}
    
    def _are_dependencies_met(self, task: AttackTask, chain: AttackChain) -> bool:
        """Check if dependencies are met"""
        for dep_id in task.dependencies:
            dep_task = next((t for t in chain.tasks if t.id == dep_id), None)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False
        return True
    
    def _save_results(self, chain_id: str, result_type: str, data: Dict[str, Any]):
        """Save results to JSON file"""
        results_dir = Path("reports") / chain_id
        results_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = results_dir / f"{result_type}.json"
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Saved {result_type} results to {file_path}")
    
    def _generate_summary(self, chain: AttackChain) -> Dict[str, Any]:
        """Generate execution summary"""
        total_duration = 0
        if chain.started_at and chain.completed_at:
            total_duration = int((chain.completed_at - chain.started_at).total_seconds())
        
        return {
            "chain_id": chain.id,
            "status": chain.status,
            "target": chain.target,
            "duration": total_duration,
            "tasks_completed": len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED]),
            "total_tasks": len(chain.tasks),
            "results": self.scan_results.get(chain.id, {})
        }
    
    def get_chain_status(self, chain_id: str) -> Dict[str, Any]:
        """Get real-time status"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        
        # Calculate progress
        total = len(chain.tasks)
        completed = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed / total * 100) if total > 0 else 0
        
        # Get current task
        current_task = next((t for t in chain.tasks if t.status == TaskStatus.RUNNING), None)
        
        return {
            "chain_id": chain.id,
            "target": chain.target,
            "status": chain.status,
            "progress": progress,
            "current_task": current_task.name if current_task else None,
            "logs": self.execution_logs.get(chain_id, [])[-20:],  # Last 20 logs
            "results": self.scan_results.get(chain_id, {}),
            "agent_states": [
                {
                    "id": agent.id,
                    "role": agent.role.value,
                    "status": agent.status
                }
                for agent in chain.agent_states.values()
            ]
        }
    
    def stop_attack_chain(self, chain_id: str) -> Dict[str, Any]:
        """Stop execution"""
        if chain_id in self.active_chains:
            chain = self.active_chains[chain_id]
            chain.status = "stopped"
            self._log(chain_id, "warning", "Chain stopped by user")
            return {"status": "stopped", "chain_id": chain_id}
        return {"error": "Chain not found"}


# Global instance
_orchestrator = None

def get_realtime_orchestrator() -> RealTimeOrchestrator:
    """Get global orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = RealTimeOrchestrator()
    return _orchestrator
