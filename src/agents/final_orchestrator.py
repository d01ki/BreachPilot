"""
Final orchestrator: Mock port scan + Simple pattern-based CVE analysis
"""
import asyncio
import json
import uuid
import os
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any
import logging

from .attack_chain_models import AttackChain, AttackTask, AgentState, TaskStatus, AttackStage, AgentRole
from .shared_knowledge import SharedKnowledgeBase

# Mock port scan
from ..tools.port_scan_mock import run_mock_port_scan

# Simple analyzer
from .simple_vuln_analyzer import get_simple_analyzer

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class FinalOrchestrator:
    """Mock scan + Simple CVE analysis"""
    
    def __init__(self):
        self.knowledge_base = SharedKnowledgeBase()
        self.active_chains: Dict[str, AttackChain] = {}
        self.execution_logs: Dict[str, List[Dict[str, Any]]] = {}
        self.scan_results: Dict[str, Dict[str, Any]] = {}
        
        logger.info("🎯 FinalOrchestrator: Mock port scan + Simple CVE analysis")
    
    def create_attack_chain(self, target: str, objective: str) -> AttackChain:
        """Create attack chain"""
        chain = AttackChain(
            name=f"Pentest: {target}",
            target=target,
            objective=objective
        )
        
        chain.tasks = [
            AttackTask(
                name="Port Scan (Mock)",
                stage=AttackStage.SCANNING,
                agent_role=AgentRole.RECON_SPECIALIST,
                priority=10,
                estimated_duration=5,
                metadata={"target": target, "tool": "port_scan"}
            ),
            AttackTask(
                name="CVE Analysis",
                stage=AttackStage.VULNERABILITY_ANALYSIS,
                agent_role=AgentRole.VULNERABILITY_ANALYST,
                dependencies=[],
                priority=9,
                estimated_duration=15,
                metadata={"target": target, "tool": "cve_analysis"}
            )
        ]
        
        # Set dependencies
        chain.tasks[1].dependencies = [chain.tasks[0].id]
        
        chain.agent_states = self._initialize_agents()
        
        self.execution_logs[chain.id] = []
        self.scan_results[chain.id] = {
            "scan": {},
            "vulnerabilities": {}
        }
        
        self._log(chain.id, "info", f"Chain created for {target}")
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
                capabilities=["port_scan", "cve_analysis"]
            )
        return agents
    
    def _log(self, chain_id: str, level: str, message: str):
        """Add log"""
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
        """Execute chain"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        chain.status = "running"
        chain.started_at = datetime.now()
        
        self._log(chain_id, "info", "Starting execution")
        
        try:
            for task in chain.tasks:
                if not self._are_dependencies_met(task, chain):
                    continue
                
                task.status = TaskStatus.RUNNING
                task.start_time = datetime.now()
                
                self._log(chain_id, "info", f"Executing: {task.name}")
                
                result = await self._execute_task(task, chain)
                
                task.status = TaskStatus.COMPLETED
                task.result = result
                task.end_time = datetime.now()
                task.actual_duration = int((task.end_time - task.start_time).total_seconds())
                
                tool = task.metadata.get("tool")
                if tool == "port_scan":
                    self.scan_results[chain_id]["scan"] = result
                    self._save_results(chain_id, "scan", result)
                elif tool == "cve_analysis":
                    self.scan_results[chain_id]["vulnerabilities"] = result
                    self._save_results(chain_id, "vulnerabilities", result)
                
                self._log(chain_id, "success", f"Completed: {task.name}")
            
            chain.status = "completed"
            chain.completed_at = datetime.now()
            self._log(chain_id, "success", "Chain completed")
            
            return self._generate_summary(chain)
            
        except Exception as e:
            chain.status = "failed"
            self._log(chain_id, "error", f"Failed: {str(e)}")
            return {"error": str(e)}
    
    async def _execute_task(self, task: AttackTask, chain: AttackChain) -> Dict[str, Any]:
        """Execute task"""
        target = task.metadata.get("target")
        tool = task.metadata.get("tool")
        
        try:
            if tool == "port_scan":
                self._log(chain.id, "info", "Running mock port scan")
                result = await run_mock_port_scan(target)
                self._log(chain.id, "info", f"Found {len(result.get('ports', []))} open ports")
                return result
            
            elif tool == "cve_analysis":
                self._log(chain.id, "info", "🔍 Starting CVE analysis")
                
                scan_data = self.scan_results.get(chain.id, {}).get("scan", {})
                
                # Use simple analyzer
                analyzer = get_simple_analyzer()
                result = await analyzer.analyze(scan_data)
                
                vulns = len(result.get("vulnerabilities", []))
                self._log(chain.id, "success", f"Found {vulns} CVEs")
                
                return result
            
            else:
                return {"error": f"Unknown tool: {tool}"}
                
        except Exception as e:
            self._log(chain.id, "error", f"Task failed: {str(e)}")
            raise
    
    def _are_dependencies_met(self, task: AttackTask, chain: AttackChain) -> bool:
        """Check dependencies"""
        for dep_id in task.dependencies:
            dep_task = next((t for t in chain.tasks if t.id == dep_id), None)
            if not dep_task or dep_task.status != TaskStatus.COMPLETED:
                return False
        return True
    
    def _save_results(self, chain_id: str, result_type: str, data: Dict[str, Any]):
        """Save to JSON"""
        results_dir = Path("reports") / chain_id
        results_dir.mkdir(parents=True, exist_ok=True)
        
        file_path = results_dir / f"{result_type}.json"
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2, default=str)
        
        logger.info(f"Saved to {file_path}")
    
    def _generate_summary(self, chain: AttackChain) -> Dict[str, Any]:
        """Generate summary"""
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
        """Get status"""
        if chain_id not in self.active_chains:
            return {"error": "Chain not found"}
        
        chain = self.active_chains[chain_id]
        
        total = len(chain.tasks)
        completed = len([t for t in chain.tasks if t.status == TaskStatus.COMPLETED])
        progress = (completed / total * 100) if total > 0 else 0
        
        current_task = next((t for t in chain.tasks if t.status == TaskStatus.RUNNING), None)
        
        return {
            "chain_id": chain.id,
            "target": chain.target,
            "status": chain.status,
            "progress": progress,
            "current_task": current_task.name if current_task else None,
            "logs": self.execution_logs.get(chain_id, [])[-20:],
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
        """Stop chain"""
        if chain_id in self.active_chains:
            chain = self.active_chains[chain_id]
            chain.status = "stopped"
            self._log(chain_id, "warning", "Stopped")
            return {"status": "stopped", "chain_id": chain_id}
        return {"error": "Chain not found"}


# Global instance
_final_orchestrator = None

def get_final_orchestrator() -> FinalOrchestrator:
    """Get orchestrator"""
    global _final_orchestrator
    if _final_orchestrator is None:
        _final_orchestrator = FinalOrchestrator()
    return _final_orchestrator
