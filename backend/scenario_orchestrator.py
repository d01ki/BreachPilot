"""Scenario Orchestrator

Orchestrates the attack scenario generation pipeline:
1. Build attack graph from reconnaissance
2. Generate attack scenarios
3. Synthesize PoCs
4. Execute in sandbox (with human approval)
"""

import logging
from typing import List, Dict, Any, Optional

from backend.models import ScanSession, NmapResult, AnalystResult
from backend.scenario.attack_graph_builder import AttackGraphBuilder
from backend.scenario.scenario_generator import ScenarioGenerator
from backend.scenario.poc_synthesizer import PoCSynthesizer
from backend.scenario.sandbox_executor import SandboxExecutor
from backend.scenario.models import AttackScenario, ScenarioStatus

from langchain_openai import ChatOpenAI
import os

logger = logging.getLogger(__name__)


class ScenarioOrchestrator:
    """Orchestrates the attack scenario generation and execution pipeline"""
    
    def __init__(self, 
                 allowed_targets: Optional[List[str]] = None,
                 use_llm: bool = True):
        """
        Initialize scenario orchestrator
        
        Args:
            allowed_targets: Whitelist of allowed targets for execution
            use_llm: Whether to use LLM for scenario generation
        """
        self.graph_builder = AttackGraphBuilder()
        
        # Initialize LLM if API key is available
        llm = None
        if use_llm and os.getenv("OPENAI_API_KEY"):
            try:
                llm = ChatOpenAI(model="gpt-4", temperature=0.7)
                logger.info("✅ LLM initialized for scenario generation")
            except Exception as e:
                logger.warning(f"⚠️ LLM initialization failed: {e}")
        
        self.scenario_generator = ScenarioGenerator(llm=llm)
        self.poc_synthesizer = PoCSynthesizer()
        self.sandbox_executor = SandboxExecutor(
            sandbox_type="docker",
            allowed_targets=allowed_targets or []
        )
        
        logger.info("🎯 ScenarioOrchestrator initialized")
    
    def generate_attack_graph(self, 
                             session: ScanSession) -> Dict[str, Any]:
        """
        Generate attack graph from scan results
        
        Args:
            session: Scan session with nmap and analyst results
            
        Returns:
            Attack graph data
        """
        logger.info(f"🔨 Generating attack graph for {session.target_ip}")
        
        if not session.nmap_result:
            raise ValueError("Nmap scan must be completed first")
        
        # Build attack graph
        attack_graph = self.graph_builder.build_graph(
            target_ip=session.target_ip,
            nmap_result=session.nmap_result,
            analyst_result=session.analyst_result
        )
        
        # Get visualization data
        viz_data = self.graph_builder.get_graph_visualization_data()
        
        # Serialize and store in session
        graph_dict = attack_graph.model_dump()
        graph_dict["visualization"] = viz_data
        session.attack_graph = graph_dict
        
        logger.info(f"✅ Attack graph created: {attack_graph.total_nodes} nodes, "
                   f"{attack_graph.total_vulnerabilities} vulnerabilities")
        
        return graph_dict
    
    def generate_scenarios(self, 
                          session: ScanSession,
                          max_scenarios: int = 5) -> List[Dict[str, Any]]:
        """
        Generate attack scenarios from attack graph
        
        Args:
            session: Scan session with attack graph
            max_scenarios: Maximum number of scenarios to generate
            
        Returns:
            List of generated scenarios
        """
        logger.info(f"🎯 Generating attack scenarios (max: {max_scenarios})")
        
        if not session.attack_graph:
            raise ValueError("Attack graph must be generated first")
        
        # Reconstruct attack graph from dict
        from backend.scenario.models import AttackGraph
        attack_graph = AttackGraph(**session.attack_graph)
        
        # Generate scenarios
        scenarios = self.scenario_generator.generate_scenarios(
            attack_graph=attack_graph,
            max_scenarios=max_scenarios
        )
        
        # Serialize and store in session
        scenarios_dict = [s.model_dump() for s in scenarios]
        session.attack_scenarios = scenarios_dict
        
        logger.info(f"✅ Generated {len(scenarios)} attack scenarios")
        
        # Log scenario summary
        for i, scenario in enumerate(scenarios, 1):
            logger.info(f"  {i}. {scenario.name} (Success: {scenario.overall_success_probability:.0%}, "
                       f"Steps: {len(scenario.steps)})")
        
        return scenarios_dict
    
    def approve_scenario(self, 
                        session: ScanSession,
                        scenario_id: str,
                        approved_by: str = "user") -> Dict[str, Any]:
        """
        Approve scenario for execution (Human-in-the-loop)
        
        Args:
            session: Scan session
            scenario_id: Scenario ID to approve
            approved_by: User who approved
            
        Returns:
            Updated scenario
        """
        logger.info(f"👍 Approving scenario: {scenario_id}")
        
        # Find and update scenario
        for scenario_dict in session.attack_scenarios:
            if scenario_dict["scenario_id"] == scenario_id:
                scenario_dict["status"] = ScenarioStatus.APPROVED
                scenario_dict["approved_by"] = approved_by
                scenario_dict["approved_at"] = str(datetime.now())
                
                logger.info(f"✅ Scenario approved: {scenario_dict['name']}")
                return scenario_dict
        
        raise ValueError(f"Scenario {scenario_id} not found")
    
    def reject_scenario(self, 
                       session: ScanSession,
                       scenario_id: str,
                       reason: str = "") -> Dict[str, Any]:
        """
        Reject scenario (Human-in-the-loop)
        
        Args:
            session: Scan session
            scenario_id: Scenario ID to reject
            reason: Rejection reason
            
        Returns:
            Updated scenario
        """
        logger.info(f"👎 Rejecting scenario: {scenario_id}")
        
        for scenario_dict in session.attack_scenarios:
            if scenario_dict["scenario_id"] == scenario_id:
                scenario_dict["status"] = ScenarioStatus.REJECTED
                scenario_dict["reviewer_notes"] = reason
                
                logger.info(f"❌ Scenario rejected: {scenario_dict['name']}")
                return scenario_dict
        
        raise ValueError(f"Scenario {scenario_id} not found")
    
    def synthesize_pocs(self, 
                       session: ScanSession,
                       scenario_id: str) -> Dict[str, Any]:
        """
        Synthesize PoCs for approved scenario
        
        Args:
            session: Scan session
            scenario_id: Scenario ID to synthesize PoCs for
            
        Returns:
            Synthesized PoC data
        """
        logger.info(f"🧪 Synthesizing PoCs for scenario: {scenario_id}")
        
        # Find scenario
        scenario_dict = None
        for s in session.attack_scenarios:
            if s["scenario_id"] == scenario_id:
                scenario_dict = s
                break
        
        if not scenario_dict:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        # Check if approved
        if scenario_dict.get("status") != ScenarioStatus.APPROVED:
            raise ValueError("Scenario must be approved before PoC synthesis")
        
        # Reconstruct scenario object
        from backend.scenario.models import AttackScenario
        scenario = AttackScenario(**scenario_dict)
        
        # Synthesize PoCs
        synthesized_pocs = self.poc_synthesizer.synthesize_poc(
            scenario=scenario,
            target_ip=session.target_ip
        )
        
        # Store in session
        if not session.synthesized_pocs:
            session.synthesized_pocs = {}
        session.synthesized_pocs[scenario_id] = synthesized_pocs
        
        logger.info(f"✅ Synthesized {synthesized_pocs['total_pocs']} PoCs")
        
        return synthesized_pocs
    
    def execute_scenario(self, 
                        session: ScanSession,
                        scenario_id: str,
                        timeout: int = 3600) -> Dict[str, Any]:
        """
        Execute approved scenario in sandbox
        
        Args:
            session: Scan session
            scenario_id: Scenario ID to execute
            timeout: Execution timeout in seconds
            
        Returns:
            Execution result
        """
        logger.info(f"🚀 Executing scenario in sandbox: {scenario_id}")
        
        # Find scenario
        scenario_dict = None
        for s in session.attack_scenarios:
            if s["scenario_id"] == scenario_id:
                scenario_dict = s
                break
        
        if not scenario_dict:
            raise ValueError(f"Scenario {scenario_id} not found")
        
        # Check if approved
        if scenario_dict.get("status") != ScenarioStatus.APPROVED:
            raise ValueError("Scenario must be approved before execution")
        
        # Check if PoCs are synthesized
        if not session.synthesized_pocs or scenario_id not in session.synthesized_pocs:
            raise ValueError("PoCs must be synthesized before execution")
        
        # Reconstruct scenario object
        from backend.scenario.models import AttackScenario
        scenario = AttackScenario(**scenario_dict)
        
        # Get synthesized PoCs
        synthesized_pocs = session.synthesized_pocs[scenario_id]
        
        # Execute in sandbox
        execution_result = self.sandbox_executor.execute_scenario(
            scenario=scenario,
            target_ip=session.target_ip,
            synthesized_pocs=synthesized_pocs,
            timeout=timeout
        )
        
        # Update scenario with results
        scenario_dict.update({
            "execution_started_at": str(scenario.execution_started_at),
            "execution_completed_at": str(scenario.execution_completed_at),
            "execution_success": scenario.execution_success,
            "execution_logs": scenario.execution_logs,
            "artifacts_collected": scenario.artifacts_collected,
            "status": scenario.status
        })
        
        # Store execution result
        session.scenario_execution_results.append({
            "scenario_id": scenario_id,
            "timestamp": str(datetime.now()),
            "result": execution_result
        })
        
        logger.info(f"✅ Scenario execution completed. Success: {execution_result.get('success')}")
        
        return execution_result
    
    def get_scenario_summary(self, session: ScanSession) -> Dict[str, Any]:
        """
        Get summary of all scenarios and their status
        
        Args:
            session: Scan session
            
        Returns:
            Summary data
        """
        if not session.attack_scenarios:
            return {
                "total_scenarios": 0,
                "status_breakdown": {},
                "scenarios": []
            }
        
        status_counts = {}
        for scenario in session.attack_scenarios:
            status = scenario.get("status", "unknown")
            status_counts[status] = status_counts.get(status, 0) + 1
        
        return {
            "total_scenarios": len(session.attack_scenarios),
            "status_breakdown": status_counts,
            "scenarios": [
                {
                    "scenario_id": s["scenario_id"],
                    "name": s["name"],
                    "status": s["status"],
                    "success_probability": s["overall_success_probability"],
                    "estimated_time": s["estimated_total_time"],
                    "steps": len(s["steps"]),
                    "risk_level": s["risk_level"]
                }
                for s in session.attack_scenarios
            ]
        }
    
    def cleanup(self):
        """Clean up temporary files and resources"""
        logger.info("🧹 Cleaning up scenario orchestrator resources")
        self.poc_synthesizer.cleanup()
        self.sandbox_executor.cleanup()


from datetime import datetime