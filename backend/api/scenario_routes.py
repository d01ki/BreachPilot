"""API Routes for Attack Scenario Generation

Provides REST API endpoints for:
- Attack graph generation
- Scenario generation and management
- Human-in-the-loop approval/rejection
- PoC synthesis
- Sandbox execution
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from pydantic import BaseModel, Field
from typing import List, Optional, Dict, Any
import logging

from backend.orchestrator import ScanOrchestrator
from backend.scenario_orchestrator import ScenarioOrchestrator
from backend.models import ScanSession

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scenario", tags=["Attack Scenarios"])

# Global instances
scan_orchestrator = ScanOrchestrator()
scenario_orchestrator = ScenarioOrchestrator(
    allowed_targets=["192.168.1.0/24", "10.0.0.0/8"],  # Configure allowed targets
    use_llm=True
)


class ScenarioApprovalRequest(BaseModel):
    approved_by: str = Field(default="user", description="User who approved")


class ScenarioRejectionRequest(BaseModel):
    reason: str = Field(default="", description="Rejection reason")


class ScenarioExecutionRequest(BaseModel):
    timeout: int = Field(default=3600, description="Execution timeout in seconds")


@router.post("/{session_id}/generate-graph")
async def generate_attack_graph(session_id: str):
    """Generate attack graph from scan results"""
    try:
        logger.info(f"🔨 API: Generating attack graph for session {session_id}")
        
        session = scan_orchestrator._get_session(session_id)
        
        if not session.nmap_result:
            raise HTTPException(
                status_code=400,
                detail="Nmap scan must be completed first"
            )
        
        attack_graph = scenario_orchestrator.generate_attack_graph(session)
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "attack_graph": {
                "graph_id": attack_graph["graph_id"],
                "total_nodes": attack_graph["total_nodes"],
                "total_vulnerabilities": attack_graph["total_vulnerabilities"],
                "total_services": attack_graph["total_services"],
                "entry_points": len(attack_graph["entry_points"]),
                "high_value_targets": len(attack_graph["high_value_targets"]),
                "generation_time": attack_graph["generation_time"]
            },
            "visualization": attack_graph.get("visualization", {})
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating attack graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/generate-scenarios")
async def generate_scenarios(session_id: str, max_scenarios: int = 5):
    """Generate attack scenarios from attack graph"""
    try:
        logger.info(f"🎯 API: Generating scenarios for session {session_id}")
        
        session = scan_orchestrator._get_session(session_id)
        
        if not session.attack_graph:
            raise HTTPException(
                status_code=400,
                detail="Attack graph must be generated first"
            )
        
        scenarios = scenario_orchestrator.generate_scenarios(
            session=session,
            max_scenarios=max_scenarios
        )
        
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "total_scenarios": len(scenarios),
            "scenarios": [
                {
                    "scenario_id": s["scenario_id"],
                    "name": s["name"],
                    "description": s["description"],
                    "status": s["status"],
                    "overall_success_probability": s["overall_success_probability"],
                    "estimated_total_time": s["estimated_total_time"],
                    "risk_level": s["risk_level"],
                    "steps": len(s["steps"]),
                    "required_tools": s["required_tools"],
                    "mitre_techniques": s.get("mitre_techniques", [])
                }
                for s in scenarios
            ]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error generating scenarios: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/scenarios")
async def list_scenarios(session_id: str):
    """List all scenarios for a session"""
    try:
        session = scan_orchestrator._get_session(session_id)
        
        if not session.attack_scenarios:
            return {
                "success": True,
                "session_id": session_id,
                "total_scenarios": 0,
                "scenarios": []
            }
        
        summary = scenario_orchestrator.get_scenario_summary(session)
        
        return {
            "success": True,
            "session_id": session_id,
            **summary
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error listing scenarios: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/scenarios/{scenario_id}")
async def get_scenario_details(session_id: str, scenario_id: str):
    """Get detailed information about a specific scenario"""
    try:
        session = scan_orchestrator._get_session(session_id)
        
        for scenario in session.attack_scenarios:
            if scenario["scenario_id"] == scenario_id:
                return {
                    "success": True,
                    "session_id": session_id,
                    "scenario": scenario
                }
        
        raise HTTPException(status_code=404, detail="Scenario not found")
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting scenario details: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/scenarios/{scenario_id}/approve")
async def approve_scenario(session_id: str, 
                          scenario_id: str,
                          request: ScenarioApprovalRequest):
    """Approve scenario for execution (Human-in-the-loop)"""
    try:
        logger.info(f"👍 API: Approving scenario {scenario_id}")
        
        session = scan_orchestrator._get_session(session_id)
        
        updated_scenario = scenario_orchestrator.approve_scenario(
            session=session,
            scenario_id=scenario_id,
            approved_by=request.approved_by
        )
        
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "scenario_id": scenario_id,
            "status": updated_scenario["status"],
            "approved_by": updated_scenario["approved_by"],
            "approved_at": updated_scenario["approved_at"]
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error approving scenario: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/scenarios/{scenario_id}/reject")
async def reject_scenario(session_id: str, 
                         scenario_id: str,
                         request: ScenarioRejectionRequest):
    """Reject scenario (Human-in-the-loop)"""
    try:
        logger.info(f"👎 API: Rejecting scenario {scenario_id}")
        
        session = scan_orchestrator._get_session(session_id)
        
        updated_scenario = scenario_orchestrator.reject_scenario(
            session=session,
            scenario_id=scenario_id,
            reason=request.reason
        )
        
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "scenario_id": scenario_id,
            "status": updated_scenario["status"],
            "rejection_reason": updated_scenario.get("reviewer_notes", "")
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error rejecting scenario: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/scenarios/{scenario_id}/synthesize-pocs")
async def synthesize_pocs(session_id: str, scenario_id: str):
    """Synthesize PoCs for approved scenario"""
    try:
        logger.info(f"🧪 API: Synthesizing PoCs for scenario {scenario_id}")
        
        session = scan_orchestrator._get_session(session_id)
        
        synthesized_pocs = scenario_orchestrator.synthesize_pocs(
            session=session,
            scenario_id=scenario_id
        )
        
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "scenario_id": scenario_id,
            "synthesized_pocs": {
                "total_pocs": synthesized_pocs["total_pocs"],
                "workspace_dir": synthesized_pocs["workspace_dir"],
                "master_script": {
                    "filename": synthesized_pocs["master_script"]["filename"],
                    "execution_command": synthesized_pocs["master_script"]["execution_command"]
                },
                "pocs": [
                    {
                        "step_number": p["step_number"],
                        "technique": p["technique"],
                        "action": p["action"],
                        "filename": p["filename"],
                        "execution_command": p["execution_command"]
                    }
                    for p in synthesized_pocs["pocs"]
                ]
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error synthesizing PoCs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{session_id}/scenarios/{scenario_id}/execute")
async def execute_scenario(session_id: str, 
                          scenario_id: str,
                          request: ScenarioExecutionRequest,
                          background_tasks: BackgroundTasks):
    """Execute approved scenario in sandbox"""
    try:
        logger.info(f"🚀 API: Executing scenario {scenario_id} in sandbox")
        
        session = scan_orchestrator._get_session(session_id)
        
        # Execute scenario (could be made async with background_tasks)
        execution_result = scenario_orchestrator.execute_scenario(
            session=session,
            scenario_id=scenario_id,
            timeout=request.timeout
        )
        
        scan_orchestrator._save_session(session)
        
        return {
            "success": True,
            "session_id": session_id,
            "scenario_id": scenario_id,
            "execution_result": {
                "success": execution_result.get("success", False),
                "execution_time": execution_result.get("execution_time"),
                "return_code": execution_result.get("return_code"),
                "logs_preview": execution_result.get("logs", [])[:10],  # First 10 lines
                "artifacts": execution_result.get("artifacts", [])
            }
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error executing scenario: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/scenarios/{scenario_id}/execution-logs")
async def get_execution_logs(session_id: str, scenario_id: str):
    """Get full execution logs for a scenario"""
    try:
        session = scan_orchestrator._get_session(session_id)
        
        # Find execution result
        for result in session.scenario_execution_results:
            if result["scenario_id"] == scenario_id:
                return {
                    "success": True,
                    "session_id": session_id,
                    "scenario_id": scenario_id,
                    "timestamp": result["timestamp"],
                    "execution_logs": result["result"].get("logs", [])
                }
        
        raise HTTPException(status_code=404, detail="Execution logs not found")
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting execution logs: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{session_id}/attack-graph")
async def get_attack_graph(session_id: str):
    """Get attack graph for visualization"""
    try:
        session = scan_orchestrator._get_session(session_id)
        
        if not session.attack_graph:
            raise HTTPException(
                status_code=404,
                detail="Attack graph not generated yet"
            )
        
        return {
            "success": True,
            "session_id": session_id,
            "attack_graph": session.attack_graph
        }
        
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        logger.error(f"Error getting attack graph: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/{session_id}/cleanup")
async def cleanup_scenario_resources(session_id: str):
    """Clean up temporary files and resources for a session"""
    try:
        logger.info(f"🧹 API: Cleaning up resources for session {session_id}")
        
        # Cleanup scenario orchestrator resources
        scenario_orchestrator.cleanup()
        
        return {
            "success": True,
            "session_id": session_id,
            "message": "Resources cleaned up successfully"
        }
        
    except Exception as e:
        logger.error(f"Error cleaning up resources: {e}")
        raise HTTPException(status_code=500, detail=str(e))