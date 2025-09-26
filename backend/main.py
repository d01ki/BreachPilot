#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Framework
Simplified FastAPI Application - CrewAI Architecture
"""

import logging
import time
from datetime import datetime
from typing import Dict, Any, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.models import ScanRequest, ScanResult, StepStatus
from backend.config import config
from backend.orchestrator import SecurityOrchestrator
from backend.crews import SecurityAssessmentCrew

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# FastAPI app
app = FastAPI(
    title="BreachPilot Professional Security Assessment Framework",
    description="Enterprise-grade security assessment powered by CrewAI multi-agent collaboration",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize orchestrator
try:
    orchestrator = SecurityOrchestrator()
    logger.info("SecurityOrchestrator initialized successfully")
except Exception as e:
    logger.error(f"Failed to initialize SecurityOrchestrator: {e}")
    orchestrator = None

# Global scan sessions storage
scan_sessions: Dict[str, ScanResult] = {}

# Request models
class ScanStartRequest(BaseModel):
    target: str
    scan_type: str = "comprehensive"
    enable_exploitation: bool = False

class StatusResponse(BaseModel):
    status: str
    message: str
    details: Dict[str, Any]

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main application page"""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>BreachPilot Professional - CrewAI Security Assessment</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); min-height: 100vh; }
            .container { max-width: 1000px; margin: 0 auto; padding: 40px 20px; }
            .header { text-align: center; color: white; margin-bottom: 40px; }
            .card { background: white; padding: 30px; margin: 20px 0; border-radius: 15px; box-shadow: 0 10px 30px rgba(0,0,0,0.2); }
            .status { padding: 15px; margin: 10px 0; border-radius: 8px; }
            .success { background: #d4edda; color: #155724; border-left: 4px solid #28a745; }
            .warning { background: #fff3cd; color: #856404; border-left: 4px solid #ffc107; }
            .error { background: #f8d7da; color: #721c24; border-left: 4px solid #dc3545; }
            .feature { margin: 20px 0; padding: 20px; background: #f8f9fa; border-radius: 8px; border-left: 4px solid #007bff; }
            .api-links { margin-top: 30px; text-align: center; }
            .api-links a { display: inline-block; margin: 10px 15px; padding: 12px 25px; background: #007bff; color: white; text-decoration: none; border-radius: 25px; transition: all 0.3s; }
            .api-links a:hover { background: #0056b3; transform: translateY(-2px); }
            .emoji { font-size: 1.5em; margin-right: 10px; }
            .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; }
            h1 { font-size: 2.5em; margin-bottom: 10px; }
            h2 { color: #6c757d; font-weight: 300; }
            .version { background: #28a745; color: white; padding: 5px 15px; border-radius: 15px; font-size: 0.9em; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><span class="emoji">🛡️</span>BreachPilot Professional</h1>
                <h2>CrewAI Security Assessment Framework</h2>
                <div class="version">Enterprise Edition v2.0</div>
            </div>
            
            <div class="grid">
                <div class="card">
                    <h3><span class="emoji">🤖</span>CrewAI Multi-Agent System</h3>
                    <p>Professional security assessment using 5 specialized AI agents:</p>
                    <ul>
                        <li><strong>Elite Vulnerability Hunter</strong> - 15+ years CVE discovery experience</li>
                        <li><strong>CVE Research Specialist</strong> - Technical analysis expert</li>
                        <li><strong>Senior Security Analyst</strong> - Business risk assessment</li>
                        <li><strong>Professional Penetration Tester</strong> - Ethical hacking strategies</li>
                        <li><strong>Professional Report Writer</strong> - Executive documentation</li>
                    </ul>
                </div>
                
                <div class="card">
                    <h3><span class="emoji">🔍</span>Advanced CVE Detection</h3>
                    <p>Comprehensive vulnerability analysis including:</p>
                    <ul>
                        <li><strong>Zerologon</strong> (CVE-2020-1472) - Domain Controller compromise</li>
                        <li><strong>EternalBlue</strong> (CVE-2017-0144) - SMB remote code execution</li>
                        <li><strong>BlueKeep</strong> (CVE-2019-0708) - RDP vulnerability</li>
                        <li><strong>Log4Shell</strong> (CVE-2021-44228) - Java logging vulnerability</li>
                        <li><strong>PrintNightmare</strong> (CVE-2021-34527) - Windows Print Spooler</li>
                    </ul>
                </div>
            </div>
            
            <div class="card">
                <h3><span class="emoji">🚀</span>Quick Start API Example</h3>
                <p><strong>Endpoint:</strong> POST /scan/start</p>
                <pre style="background: #f8f9fa; padding: 20px; border-radius: 8px; overflow-x: auto;">curl -X POST "http://localhost:8000/scan/start" \
     -H "Content-Type: application/json" \
     -d '{
       "target": "scanme.nmap.org",
       "scan_type": "comprehensive",
       "enable_exploitation": false
     }'</pre>
            </div>
            
            <div class="api-links">
                <h3><span class="emoji">📚</span>API Documentation & Tools</h3>
                <a href="/docs" target="_blank">📖 Interactive API Docs</a>
                <a href="/redoc" target="_blank">📋 ReDoc Documentation</a>
                <a href="/status" target="_blank">📊 System Status</a>
                <a href="/health" target="_blank">💚 Health Check</a>
                <a href="/crewai/status" target="_blank">🤖 CrewAI Status</a>
            </div>
            
            <div class="card" style="text-align: center; margin-top: 40px;">
                <h3><span class="emoji">🎯</span>Ready for Professional Security Assessment</h3>
                <p>Your CrewAI-powered security assessment framework is ready to analyze targets with enterprise-grade AI collaboration.</p>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if not orchestrator:
        return JSONResponse(
            content={"status": "unhealthy", "message": "Orchestrator not available"},
            status_code=503
        )
    
    health_status = await orchestrator.health_check()
    
    if health_status.get('overall') == 'healthy':
        return JSONResponse(content=health_status)
    else:
        return JSONResponse(content=health_status, status_code=503)

@app.get("/status")
async def get_status() -> StatusResponse:
    """Get system status including CrewAI components"""
    if not orchestrator:
        return StatusResponse(
            status="error",
            message="Orchestrator not available",
            details={}
        )
    
    try:
        status_details = orchestrator.get_orchestrator_status()
        
        # Determine overall status
        crew_available = status_details.get('crewai', {}).get('crew_available', False)
        status = "operational" if crew_available else "degraded"
        
        return StatusResponse(
            status=status,
            message="System status retrieved successfully",
            details=status_details
        )
        
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return StatusResponse(
            status="error",
            message=f"Status check failed: {str(e)}",
            details={}
        )

@app.get("/crewai/status")
async def get_crewai_status():
    """Get CrewAI specific status information"""
    try:
        crew = SecurityAssessmentCrew()
        status = crew.get_crew_status()
        validation = crew.validate_configuration()
        
        return {
            "crewai_version": "2.0.0",
            "framework_version": "0.51.0",
            "status": status,
            "validation": validation,
            "agents_available": list(crew.agents.keys()) if crew.crew_available else [],
            "tasks_available": list(crew.tasks_config.keys()) if hasattr(crew, 'tasks_config') else []
        }
        
    except Exception as e:
        logger.error(f"CrewAI status check failed: {e}")
        return {
            "error": str(e),
            "crewai_available": False,
            "message": "CrewAI initialization failed - check OpenAI API key configuration"
        }

@app.post("/scan/start")
async def start_scan(request: ScanStartRequest, background_tasks: BackgroundTasks):
    """Start a comprehensive security assessment"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
    try:
        # Create scan request
        scan_request = ScanRequest(
            target=request.target,
            scan_type=request.scan_type,
            enable_exploitation=request.enable_exploitation
        )
        
        # Generate session ID
        session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{request.target.replace('.', '_')}"
        
        # Initialize scan result
        scan_result = ScanResult(
            request=scan_request,
            status=StepStatus.IN_PROGRESS,
            errors=[]
        )
        
        # Store in sessions
        scan_sessions[session_id] = scan_result
        
        # Start background scan
        background_tasks.add_task(run_security_assessment, session_id, scan_request)
        
        return {
            "session_id": session_id,
            "status": "started",
            "message": "CrewAI security assessment started",
            "target": request.target,
            "scan_type": request.scan_type,
            "agents": 5,
            "estimated_duration": "2-5 minutes"
        }
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@app.get("/scan/{session_id}/status")
async def get_scan_status(session_id: str):
    """Get status of a running scan"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    scan_result = scan_sessions[session_id]
    
    return {
        "session_id": session_id,
        "status": scan_result.status.value,
        "target": scan_result.request.target,
        "execution_time": scan_result.execution_time,
        "errors": scan_result.errors,
        "progress": {
            "network_scan": "✅" if scan_result.nmap_result else "⏳",
            "crewai_analysis": "✅" if scan_result.analyst_result else "⏳",
            "exploitation": "✅" if scan_result.exploit_result else ("N/A" if not scan_result.request.enable_exploitation else "⏳"),
            "report": "✅" if scan_result.report_result else "⏳"
        },
        "message": "CrewAI agents are collaborating on your security assessment..."
    }

@app.get("/scan/{session_id}/results")
async def get_scan_results(session_id: str):
    """Get complete scan results"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    scan_result = scan_sessions[session_id]
    
    if scan_result.status == StepStatus.IN_PROGRESS:
        raise HTTPException(status_code=202, detail="CrewAI assessment still in progress")
    
    # Build comprehensive results
    result_dict = {
        "session_id": session_id,
        "status": scan_result.status.value,
        "execution_time": f"{scan_result.execution_time:.2f} seconds",
        "target": scan_result.request.target,
        "scan_type": scan_result.request.scan_type,
        "crewai_agents": 5,
        "errors": scan_result.errors
    }
    
    # Add network scan results
    if scan_result.nmap_result:
        result_dict["network_scan"] = {
            "services_discovered": len(scan_result.nmap_result.services or []),
            "os_detection": scan_result.nmap_result.os_detection,
            "scan_time": scan_result.nmap_result.scan_time
        }
    
    # Add CrewAI vulnerability analysis
    if scan_result.analyst_result:
        result_dict["vulnerability_analysis"] = {
            "total_cves": len(scan_result.analyst_result.identified_cves),
            "critical_vulnerabilities": len([cve for cve in scan_result.analyst_result.identified_cves if cve.severity == "Critical"]),
            "high_vulnerabilities": len([cve for cve in scan_result.analyst_result.identified_cves if cve.severity == "High"]),
            "risk_assessment_summary": scan_result.analyst_result.risk_assessment[:300] + "..." if len(scan_result.analyst_result.risk_assessment) > 300 else scan_result.analyst_result.risk_assessment,
            "priority_cves": scan_result.analyst_result.priority_vulnerabilities,
            "detailed_findings": [{
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description,
                "affected_service": cve.affected_service,
                "exploit_available": cve.exploit_available
            } for cve in scan_result.analyst_result.identified_cves]
        }
    
    # Add exploitation results if available
    if scan_result.exploit_result:
        result_dict["exploitation_analysis"] = {
            "exploits_tested": len(scan_result.exploit_result.tested_exploits or []),
            "successful_exploits": len(scan_result.exploit_result.successful_exploits or []),
            "failed_exploits": len(scan_result.exploit_result.failed_exploits or [])
        }
    
    # Add report summary if available
    if scan_result.report_result:
        result_dict["report_summary"] = {
            "executive_summary": scan_result.report_result.executive_summary[:300] + "..." if len(scan_result.report_result.executive_summary) > 300 else scan_result.report_result.executive_summary,
            "recommendations": scan_result.report_result.recommendations[:300] + "..." if len(scan_result.report_result.recommendations) > 300 else scan_result.report_result.recommendations,
            "generation_time": scan_result.report_result.generation_time
        }
    
    return result_dict

async def run_security_assessment(session_id: str, scan_request: ScanRequest):
    """Background task to run security assessment"""
    try:
        logger.info(f"Starting background security assessment for session {session_id}")
        
        # Execute assessment
        result = await orchestrator.execute_security_assessment(scan_request)
        
        # Update session
        scan_sessions[session_id] = result
        
        logger.info(f"Security assessment completed for session {session_id}")
        
    except Exception as e:
        logger.error(f"Security assessment failed for session {session_id}: {e}")
        
        # Update session with error
        if session_id in scan_sessions:
            scan_sessions[session_id].status = StepStatus.FAILED
            scan_sessions[session_id].errors.append(str(e))

if __name__ == "__main__":
    import uvicorn
    
    logger.info("Starting BreachPilot Professional Security Assessment Framework")
    logger.info("CrewAI Architecture - Enterprise Edition v2.0")
    
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=config.DEBUG,
        log_level=config.LOG_LEVEL.lower()
    )
