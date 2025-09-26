#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Framework
Main FastAPI Application - Updated for CrewAI Architecture
"""

import logging
import asyncio
from datetime import datetime
from typing import Dict, Any, List, Optional

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from backend.models import (
    ScanRequest, ScanResult, NmapResult, AnalystResult,
    StepStatus
)
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

# Global scan sessions storage (in production, use proper database)
scan_sessions: Dict[str, ScanResult] = {}

# Request/Response models
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
            body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }
            .container { max-width: 800px; margin: 0 auto; background: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
            .header { text-align: center; margin-bottom: 30px; }
            .status { padding: 15px; margin: 10px 0; border-radius: 5px; }
            .success { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
            .warning { background: #fff3cd; color: #856404; border: 1px solid #ffeaa7; }
            .error { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
            .feature { margin: 15px 0; padding: 10px; background: #e7f3ff; border-radius: 5px; }
            .api-links { margin-top: 20px; }
            .api-links a { display: inline-block; margin: 5px 10px; padding: 10px 20px; background: #007bff; color: white; text-decoration: none; border-radius: 5px; }
            .api-links a:hover { background: #0056b3; }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>🛡️ BreachPilot Professional</h1>
                <h2>CrewAI Security Assessment Framework</h2>
                <p><strong>Enterprise Edition v2.0</strong></p>
            </div>
            
            <div class="feature">
                <h3>🤖 CrewAI Multi-Agent System</h3>
                <p>Professional security assessment using 5 specialized AI agents:</p>
                <ul>
                    <li><strong>Elite Vulnerability Hunter</strong> - CVE discovery specialist</li>
                    <li><strong>CVE Research Specialist</strong> - Technical analysis expert</li>
                    <li><strong>Senior Security Analyst</strong> - Business risk assessment</li>
                    <li><strong>Professional Penetration Tester</strong> - Exploitation strategies</li>
                    <li><strong>Professional Report Writer</strong> - Executive documentation</li>
                </ul>
            </div>
            
            <div class="feature">
                <h3>🔍 Advanced CVE Detection</h3>
                <p>Comprehensive vulnerability analysis including:</p>
                <ul>
                    <li>Zerologon (CVE-2020-1472) - Domain Controller compromise</li>
                    <li>EternalBlue (CVE-2017-0144) - SMB remote code execution</li>
                    <li>BlueKeep (CVE-2019-0708) - RDP vulnerability</li>
                    <li>Log4Shell (CVE-2021-44228) - Java logging vulnerability</li>
                    <li>PrintNightmare (CVE-2021-34527) - Windows Print Spooler</li>
                </ul>
            </div>
            
            <div class="api-links">
                <h3>🚀 API Documentation</h3>
                <a href="/docs" target="_blank">Interactive API Docs</a>
                <a href="/redoc" target="_blank">ReDoc Documentation</a>
                <a href="/status" target="_blank">System Status</a>
                <a href="/health" target="_blank">Health Check</a>
            </div>
            
            <div class="feature">
                <h3>📖 Quick Start</h3>
                <p><strong>API Endpoint:</strong> POST /scan/start</p>
                <p><strong>Example Request:</strong></p>
                <pre style="background: #f8f9fa; padding: 10px; border-radius: 5px;">{
  "target": "192.168.1.100",
  "scan_type": "comprehensive",
  "enable_exploitation": false
}</pre>
            </div>
        </div>
    </body>
    </html>
    """

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
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
        
        # Add CrewAI specific status
        if 'crewai' in status_details and 'crew_available' in status_details['crewai']:
            crew_available = status_details['crewai']['crew_available']
            status = "operational" if crew_available else "degraded"
        else:
            status = "unknown"
        
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
            "message": "Security assessment started",
            "target": request.target,
            "scan_type": request.scan_type
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
        "completed_steps": {
            "nmap": scan_result.nmap_result is not None,
            "analysis": scan_result.analyst_result is not None,
            "exploitation": scan_result.exploit_result is not None,
            "report": scan_result.report_result is not None
        }
    }

@app.get("/scan/{session_id}/results")
async def get_scan_results(session_id: str):
    """Get complete scan results"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    scan_result = scan_sessions[session_id]
    
    if scan_result.status not in [StepStatus.COMPLETED, StepStatus.FAILED]:
        raise HTTPException(status_code=202, detail="Scan still in progress")
    
    # Convert to dict for JSON serialization
    result_dict = {
        "session_id": session_id,
        "status": scan_result.status.value,
        "execution_time": scan_result.execution_time,
        "target": scan_result.request.target,
        "scan_type": scan_result.request.scan_type,
        "errors": scan_result.errors
    }
    
    # Add results if available
    if scan_result.nmap_result:
        result_dict["nmap_results"] = {
            "target_ip": scan_result.nmap_result.target_ip,
            "services_count": len(scan_result.nmap_result.services or []),
            "os_detection": scan_result.nmap_result.os_detection
        }
    
    if scan_result.analyst_result:
        result_dict["vulnerability_analysis"] = {
            "cves_identified": len(scan_result.analyst_result.identified_cves),
            "priority_vulnerabilities": len(scan_result.analyst_result.priority_vulnerabilities),
            "risk_assessment": scan_result.analyst_result.risk_assessment[:500] + "..." if len(scan_result.analyst_result.risk_assessment) > 500 else scan_result.analyst_result.risk_assessment,
            "cves": [{
                "cve_id": cve.cve_id,
                "severity": cve.severity,
                "cvss_score": cve.cvss_score,
                "description": cve.description[:200] + "..." if len(cve.description) > 200 else cve.description
            } for cve in scan_result.analyst_result.identified_cves]
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

@app.get("/crewai/status")
async def get_crewai_status():
    """Get CrewAI specific status information"""
    try:
        crew = SecurityAssessmentCrew()
        status = crew.get_crew_status()
        validation = crew.validate_configuration()
        
        return {
            "crewai_version": "2.0.0",
            "status": status,
            "validation": validation,
            "agents_available": list(crew.agents.keys()) if crew.crew_available else [],
            "tasks_available": list(crew.tasks_config.keys()) if hasattr(crew, 'tasks_config') else []
        }
        
    except Exception as e:
        logger.error(f"CrewAI status check failed: {e}")
        return {
            "error": str(e),
            "crewai_available": False
        }

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
