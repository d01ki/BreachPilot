#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Framework
FastAPI Application with Frontend Support
"""

import logging
from datetime import datetime
from typing import Dict, Any
from pathlib import Path

from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, FileResponse
from fastapi.staticfiles import StaticFiles
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

# Mount static files
static_dir = Path(__file__).parent.parent / "frontend" / "static"
if static_dir.exists():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

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
    target_ip: str  # Changed from 'target' to match frontend
    scan_type: str = "comprehensive"
    enable_exploitation: bool = False

class StatusResponse(BaseModel):
    status: str
    message: str
    details: Dict[str, Any]

@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve the main application page"""
    html_file = Path(__file__).parent.parent / "frontend" / "index.html"
    if html_file.exists():
        return FileResponse(html_file)
    
    return HTMLResponse(content="<h1>BreachPilot</h1><p>Frontend not found. Please check installation.</p>")

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    if not orchestrator:
        return {
            "status": "unhealthy",
            "message": "Orchestrator not available"
        }
    
    try:
        health_status = await orchestrator.health_check()
        return health_status
    except Exception as e:
        return {
            "status": "unhealthy",
            "message": str(e)
        }

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

# API endpoints with /api prefix for frontend compatibility
@app.post("/api/scan/start")
async def api_start_scan(request: ScanStartRequest, background_tasks: BackgroundTasks):
    """Start a comprehensive security assessment - API endpoint"""
    if not orchestrator:
        raise HTTPException(status_code=503, detail="Orchestrator not available")
    
    try:
        # Create scan request with correct field name
        scan_request = ScanRequest(
            target=request.target_ip,  # Map target_ip to target
            scan_type=request.scan_type,
            enable_exploitation=request.enable_exploitation
        )
        
        # Generate session ID
        session_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{request.target_ip.replace('.', '_')}"
        
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
            "target": request.target_ip,
            "scan_type": request.scan_type,
            "agents": 5,
            "estimated_duration": "2-5 minutes"
        }
        
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to start scan: {str(e)}")

@app.post("/api/scan/{session_id}/nmap")
async def api_run_nmap(session_id: str):
    """Execute nmap scan"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    try:
        scan_result = scan_sessions[session_id]
        target = scan_result.request.target
        
        # Execute nmap scan through orchestrator
        nmap_result = await orchestrator.run_nmap_scan(target)
        
        # Update session
        scan_sessions[session_id].nmap_result = nmap_result
        
        return nmap_result.dict() if hasattr(nmap_result, 'dict') else nmap_result
        
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        raise HTTPException(status_code=500, detail=f"Nmap scan failed: {str(e)}")

@app.post("/api/scan/{session_id}/analyze")
async def api_run_analysis(session_id: str):
    """Execute vulnerability analysis"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    try:
        scan_result = scan_sessions[session_id]
        
        if not scan_result.nmap_result:
            raise HTTPException(status_code=400, detail="Nmap scan must be completed first")
        
        # Execute vulnerability analysis
        analyst_result = await orchestrator.run_vulnerability_analysis(scan_result.nmap_result)
        
        # Update session
        scan_sessions[session_id].analyst_result = analyst_result
        
        return analyst_result.dict() if hasattr(analyst_result, 'dict') else analyst_result
        
    except Exception as e:
        logger.error(f"Vulnerability analysis failed: {e}")
        raise HTTPException(status_code=500, detail=f"Analysis failed: {str(e)}")

@app.get("/api/scan/{session_id}/status")
async def api_get_scan_status(session_id: str):
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
        "message": "Security assessment in progress..."
    }

@app.get("/api/scan/{session_id}/results")
async def api_get_scan_results(session_id: str):
    """Get complete scan results"""
    if session_id not in scan_sessions:
        raise HTTPException(status_code=404, detail="Scan session not found")
    
    scan_result = scan_sessions[session_id]
    
    if scan_result.status == StepStatus.IN_PROGRESS:
        raise HTTPException(status_code=202, detail="Assessment still in progress")
    
    # Build comprehensive results
    return {
        "session_id": session_id,
        "status": scan_result.status.value,
        "execution_time": scan_result.execution_time,
        "target": scan_result.request.target,
        "scan_type": scan_result.request.scan_type,
        "nmap_result": scan_result.nmap_result.dict() if scan_result.nmap_result and hasattr(scan_result.nmap_result, 'dict') else scan_result.nmap_result,
        "analyst_result": scan_result.analyst_result.dict() if scan_result.analyst_result and hasattr(scan_result.analyst_result, 'dict') else scan_result.analyst_result,
        "errors": scan_result.errors
    }

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
    logger.info("Listening on http://0.0.0.0:8000")
    
    uvicorn.run(
        "backend.main:app",
        host="0.0.0.0",
        port=8000,
        reload=config.DEBUG,
        log_level=config.LOG_LEVEL.lower()
    )
