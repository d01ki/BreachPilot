from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from typing import List, Dict, Any
import asyncio
import json
import logging

from backend.models import ScanRequest, ScanSession, StepStatus
from backend.orchestrator import ScanOrchestrator
from backend.config import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Create FastAPI app
app = FastAPI(title="BreachPilot API", version="2.0.0")

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global orchestrator
orchestrator = ScanOrchestrator()

# WebSocket connections
active_connections: Dict[str, WebSocket] = {}


@app.get("/")
async def root():
    return {"message": "BreachPilot API v2.0", "status": "online"}


@app.post("/api/scan/start")
async def start_scan(request: ScanRequest) -> Dict[str, Any]:
    """Start a new penetration test scan"""
    try:
        logger.info(f"Starting scan for {request.target_ip}")
        session = orchestrator.start_scan(request)
        
        return {
            "session_id": session.session_id,
            "target_ip": session.target_ip,
            "status": "started"
        }
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/osint")
async def run_osint(session_id: str) -> Dict[str, Any]:
    """Run OSINT scan"""
    try:
        result = orchestrator.run_osint(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"OSINT scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/nmap")
async def run_nmap(session_id: str) -> Dict[str, Any]:
    """Run Nmap scan"""
    try:
        result = orchestrator.run_nmap(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Nmap scan failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/analyze")
async def run_analysis(session_id: str) -> Dict[str, Any]:
    """Run vulnerability analysis"""
    try:
        result = orchestrator.run_analysis(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Analysis failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/poc")
async def search_pocs(session_id: str) -> List[Dict[str, Any]]:
    """Search for PoC exploits"""
    try:
        results = orchestrator.search_pocs(session_id)
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"PoC search failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/approve")
async def approve_exploits(session_id: str, approved_cves: List[str] = Body(...)) -> Dict[str, Any]:
    """Approve CVEs for exploitation"""
    try:
        orchestrator.await_user_approval(session_id, approved_cves)
        return {"status": "approved", "cves": ",".join(approved_cves)}
    except Exception as e:
        logger.error(f"Approval failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/exploit")
async def run_exploits(session_id: str) -> List[Dict[str, Any]]:
    """Execute approved exploits"""
    try:
        results = orchestrator.run_exploits(session_id)
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Exploitation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/verify")
async def verify_success(session_id: str) -> Dict[str, bool]:
    """Verify exploitation success"""
    try:
        results = orchestrator.verify_success(session_id)
        return results
    except Exception as e:
        logger.error(f"Verification failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{session_id}/report")
async def generate_report(session_id: str) -> Dict[str, Any]:
    """Generate final report"""
    try:
        result = orchestrator.generate_report(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{session_id}/status")
async def get_status(session_id: str) -> Dict[str, Any]:
    """Get scan session status"""
    try:
        status = orchestrator.get_session_status(session_id)
        return status
    except Exception as e:
        logger.error(f"Failed to get status: {e}")
        raise HTTPException(status_code=404, detail="Session not found")


@app.get("/api/scan/{session_id}/results")
async def get_results(session_id: str) -> Dict[str, Any]:
    """Get all scan results"""
    try:
        session = orchestrator._get_session(session_id)
        return {
            "osint_result": session.osint_result.model_dump() if session.osint_result else None,
            "nmap_result": session.nmap_result.model_dump() if session.nmap_result else None,
            "analyst_result": session.analyst_result.model_dump() if session.analyst_result else None,
            "poc_results": [p.model_dump() for p in session.poc_results] if session.poc_results else [],
            "exploit_results": [e.model_dump() for e in session.exploit_results] if session.exploit_results else []
        }
    except Exception as e:
        logger.error(f"Failed to get results: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/scan/{session_id}/download/report")
async def download_report(session_id: str, format: str = "pdf"):
    """Download report in specified format"""
    try:
        session = orchestrator._get_session(session_id)
        
        if format == "pdf" and session.report_data and session.report_data.pdf_path:
            return FileResponse(
                session.report_data.pdf_path,
                media_type="application/pdf",
                filename=f"{session.target_ip}_report.pdf"
            )
        elif format == "markdown":
            md_path = config.REPORTS_DIR / f"{session.target_ip}_report.md"
            if md_path.exists():
                return FileResponse(
                    str(md_path),
                    media_type="text/markdown",
                    filename=f"{session.target_ip}_report.md"
                )
        
        raise HTTPException(status_code=404, detail="Report not found")
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    """WebSocket for real-time updates"""
    await websocket.accept()
    active_connections[session_id] = websocket
    
    try:
        while True:
            # Keep connection alive and send status updates
            await asyncio.sleep(2)
            
            try:
                status = orchestrator.get_session_status(session_id)
                await websocket.send_json(status)
            except Exception as e:
                logger.error(f"Error sending status: {e}")
                break
                
    except WebSocketDisconnect:
        logger.info(f"WebSocket disconnected for session {session_id}")
    finally:
        if session_id in active_connections:
            del active_connections[session_id]


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
