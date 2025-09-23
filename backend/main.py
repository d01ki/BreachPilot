from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from typing import List, Dict, Any
import asyncio
import json
import logging
from backend.models import ScanRequest, PoCInfo
from backend.orchestrator import ScanOrchestrator
from backend.config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)
logging.getLogger("uvicorn.access").addFilter(lambda r: "/results" not in r.getMessage())

app = FastAPI(title="BreachPilot API")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"])

orchestrator = ScanOrchestrator()
active_connections: Dict[str, WebSocket] = {}

@app.get("/")
async def root():
    return {"message": "BreachPilot API", "status": "online"}

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    try:
        logger.info(f"Starting scan for target: {request.target_ip}")
        session = orchestrator.start_scan(request)
        logger.info(f"Session created: {session.session_id}")
        return {"session_id": session.session_id, "target_ip": session.target_ip}
    except Exception as e:
        logger.error(f"Failed to start scan: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/osint")
async def run_osint(session_id: str):
    try:
        logger.info(f"Running OSINT for session: {session_id}")
        result = orchestrator.run_osint(session_id)
        logger.info(f"OSINT completed for session: {session_id}")
        return result.model_dump()
    except Exception as e:
        logger.error(f"OSINT failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/nmap")
async def run_nmap(session_id: str):
    try:
        logger.info(f"Running Nmap for session: {session_id}")
        result = orchestrator.run_nmap(session_id)
        
        # Log detailed nmap results
        logger.info(f"Nmap completed for session: {session_id}")
        logger.info(f"  - Status: {result.status}")
        logger.info(f"  - Open ports found: {len(result.open_ports)}")
        logger.info(f"  - Services found: {len(result.services)}")
        logger.info(f"  - Raw output length: {len(result.raw_output) if result.raw_output else 0}")
        
        if result.open_ports:
            for port in result.open_ports:
                logger.info(f"    Port {port['port']}: {port['service']} - {port.get('product', 'Unknown')}")
        else:
            logger.warning(f"No open ports found for session: {session_id}")
            
        result_dict = result.model_dump()
        logger.info(f"Returning nmap result with {len(result_dict.get('open_ports', []))} ports")
        return result_dict
        
    except Exception as e:
        logger.error(f"Nmap failed for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/analyze")
async def run_analysis(session_id: str):
    try:
        logger.info(f"Running analysis for session: {session_id}")
        result = orchestrator.run_analysis(session_id)
        logger.info(f"Analysis completed for session: {session_id}")
        return result.model_dump()
    except Exception as e:
        logger.error(f"Analysis failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/poc")
async def search_pocs(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        selected_cves = payload.get('selected_cves', [])
        limit = payload.get('limit', 4)  # Allow frontend to specify limit
        logger.info(f"Searching PoCs for session {session_id}, CVEs: {selected_cves}, limit: {limit}")
        
        results = orchestrator.search_pocs_for_cves(session_id, selected_cves, limit=limit)
        
        # Log detailed results
        total_pocs = sum(len(r.available_pocs) for r in results)
        total_with_code = sum(len([p for p in r.available_pocs if p.code]) for r in results)
        logger.info(f"PoC search completed: {total_pocs} total PoCs, {total_with_code} with code")
        
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"PoC search failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/single")
async def execute_single_exploit(session_id: str, payload: Dict[str, Any] = Body(...)):
    """Execute a single PoC (legacy endpoint - backward compatibility)"""
    try:
        cve_id = payload.get('cve_id')
        poc_data = payload.get('poc')
        target_ip = payload.get('target_ip')
        
        if not all([cve_id, poc_data, target_ip]):
            raise HTTPException(status_code=400, detail="Missing required parameters")
        
        poc = PoCInfo(**poc_data)
        logger.info(f"Executing single PoC for CVE {cve_id} on target {target_ip}")
        
        result = orchestrator.execute_single_poc(session_id, cve_id, poc, target_ip)
        logger.info(f"Single PoC execution completed for CVE {cve_id}: {'SUCCESS' if result.success else 'FAILED'}")
        
        return result.model_dump()
    except Exception as e:
        logger.error(f"Single PoC execution failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/multi")
async def execute_multiple_exploits(session_id: str, payload: Dict[str, Any] = Body(...)):
    """Execute all available PoCs for a CVE with retry logic"""
    try:
        cve_id = payload.get('cve_id')
        target_ip = payload.get('target_ip')
        
        if not all([cve_id, target_ip]):
            raise HTTPException(status_code=400, detail="Missing required parameters")
        
        logger.info(f"Executing multiple PoCs for CVE {cve_id} on target {target_ip}")
        
        results = orchestrator.execute_multiple_pocs(session_id, cve_id, target_ip)
        
        successful = [r for r in results if r.success]
        logger.info(f"Multiple PoC execution completed for CVE {cve_id}: {len(successful)}/{len(results)} successful")
        
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Multiple PoC execution failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/by_index")
async def execute_exploit_by_index(session_id: str, payload: Dict[str, Any] = Body(...)):
    """Execute a specific PoC by its index"""
    try:
        cve_id = payload.get('cve_id')
        poc_index = payload.get('poc_index')
        target_ip = payload.get('target_ip')
        
        if not all([cve_id is not None, poc_index is not None, target_ip]):
            raise HTTPException(status_code=400, detail="Missing required parameters")
        
        logger.info(f"Executing PoC #{poc_index} for CVE {cve_id} on target {target_ip}")
        
        result = orchestrator.execute_poc_by_index(session_id, cve_id, poc_index, target_ip)
        logger.info(f"PoC #{poc_index} execution completed for CVE {cve_id}: {'SUCCESS' if result.success else 'FAILED'}")
        
        return result.model_dump()
    except Exception as e:
        logger.error(f"PoC by index execution failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{session_id}/exploits/{cve_id}")
async def get_exploit_results_by_cve(session_id: str, cve_id: str):
    """Get all exploit results for a specific CVE"""
    try:
        results = orchestrator.get_exploit_results_by_cve(session_id, cve_id)
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Failed to get exploit results for {cve_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{session_id}/exploits/successful")
async def get_successful_exploits(session_id: str):
    """Get all successful exploit results"""
    try:
        results = orchestrator.get_successful_exploits(session_id)
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Failed to get successful exploits: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{session_id}/poc_files")
async def get_poc_files_info(session_id: str):
    """Get information about saved PoC files"""
    try:
        files_info = orchestrator.get_poc_files_info(session_id)
        return files_info
    except Exception as e:
        logger.error(f"Failed to get PoC files info: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/api/scan/{session_id}/exploit_files")
async def cleanup_exploit_files(session_id: str, keep_successful: bool = True):
    """Clean up exploit files for a session"""
    try:
        orchestrator.cleanup_exploit_files(session_id, keep_successful)
        return {"message": "Exploit files cleaned up successfully"}
    except Exception as e:
        logger.error(f"Failed to cleanup exploit files: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{session_id}/status")
async def get_status(session_id: str):
    try:
        status = orchestrator.get_session_status(session_id)
        return status
    except Exception as e:
        logger.error(f"Failed to get status for session {session_id}: {e}")
        raise HTTPException(status_code=404, detail="Session not found")

@app.get("/api/scan/{session_id}/results")
async def get_results(session_id: str):
    try:
        session = orchestrator._get_session(session_id)
        
        # Build response with detailed logging
        response = {
            "osint_result": session.osint_result.model_dump() if session.osint_result else None,
            "nmap_result": session.nmap_result.model_dump() if session.nmap_result else None,
            "analyst_result": session.analyst_result.model_dump() if session.analyst_result else None,
            "poc_results": [p.model_dump() for p in session.poc_results] if session.poc_results else [],
            "exploit_results": [e.model_dump() for e in session.exploit_results] if session.exploit_results else []
        }
        
        # Log what we're returning
        if session.nmap_result:
            logger.debug(f"Results endpoint returning nmap data with {len(session.nmap_result.open_ports)} ports")
        
        if session.poc_results:
            total_pocs = sum(len(pr.available_pocs) for pr in session.poc_results)
            logger.debug(f"Results endpoint returning {len(session.poc_results)} CVE results with {total_pocs} total PoCs")
        
        if session.exploit_results:
            successful = len([er for er in session.exploit_results if er.success])
            logger.debug(f"Results endpoint returning {len(session.exploit_results)} exploit results ({successful} successful)")
        
        return response
    except Exception as e:
        logger.error(f"Failed to get results for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.websocket("/ws/{session_id}")
async def websocket_endpoint(websocket: WebSocket, session_id: str):
    await websocket.accept()
    active_connections[session_id] = websocket
    try:
        while True:
            await asyncio.sleep(2)
            try:
                status = orchestrator.get_session_status(session_id)
                await websocket.send_json(status)
            except:
                break
    except WebSocketDisconnect:
        pass
    finally:
        if session_id in active_connections:
            del active_connections[session_id]

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
