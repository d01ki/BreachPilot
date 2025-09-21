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
        session = orchestrator.start_scan(request)
        return {"session_id": session.session_id, "target_ip": session.target_ip}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/osint")
async def run_osint(session_id: str):
    try:
        return orchestrator.run_osint(session_id).model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/nmap")
async def run_nmap(session_id: str):
    try:
        return orchestrator.run_nmap(session_id).model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/analyze")
async def run_analysis(session_id: str):
    try:
        return orchestrator.run_analysis(session_id).model_dump()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/poc")
async def search_pocs(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        selected_cves = payload.get('selected_cves', [])
        results = orchestrator.search_pocs_for_cves(session_id, selected_cves)
        return [r.model_dump() for r in results]
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/single")
async def execute_single_exploit(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        cve_id = payload.get('cve_id')
        poc = PoCInfo(**payload.get('poc'))
        target_ip = payload.get('target_ip')
        
        result = orchestrator.execute_single_poc(session_id, cve_id, poc, target_ip)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Exploit failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/scan/{session_id}/status")
async def get_status(session_id: str):
    try:
        return orchestrator.get_session_status(session_id)
    except Exception as e:
        raise HTTPException(status_code=404, detail="Session not found")

@app.get("/api/scan/{session_id}/results")
async def get_results(session_id: str):
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
