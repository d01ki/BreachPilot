from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.staticfiles import StaticFiles
from typing import List, Dict, Any
import asyncio
import json
import logging
from pathlib import Path
import os
import glob
from datetime import datetime
from backend.models import ScanRequest, PoCInfo
from backend.orchestrator import ScanOrchestrator
from backend.config import config

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="BreachPilot Professional API")

# CORS configuration
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"]
)

# Ensure directories exist
reports_dir = config.REPORTS_DIR
reports_dir.mkdir(exist_ok=True)
config.DATA_DIR.mkdir(exist_ok=True)

# Static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")

# Serve frontend
@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")

orchestrator = ScanOrchestrator()
active_connections: Dict[str, WebSocket] = {}

@app.post("/api/scan/start")
async def start_scan(request: ScanRequest):
    try:
        logger.info(f"Starting security assessment for target: {request.target_ip}")
        session = orchestrator.start_scan(request)
        logger.info(f"Security assessment session created: {session.session_id}")
        return {"session_id": session.session_id, "target_ip": session.target_ip}
    except Exception as e:
        logger.error(f"Failed to start security assessment: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/nmap")
async def run_nmap(session_id: str):
    try:
        result = orchestrator.run_nmap(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Network discovery failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/analyze")
async def run_analysis(session_id: str):
    try:
        result = orchestrator.run_analysis(session_id)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Vulnerability assessment failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/poc")
async def search_pocs(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        selected_cves = payload.get('selected_cves', [])
        limit = payload.get('limit', 4)
        results = orchestrator.search_pocs_for_cves(session_id, selected_cves, limit=limit)
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Exploit search failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/by_index")
async def execute_exploit_by_index(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        cve_id = payload.get('cve_id')
        poc_index = payload.get('poc_index')
        target_ip = payload.get('target_ip')
        
        if not all([cve_id is not None, poc_index is not None, target_ip]):
            raise HTTPException(status_code=400, detail="Missing required parameters")
        
        result = orchestrator.execute_poc_by_index(session_id, cve_id, poc_index, target_ip)
        return result.model_dump()
    except Exception as e:
        logger.error(f"Exploit execution failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/report")
async def generate_report(session_id: str):
    """Generate comprehensive security assessment report"""
    try:
        logger.info(f"Generating report for session: {session_id}")
        
        # Get session to extract target IP
        session = orchestrator._get_session(session_id)
        target_ip = session.target_ip
        
        # Generate report using orchestrator
        result = orchestrator.generate_report(session_id)
        
        # Create a simple test PDF for immediate download
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create HTML report
        html_content = f"""<!DOCTYPE html>
<html><head><title>Security Assessment Report - {target_ip}</title>
<style>
body {{font-family: Arial, sans-serif; margin: 40px; line-height: 1.6;}}
h1 {{color: #333; border-bottom: 2px solid #007acc;}}
.header {{background: #f4f4f4; padding: 20px; border-radius: 5px; margin-bottom: 20px;}}
.section {{margin: 20px 0;}}
.metric {{display: inline-block; background: #e8f4fd; padding: 10px; margin: 5px; border-radius: 5px;}}
</style></head>
<body>
<div class="header">
<h1>Security Assessment Report</h1>
<p><strong>Target:</strong> {target_ip}</p>
<p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
<p><strong>Report Type:</strong> Professional Security Assessment</p>
</div>

<div class="section">
<h2>Executive Summary</h2>
<p>This security assessment was conducted using BreachPilot Professional Framework.</p>

<div class="metric">Services: {result.get('findings_count', 0)}</div>
<div class="metric">Critical Issues: {result.get('critical_issues', 0)}</div>
<div class="metric">Successful Exploits: {result.get('successful_exploits', 0)}</div>
</div>

<div class="section">
<h2>Assessment Results</h2>
<p>{result.get('executive_summary', 'Comprehensive security analysis completed.')}</p>
</div>

<div class="section">
<h2>Recommendations</h2>
<ul>
<li>Apply security patches for identified vulnerabilities</li>
<li>Implement network segmentation</li>
<li>Enable advanced monitoring</li>
<li>Conduct regular security assessments</li>
</ul>
</div>

<footer style="margin-top: 50px; padding-top: 20px; border-top: 1px solid #ccc; color: #666;">
<p>Generated by BreachPilot Professional Security Assessment Framework</p>
<p>Report ID: {session_id}</p>
</footer>
</body></html>"""
        
        html_path = reports_dir / f"security_report_{target_ip}_{timestamp}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Create simple PDF content
        pdf_content = f"""SECURITY ASSESSMENT REPORT
=============================

Target: {target_ip}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: Professional Security Assessment
Session ID: {session_id}

EXECUTIVE SUMMARY
================
This security assessment was conducted using BreachPilot Professional Framework.

KEY METRICS:
- Findings: {result.get('findings_count', 0)}
- Critical Issues: {result.get('critical_issues', 0)}  
- Successful Exploits: {result.get('successful_exploits', 0)}

ASSESSMENT RESULTS:
{result.get('executive_summary', 'Comprehensive security analysis completed.')}

RECOMMENDATIONS:
1. Apply security patches for identified vulnerabilities
2. Implement network segmentation  
3. Enable advanced monitoring
4. Conduct regular security assessments

---
Generated by BreachPilot Professional Security Assessment Framework
Report ID: {session_id}
"""
        
        pdf_path = reports_dir / f"security_report_{target_ip}_{timestamp}.pdf"
        with open(pdf_path, 'w', encoding='utf-8') as f:
            f.write(pdf_content)
        
        logger.info(f"Report files created: {html_path}, {pdf_path}")
        
        # Update result with file paths
        result.update({
            "html_path": str(html_path),
            "pdf_path": str(pdf_path),
            "html_download_url": f"/download/html/{target_ip}",
            "pdf_download_url": f"/download/pdf/{target_ip}"
        })
        
        return result
        
    except Exception as e:
        logger.error(f"Report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/download/{file_type}/{target_ip}")
async def download_file(file_type: str, target_ip: str):
    """Simple file download endpoint"""
    try:
        logger.info(f"Download request: {file_type} for {target_ip}")
        
        if file_type not in ['html', 'pdf']:
            raise HTTPException(status_code=400, detail="File type must be html or pdf")
        
        # Find the most recent file
        pattern = f"security_report_{target_ip}_*.{file_type}"
        files = list(reports_dir.glob(pattern))
        
        if not files:
            logger.error(f"No {file_type} file found for {target_ip}")
            logger.info(f"Available files: {list(reports_dir.glob('*'))}")
            raise HTTPException(status_code=404, detail=f"No {file_type} report found for {target_ip}")
        
        # Get the newest file
        latest_file = max(files, key=os.path.getctime)
        
        logger.info(f"Serving file: {latest_file}")
        
        media_type = "application/pdf" if file_type == "pdf" else "text/html"
        filename = f"security_assessment_{target_ip}.{file_type}"
        
        return FileResponse(
            path=str(latest_file),
            media_type=media_type,
            filename=filename
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/test/create/{target_ip}")
async def create_test_files(target_ip: str):
    """Create test files for download testing"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Create test HTML
        html_content = f"""<!DOCTYPE html>
<html><head><title>Test Report - {target_ip}</title></head>
<body><h1>Test Security Report</h1><p>Target: {target_ip}</p><p>This is a test file.</p></body></html>"""
        
        html_path = reports_dir / f"security_report_{target_ip}_{timestamp}.html"
        with open(html_path, 'w') as f:
            f.write(html_content)
        
        # Create test PDF
        pdf_content = f"TEST SECURITY REPORT\nTarget: {target_ip}\nGenerated: {datetime.now()}\nThis is a test PDF file."
        
        pdf_path = reports_dir / f"security_report_{target_ip}_{timestamp}.pdf"  
        with open(pdf_path, 'w') as f:
            f.write(pdf_content)
        
        return {
            "message": "Test files created",
            "html_url": f"/download/html/{target_ip}",
            "pdf_url": f"/download/pdf/{target_ip}",
            "files": [html_path.name, pdf_path.name]
        }
        
    except Exception as e:
        logger.error(f"Failed to create test files: {e}")
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
        
        response = {
            "nmap_result": session.nmap_result.model_dump() if session.nmap_result else None,
            "analyst_result": session.analyst_result.model_dump() if session.analyst_result else None,
            "poc_results": [p.model_dump() for p in session.poc_results] if session.poc_results else [],
            "exploit_results": [e.model_dump() for e in session.exploit_results] if session.exploit_results else [],
            "report_data": session.report_data if session.report_data else None
        }
        
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
    logger.info(f"Starting server with reports directory: {reports_dir}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
