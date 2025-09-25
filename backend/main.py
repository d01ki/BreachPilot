from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response, StreamingResponse
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
logging.getLogger("uvicorn.access").addFilter(lambda r: "/results" not in r.getMessage())

app = FastAPI(title="BreachPilot Professional API")

# Enhanced CORS configuration
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type"]  # For file downloads
)

# Ensure directories exist
reports_dir = config.REPORTS_DIR
reports_dir.mkdir(exist_ok=True)
config.DATA_DIR.mkdir(exist_ok=True)

# Mount static files for reports with enhanced configuration
try:
    app.mount("/reports", StaticFiles(directory=str(reports_dir), html=True), name="reports")
    logger.info(f"Static reports directory mounted at /reports -> {reports_dir}")
except Exception as e:
    logger.error(f"Failed to mount static reports directory: {e}")

orchestrator = ScanOrchestrator()
active_connections: Dict[str, WebSocket] = {}

@app.get("/")
async def root():
    return {"message": "BreachPilot Professional API", "status": "online", "reports_dir": str(reports_dir)}

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
        logger.info(f"Running network service discovery for session: {session_id}")
        result = orchestrator.run_nmap(session_id)
        
        logger.info(f"Network discovery completed for session: {session_id}")
        logger.info(f"  - Status: {result.status}")
        logger.info(f"  - Open services found: {len(result.open_ports) if result.open_ports else 0}")
        
        if result.open_ports:
            for port in result.open_ports:
                logger.info(f"    Service {port['port']}: {port['service']} - {port.get('product', 'Unknown')} {port.get('version', '')}")
        else:
            logger.warning(f"No accessible services found for session: {session_id}")
            
        result_dict = result.model_dump()
        return result_dict
        
    except Exception as e:
        logger.error(f"Network discovery failed for session {session_id}: {e}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/analyze")
async def run_analysis(session_id: str):
    try:
        logger.info(f"Running professional vulnerability assessment for session: {session_id}")
        result = orchestrator.run_analysis(session_id)
        logger.info(f"Vulnerability assessment completed for session: {session_id}")
        logger.info(f"  - CVEs identified: {len(result.identified_cves) if result.identified_cves else 0}")
        
        if result.identified_cves:
            severity_count = {}
            for cve in result.identified_cves:
                severity = cve.severity or 'unknown'
                severity_count[severity] = severity_count.get(severity, 0) + 1
            logger.info(f"  - Severity distribution: {severity_count}")
        
        return result.model_dump()
    except Exception as e:
        logger.error(f"Vulnerability assessment failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/poc")
async def search_pocs(session_id: str, payload: Dict[str, Any] = Body(...)):
    try:
        selected_cves = payload.get('selected_cves', [])
        limit = payload.get('limit', 4)
        logger.info(f"Searching exploits for session {session_id}, CVEs: {selected_cves}, limit: {limit}")
        
        results = orchestrator.search_pocs_for_cves(session_id, selected_cves, limit=limit)
        
        total_pocs = sum(len(r.available_pocs) for r in results)
        total_with_code = sum(len([p for p in r.available_pocs if p.code]) for r in results)
        logger.info(f"Exploit search completed: {total_pocs} total exploits, {total_with_code} with source code")
        
        return [r.model_dump() for r in results]
    except Exception as e:
        logger.error(f"Exploit search failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/exploit/by_index")
async def execute_exploit_by_index(session_id: str, payload: Dict[str, Any] = Body(...)):
    """Execute a specific exploit by its index"""
    try:
        cve_id = payload.get('cve_id')
        poc_index = payload.get('poc_index')
        target_ip = payload.get('target_ip')
        
        if not all([cve_id is not None, poc_index is not None, target_ip]):
            raise HTTPException(status_code=400, detail="Missing required parameters")
        
        logger.info(f"Executing exploit #{poc_index} for CVE {cve_id} on target {target_ip}")
        
        result = orchestrator.execute_poc_by_index(session_id, cve_id, poc_index, target_ip)
        logger.info(f"Exploit #{poc_index} execution completed for CVE {cve_id}: {'SUCCESS' if result.success else 'FAILED'}")
        
        return result.model_dump()
    except Exception as e:
        logger.error(f"Exploit execution failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/scan/{session_id}/report")
async def generate_report(session_id: str):
    """Generate comprehensive security assessment report"""
    try:
        logger.info(f"Generating professional security assessment report for session: {session_id}")
        
        result = orchestrator.generate_report(session_id)
        
        logger.info(f"Security assessment report generated successfully for session: {session_id}")
        logger.info(f"  - Report type: {result.get('report_type', 'Standard')}")
        logger.info(f"  - Executive summary: {len(result.get('executive_summary', '')) > 0}")
        logger.info(f"  - Technical findings: {result.get('findings_count', 0)}")
        
        return result
    except Exception as e:
        logger.error(f"Report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/download/{report_type}/{target_ip}")
async def download_report(report_type: str, target_ip: str):
    """Download generated reports (HTML/PDF/JSON/MD)"""
    try:
        logger.info(f"Download request: {report_type} report for {target_ip}")
        
        if report_type not in ['html', 'pdf', 'json', 'md']:
            raise HTTPException(status_code=400, detail="Invalid report type. Must be html, pdf, json, or md")
        
        # Search for report files with multiple patterns
        search_patterns = [
            f"{reports_dir}/*{target_ip}*.{report_type}",
            f"{reports_dir}/enterprise_assessment_{target_ip}_*.{report_type}",
            f"{reports_dir}/professional_assessment_{target_ip}*.{report_type}",
            f"{reports_dir}/{target_ip}_report.{report_type}",
        ]
        
        if report_type == 'md':
            search_patterns.append(f"{reports_dir}/executive_summary_{target_ip}_*.{report_type}")
        
        files = []
        for pattern in search_patterns:
            files.extend(glob.glob(pattern))
        
        # Remove duplicates and sort by modification time
        files = list(set(files))
        
        if not files:
            logger.warning(f"No {report_type.upper()} report found for target {target_ip}")
            logger.info(f"Searched patterns: {search_patterns}")
            
            # List all files in reports directory for debugging
            all_files = list(reports_dir.glob("*"))
            logger.info(f"Available files in reports directory: {[f.name for f in all_files]}")
            
            raise HTTPException(
                status_code=404, 
                detail=f"No {report_type.upper()} report found for target {target_ip}. Please generate a report first."
            )
        
        # Get the most recent file
        latest_file = max(files, key=lambda f: os.path.getctime(f))
        file_path = Path(latest_file)
        
        if not file_path.exists():
            raise HTTPException(status_code=404, detail="Report file not found")
        
        # Determine content type and filename
        content_types = {
            'html': 'text/html',
            'pdf': 'application/pdf',
            'json': 'application/json',
            'md': 'text/markdown'
        }
        
        content_type = content_types.get(report_type, 'application/octet-stream')
        filename = f"security_assessment_{target_ip}.{report_type}"
        
        logger.info(f"Serving {report_type.upper()} report: {file_path} ({file_path.stat().st_size} bytes)")
        
        # For PDF files, use StreamingResponse to handle large files better
        if report_type == 'pdf':
            def iterfile(file_path: Path):
                with open(file_path, mode="rb") as file_like:
                    yield from file_like
            
            return StreamingResponse(
                iterfile(file_path),
                media_type=content_type,
                headers={
                    "Content-Disposition": f"attachment; filename={filename}",
                    "Content-Length": str(file_path.stat().st_size)
                }
            )
        else:
            return FileResponse(
                path=str(file_path),
                media_type=content_type,
                filename=filename,
                headers={"Content-Disposition": f"attachment; filename={filename}"}
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to download {report_type} report for {target_ip}: {e}")
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@app.get("/api/reports/list/{target_ip}")
async def list_reports(target_ip: str):
    """List available reports for a target"""
    try:
        reports = []
        patterns = [
            f"{reports_dir}/*{target_ip}*.html",
            f"{reports_dir}/*{target_ip}*.pdf", 
            f"{reports_dir}/*{target_ip}*.json",
            f"{reports_dir}/*{target_ip}*.md"
        ]
        
        for pattern in patterns:
            files = glob.glob(pattern)
            for file_path in files:
                file_info = os.stat(file_path)
                file_name = os.path.basename(file_path)
                file_ext = file_name.split('.')[-1]
                
                reports.append({
                    'filename': file_name,
                    'type': file_ext,
                    'size': file_info.st_size,
                    'created': datetime.fromtimestamp(file_info.st_ctime).isoformat(),
                    'download_url': f"/api/reports/download/{file_ext}/{target_ip}",
                    'full_path': file_path
                })
        
        # Sort by creation time, newest first
        reports.sort(key=lambda x: x['created'], reverse=True)
        
        logger.info(f"Found {len(reports)} reports for {target_ip}")
        
        return {'target_ip': target_ip, 'reports': reports, 'reports_directory': str(reports_dir)}
        
    except Exception as e:
        logger.error(f"Failed to list reports for {target_ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/test/{target_ip}")
async def test_report_generation(target_ip: str):
    """Test endpoint to generate a sample report for testing downloads"""
    try:
        logger.info(f"Generating test report for {target_ip}")
        
        # Generate test HTML report
        html_content = f"""<!DOCTYPE html>
<html><head><title>Test Report - {target_ip}</title></head>
<body>
<h1>Security Assessment Report</h1>
<p><strong>Target:</strong> {target_ip}</p>
<p><strong>Generated:</strong> {datetime.now().isoformat()}</p>
<p>This is a test report to verify download functionality.</p>
</body></html>"""
        
        html_path = reports_dir / f"test_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        # Generate test PDF (simple text file for testing)
        pdf_content = f"TEST SECURITY ASSESSMENT REPORT\nTarget: {target_ip}\nGenerated: {datetime.now().isoformat()}\n\nThis is a test report file."
        
        pdf_path = reports_dir / f"test_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
        with open(pdf_path, 'w', encoding='utf-8') as f:
            f.write(pdf_content)
        
        # Generate test JSON
        json_content = {
            "target_ip": target_ip,
            "report_type": "test",
            "generated": datetime.now().isoformat(),
            "test_data": {
                "vulnerabilities": 2,
                "services": 3,
                "risk_level": "medium"
            }
        }
        
        json_path = reports_dir / f"test_report_{target_ip}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(json_content, f, indent=2)
        
        logger.info(f"Test reports generated for {target_ip}")
        
        return {
            "message": "Test reports generated successfully",
            "files": [str(html_path.name), str(pdf_path.name), str(json_path.name)],
            "download_urls": {
                "html": f"/api/reports/download/html/{target_ip}",
                "pdf": f"/api/reports/download/pdf/{target_ip}",
                "json": f"/api/reports/download/json/{target_ip}"
            }
        }
        
    except Exception as e:
        logger.error(f"Failed to generate test reports for {target_ip}: {e}")
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
            "report_data": session.report_data.model_dump() if session.report_data else None
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
    logger.info("Starting BreachPilot Professional API server...")
    logger.info(f"Reports directory: {reports_dir}")
    logger.info(f"Data directory: {config.DATA_DIR}")
    uvicorn.run(app, host="0.0.0.0", port=8000)
