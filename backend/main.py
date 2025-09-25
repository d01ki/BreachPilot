from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Body
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, StreamingResponse, Response
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
import io

# Try to import PDF generation libraries
try:
    import weasyprint
    PDF_LIBRARY = "weasyprint"
except ImportError:
    try:
        from reportlab.pdfgen import canvas
        from reportlab.lib.pagesizes import letter, A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
        from reportlab.lib import colors
        from reportlab.lib.units import inch
        PDF_LIBRARY = "reportlab"
    except ImportError:
        PDF_LIBRARY = None

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = FastAPI(title="BreachPilot Professional API")

# Enhanced CORS configuration for file downloads
app.add_middleware(
    CORSMiddleware, 
    allow_origins=["*"], 
    allow_credentials=True, 
    allow_methods=["*"], 
    allow_headers=["*"],
    expose_headers=["Content-Disposition", "Content-Type", "Content-Length"]
)

# Ensure directories exist
reports_dir = config.REPORTS_DIR
reports_dir.mkdir(exist_ok=True)
config.DATA_DIR.mkdir(exist_ok=True)

# Static files
app.mount("/static", StaticFiles(directory="frontend/static"), name="static")
app.mount("/reports", StaticFiles(directory=str(reports_dir)), name="reports")

logger.info(f"Reports directory: {reports_dir}")
logger.info(f"Static reports directory mounted at /reports")
logger.info(f"PDF Library available: {PDF_LIBRARY}")

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

def generate_html_report(target_ip, session_id, result):
    """Generate HTML report content"""
    html_content = f"""<!DOCTYPE html>
<html><head>
    <title>Security Assessment Report - {target_ip}</title>
    <meta charset="UTF-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; line-height: 1.6; }}
        .header {{ background: linear-gradient(135deg, #1f2937, #374151); color: white; padding: 30px; border-radius: 12px; margin-bottom: 30px; }}
        .header h1 {{ margin: 0; font-size: 2.5rem; }}
        .header p {{ margin: 5px 0; opacity: 0.9; }}
        .section {{ margin: 30px 0; padding: 20px; background: #f8fafc; border-left: 4px solid #3b82f6; border-radius: 8px; }}
        .metric {{ display: inline-block; background: #e8f4fd; padding: 15px; margin: 10px; border-radius: 8px; min-width: 120px; text-align: center; }}
        .metric-label {{ font-size: 0.9rem; color: #666; }}
        .metric-value {{ font-size: 1.5rem; font-weight: bold; color: #1f2937; }}
        .critical {{ background: #fef2f2; border-left-color: #dc2626; }}
        .high {{ background: #fefbf2; border-left-color: #f59e0b; }}
        .footer {{ margin-top: 50px; padding-top: 20px; border-top: 2px solid #e5e7eb; color: #666; font-size: 0.9rem; }}
        table {{ width: 100%; border-collapse: collapse; margin: 20px 0; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }}
        th {{ background-color: #f5f5f5; font-weight: bold; }}
        .status-badge {{ padding: 4px 8px; border-radius: 4px; color: white; font-size: 0.8rem; }}
        .status-critical {{ background: #dc2626; }}
        .status-high {{ background: #f59e0b; }}
        .status-medium {{ background: #10b981; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🛡️ Security Assessment Report</h1>
        <p><strong>Target:</strong> {target_ip}</p>
        <p><strong>Generated:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
        <p><strong>Assessment Type:</strong> Professional Security Assessment</p>
        <p><strong>Report ID:</strong> {session_id}</p>
    </div>

    <div class="section">
        <h2>📊 Executive Summary</h2>
        <p>This comprehensive security assessment was conducted using BreachPilot Professional Framework against the target system <strong>{target_ip}</strong>.</p>
        
        <div style="margin: 20px 0;">
            <div class="metric">
                <div class="metric-label">Services Discovered</div>
                <div class="metric-value">{result.get('findings_count', 0)}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Critical Issues</div>
                <div class="metric-value">{result.get('critical_issues', 0)}</div>
            </div>
            <div class="metric">
                <div class="metric-label">Exploits Verified</div>
                <div class="metric-value">{result.get('successful_exploits', 0)}</div>
            </div>
        </div>
    </div>

    <div class="section critical">
        <h2>⚠️ Security Recommendations</h2>
        <table>
            <tr><th>Priority</th><th>Recommendation</th><th>Timeline</th></tr>
            <tr><td><span class="status-badge status-critical">CRITICAL</span></td><td>Apply security patches for all critical vulnerabilities</td><td>Immediate</td></tr>
            <tr><td><span class="status-badge status-high">HIGH</span></td><td>Implement network access controls</td><td>1-2 weeks</td></tr>
            <tr><td><span class="status-badge status-medium">MEDIUM</span></td><td>Enable advanced monitoring</td><td>2-4 weeks</td></tr>
        </table>
    </div>

    <div class="footer">
        <p><strong>Generated by:</strong> BreachPilot Professional Security Assessment Framework</p>
        <p><strong>Report Validity:</strong> Valid for 30 days from generation date</p>
    </div>
</body></html>"""
    return html_content

def generate_pdf_with_weasyprint(html_content, target_ip):
    """Generate PDF using WeasyPrint"""
    try:
        pdf_buffer = io.BytesIO()
        weasyprint.HTML(string=html_content).write_pdf(pdf_buffer)
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
    except Exception as e:
        logger.error(f"WeasyPrint PDF generation failed: {e}")
        return None

def generate_pdf_with_reportlab(target_ip, session_id, result):
    """Generate PDF using ReportLab"""
    try:
        pdf_buffer = io.BytesIO()
        doc = SimpleDocTemplate(pdf_buffer, pagesize=A4)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Title'],
            fontSize=24,
            spaceAfter=30,
            textColor=colors.HexColor('#1f2937')
        )
        story.append(Paragraph("Security Assessment Report", title_style))
        story.append(Spacer(1, 12))
        
        # Header Info
        header_data = [
            ['Target IP:', target_ip],
            ['Generated:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')],
            ['Assessment Type:', 'Professional Security Assessment'],
            ['Report ID:', session_id]
        ]
        
        header_table = Table(header_data, colWidths=[2*inch, 4*inch])
        header_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f3f4f6')),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(header_table)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", styles['Heading2']))
        story.append(Paragraph(
            f"This security assessment identified {result.get('findings_count', 0)} "
            f"network services and {result.get('critical_issues', 0)} critical security issues.",
            styles['Normal']
        ))
        story.append(Spacer(1, 20))
        
        # Recommendations
        story.append(Paragraph("Security Recommendations", styles['Heading2']))
        recommendations = [
            "Apply security patches for all identified critical vulnerabilities",
            "Implement comprehensive network segmentation and access controls",
            "Enable advanced logging and security monitoring solutions",
            "Conduct regular security assessments and penetration testing"
        ]
        
        for i, rec in enumerate(recommendations, 1):
            story.append(Paragraph(f"{i}. {rec}", styles['Normal']))
        
        doc.build(story)
        pdf_buffer.seek(0)
        return pdf_buffer.getvalue()
        
    except Exception as e:
        logger.error(f"ReportLab PDF generation failed: {e}")
        return None

def find_report_file(target_ip, report_type):
    """Find report file with multiple search patterns"""
    search_patterns = [
        f"{reports_dir}/*{target_ip}*.{report_type}",
        f"{reports_dir}/security_report_{target_ip}_*.{report_type}",
        f"{reports_dir}/enterprise_assessment_{target_ip}_*.{report_type}",
        f"{reports_dir}/{target_ip}_report.{report_type}"
    ]
    
    for pattern in search_patterns:
        files = glob.glob(pattern)
        if files:
            return max(files, key=os.path.getctime)
    
    return None

@app.post("/api/scan/{session_id}/report")
async def generate_report(session_id: str):
    """Generate comprehensive security assessment report with proper PDF"""
    try:
        logger.info(f"Generating report for session: {session_id}")
        
        session = orchestrator._get_session(session_id)
        target_ip = session.target_ip
        result = orchestrator.generate_report(session_id)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Generate HTML report
        html_content = generate_html_report(target_ip, session_id, result)
        html_path = reports_dir / f"security_report_{target_ip}_{timestamp}.html"
        
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"HTML report saved: {html_path}")
        
        # Generate PDF report
        pdf_data = None
        pdf_path = reports_dir / f"security_report_{target_ip}_{timestamp}.pdf"
        
        if PDF_LIBRARY == "weasyprint":
            logger.info("Generating PDF with WeasyPrint")
            pdf_data = generate_pdf_with_weasyprint(html_content, target_ip)
        elif PDF_LIBRARY == "reportlab":
            logger.info("Generating PDF with ReportLab")
            pdf_data = generate_pdf_with_reportlab(target_ip, session_id, result)
        
        if pdf_data:
            with open(pdf_path, 'wb') as f:
                f.write(pdf_data)
            logger.info(f"PDF report saved: {pdf_path} ({len(pdf_data)} bytes)")
        else:
            logger.warning("PDF generation failed, creating text fallback")
            text_content = f"""SECURITY ASSESSMENT REPORT
{'='*50}

Target: {target_ip}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Report Type: Professional Security Assessment
Session ID: {session_id}

EXECUTIVE SUMMARY
{'-'*20}
Services Discovered: {result.get('findings_count', 0)}
Critical Issues: {result.get('critical_issues', 0)}
Exploits Verified: {result.get('successful_exploits', 0)}

RECOMMENDATIONS:
1. Apply security patches for identified vulnerabilities
2. Implement network segmentation
3. Enable advanced monitoring
4. Conduct regular security assessments

Generated by BreachPilot Professional Security Assessment Framework
"""
            
            with open(pdf_path, 'w', encoding='utf-8') as f:
                f.write(text_content)
        
        result.update({
            "html_path": str(html_path),
            "pdf_path": str(pdf_path),
            "html_download_url": f"/api/reports/download/html/{target_ip}",
            "pdf_download_url": f"/api/reports/download/pdf/{target_ip}",
            "report_generated": True,
            "timestamp": timestamp
        })
        
        return result
        
    except Exception as e:
        logger.error(f"Report generation failed for session {session_id}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/download/{report_type}/{target_ip}")
async def download_report_api(report_type: str, target_ip: str):
    """Enhanced API endpoint for downloading reports"""
    try:
        logger.info(f"Download request: {report_type} report for {target_ip}")
        
        if report_type not in ['html', 'pdf', 'json', 'md']:
            raise HTTPException(status_code=400, detail="File type must be html, pdf, json, or md")
        
        file_path = find_report_file(target_ip, report_type)
        
        if not file_path or not os.path.exists(file_path):
            logger.error(f"No {report_type} file found for {target_ip}")
            raise HTTPException(status_code=404, detail=f"No {report_type} report found for {target_ip}")
        
        media_types = {
            'html': 'text/html',
            'pdf': 'application/pdf',
            'json': 'application/json',
            'md': 'text/markdown'
        }
        media_type = media_types.get(report_type, 'application/octet-stream')
        filename = f"security_assessment_{target_ip}.{report_type}"
        file_size = os.path.getsize(file_path)
        
        logger.info(f"Serving {report_type.upper()} report: {file_path} ({file_size} bytes)")
        
        if report_type == 'pdf':
            def generate_pdf_stream():
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        yield chunk
            
            return StreamingResponse(
                generate_pdf_stream(),
                media_type=media_type,
                headers={
                    "Content-Disposition": f"attachment; filename={filename}",
                    "Content-Length": str(file_size)
                }
            )
        else:
            return FileResponse(
                path=file_path,
                media_type=media_type,
                filename=filename
            )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Download failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/list/{target_ip}")
async def list_reports(target_ip: str):
    """List all available reports for a target IP"""
    try:
        reports = []
        for report_type in ['html', 'pdf', 'json', 'md']:
            file_path = find_report_file(target_ip, report_type)
            if file_path and os.path.exists(file_path):
                file_stat = os.stat(file_path)
                reports.append({
                    "filename": os.path.basename(file_path),
                    "type": report_type,
                    "size": file_stat.st_size,
                    "created": datetime.fromtimestamp(file_stat.st_ctime).isoformat(),
                    "download_url": f"/api/reports/download/{report_type}/{target_ip}"
                })
        
        return {
            "target_ip": target_ip,
            "reports": reports,
            "count": len(reports)
        }
        
    except Exception as e:
        logger.error(f"Failed to list reports for {target_ip}: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/reports/test/{target_ip}")
async def create_test_reports(target_ip: str):
    """Create test report files for immediate testing"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        test_result = {
            'findings_count': 5,
            'critical_issues': 2,
            'successful_exploits': 1,
            'executive_summary': 'Test security assessment completed.'
        }
        
        created_files = []
        
        # Create HTML report
        html_content = generate_html_report(target_ip, f"test-{timestamp}", test_result)
        html_path = reports_dir / f"security_report_{target_ip}_{timestamp}.html"
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        created_files.append({"type": "html", "path": str(html_path)})
        
        # Create PDF report
        pdf_path = reports_dir / f"security_report_{target_ip}_{timestamp}.pdf"
        
        if PDF_LIBRARY == "weasyprint":
            pdf_data = generate_pdf_with_weasyprint(html_content, target_ip)
        elif PDF_LIBRARY == "reportlab":
            pdf_data = generate_pdf_with_reportlab(target_ip, f"test-{timestamp}", test_result)
        else:
            pdf_data = None
        
        if pdf_data:
            with open(pdf_path, 'wb') as f:
                f.write(pdf_data)
        else:
            with open(pdf_path, 'w', encoding='utf-8') as f:
                f.write(f"TEST PDF REPORT\nTarget: {target_ip}\nGenerated: {datetime.now()}")
        
        created_files.append({"type": "pdf", "path": str(pdf_path)})
        
        logger.info(f"Test reports created for {target_ip}: {created_files}")
        
        return {
            "message": "Test reports created successfully",
            "target_ip": target_ip,
            "files": created_files,
            "html_url": f"/api/reports/download/html/{target_ip}",
            "pdf_url": f"/api/reports/download/pdf/{target_ip}"
        }
        
    except Exception as e:
        logger.error(f"Failed to create test reports: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Legacy endpoints for backward compatibility
@app.get("/download/{file_type}/{target_ip}")
async def download_file_legacy(file_type: str, target_ip: str):
    """Legacy download endpoint - redirects to new API"""
    return await download_report_api(file_type, target_ip)

@app.get("/test/create/{target_ip}")
async def create_test_files_legacy(target_ip: str):
    """Legacy test creation endpoint"""
    return await create_test_reports(target_ip)

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
