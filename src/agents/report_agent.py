"""
Enhanced Report Agent with AI integration
Claude-powered comprehensive report generation
"""
import json
import markdown
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, Tuple
from weasyprint import HTML, CSS
from weasyprint.text.fonts import FontConfiguration
import tempfile

from .ai_orchestrator import get_orchestrator


def generate_report(target: str, artifacts: dict, work_dir: Path) -> Tuple[Path, Path]:
    """
    Generate comprehensive Markdown and PDF reports using AI analysis
    Returns (md_path, pdf_path)
    """
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    md_path = work_dir / f"report_{ts}.md"
    pdf_path = work_dir / f"report_{ts}.pdf"
    
    try:
        # Load all available data
        all_data = {"target": target}
        
        # Load scan results
        if "scan_json" in artifacts:
            try:
                scan_data = json.loads(Path(artifacts["scan_json"]).read_text())
                all_data["scan"] = scan_data
            except Exception:
                all_data["scan"] = {"error": "Could not load scan data"}
        
        # Load PoC data
        if "poc" in artifacts:
            all_data["poc"] = artifacts["poc"]
        
        # Load exploit logs
        if "exploit_log" in artifacts:
            try:
                exploit_data = json.loads(Path(artifacts["exploit_log"]).read_text())
                all_data["exploit"] = exploit_data
            except Exception:
                all_data["exploit"] = {"error": "Could not load exploit data"}
        
        # Get AI orchestrator and generate comprehensive analysis
        orchestrator = get_orchestrator()
        
        # Generate AI-powered comprehensive report
        ai_report = orchestrator.generate_comprehensive_report(all_data, work_dir)
        
        if ai_report["status"] == "success":
            report_content = ai_report["content"]
        else:
            # Fallback to basic template if AI fails
            report_content = generate_fallback_report(target, all_data)
        
        # Save Markdown report
        md_path.write_text(report_content, encoding='utf-8')
        
        # Generate PDF from Markdown
        try:
            pdf_success = generate_pdf_from_markdown(report_content, pdf_path)
            if not pdf_success:
                # Create placeholder PDF
                create_placeholder_pdf(pdf_path)
        except Exception as e:
            print(f"PDF generation failed: {e}")
            create_placeholder_pdf(pdf_path)
        
        return md_path, pdf_path
        
    except Exception as e:
        print(f"Report generation error: {e}")
        # Create minimal fallback report
        fallback_content = generate_fallback_report(target, {"error": str(e)})
        md_path.write_text(fallback_content, encoding='utf-8')
        create_placeholder_pdf(pdf_path)
        return md_path, pdf_path


def generate_fallback_report(target: str, data: Dict[str, Any]) -> str:
    """Generate basic fallback report when AI is unavailable"""
    
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    report = f"""# BreachPilot Penetration Test Report

## Executive Summary

**Target:** {target}  
**Date:** {timestamp}  
**Tool:** BreachPilot AI-Assisted Penetration Testing Platform (PoC)

This report contains the results of an automated penetration test focusing on CVE-2020-1472 (Zerologon) vulnerability assessment.

---

## Methodology

This assessment used BreachPilot's AI-assisted methodology:

1. **Network Reconnaissance** - Port scanning and service enumeration
2. **Vulnerability Analysis** - AI-powered threat assessment  
3. **Exploit Research** - Automated PoC discovery and ranking
4. **Proof of Concept Execution** - Controlled exploitation testing
5. **Impact Analysis** - Risk assessment and reporting

---

## Technical Findings

### Network Scan Results
"""
    
    # Add scan results if available
    scan_data = data.get("scan", {})
    if scan_data and not scan_data.get("error"):
        report += f"""
**Target:** {scan_data.get('target', target)}  
**Scan Time:** {scan_data.get('timestamp', 'Unknown')}

#### Open Ports
"""
        ports = scan_data.get('ports', [])
        open_ports = [p for p in ports if p.get('state') == 'open']
        
        if open_ports:
            report += "| Port | Protocol | Service | Product | Version |\n"
            report += "|------|----------|---------|---------|----------|\n"
            for port in open_ports:
                report += f"| {port.get('port', 'N/A')} | {port.get('proto', 'N/A')} | {port.get('service', 'N/A')} | {port.get('product', 'N/A')} | {port.get('version', 'N/A')} |\n"
        else:
            report += "No open ports detected or scan failed.\n"
        
        # Add inferences
        inferences = scan_data.get('inferences', {})
        if inferences:
            report += "\n#### Vulnerability Indicators\n"
            if inferences.get('possible_domain_controller'):
                report += "- **Domain Controller Detected**: Target appears to be a Windows Domain Controller\n"
            if inferences.get('kerberos_present'):
                report += "- **Kerberos Service**: Potentially vulnerable to Zerologon (CVE-2020-1472)\n"
    else:
        report += "Scan data unavailable or failed.\n"
    
    # Add PoC research results
    poc_data = data.get("poc", {})
    if poc_data:
        report += "\n### Exploit Research\n"
        report += f"**Target CVE:** {poc_data.get('cve', 'CVE-2020-1472')}\n\n"
        
        sources = poc_data.get('sources', [])
        if sources:
            report += "#### Available PoC Sources\n"
            for source in sources[:5]:  # Top 5 sources
                name = source.get('name', 'Unknown')
                url = source.get('url', '#')
                source_type = source.get('type', 'unknown')
                score = source.get('score', 0)
                report += f"- **{name}** ({source_type}) - Score: {score} - [Link]({url})\n"
        
        selected = poc_data.get('selected')
        if selected:
            report += f"\n**Selected PoC:** {selected.get('name', 'Unknown')} ([Link]({selected.get('url', '#')}))\n"
    
    # Add exploit execution results
    exploit_data = data.get("exploit", {})
    if exploit_data and isinstance(exploit_data, list):
        report += "\n### Exploit Execution Results\n"
        
        # Find key results
        vulnerable_found = False
        execution_log = []
        
        for entry in exploit_data:
            stage = entry.get('stage', '')
            message = entry.get('msg', '')
            timestamp = entry.get('t', 0)
            
            execution_log.append(f"[{timestamp:.3f}s] {stage}: {message}")
            
            if 'VULNERABLE' in message:
                vulnerable_found = True
                report += "**🚨 VULNERABILITY CONFIRMED**: Target is vulnerable to Zerologon attack\n\n"
            elif 'NOT_ACCESSIBLE' in message:
                report += "**❌ TARGET NOT ACCESSIBLE**: Could not reach target for testing\n\n"
        
        # Add execution timeline
        report += "#### Execution Timeline\n```\n"
        for log_entry in execution_log[-10:]:  # Last 10 entries
            report += log_entry + "\n"
        report += "```\n"
    
    # Risk Assessment
    report += "\n---\n\n## Risk Assessment\n"
    
    if data.get("scan", {}).get('inferences', {}).get('kerberos_present'):
        report += """
### CVE-2020-1472 (Zerologon)
**CVSS Score:** 10.0 (Critical)  
**Impact:** Complete domain compromise  
**Likelihood:** High (if unpatched)

**Description:** An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection to a domain controller, using the Netlogon Remote Protocol (MS-NRPC).

**Attack Vector:** Network-based attack requiring no authentication

**Potential Impact:**
- Complete Active Directory compromise
- Domain Administrator privilege escalation  
- Lateral movement capabilities
- Data exfiltration and ransomware deployment
"""
    else:
        report += "No critical vulnerabilities identified in this assessment.\n"
    
    # Recommendations
    report += "\n---\n\n## Recommendations\n"
    
    if data.get("scan", {}).get('inferences', {}).get('kerberos_present'):
        report += """
### Immediate Actions Required
1. **Apply Microsoft Security Updates**: Install KB4556414 and later updates immediately
2. **Monitor Domain Controllers**: Check for suspicious authentication patterns
3. **Network Segmentation**: Restrict network access to domain controllers
4. **Backup Verification**: Ensure clean backups are available and tested

### Long-term Security Improvements  
1. **Implement Privileged Access Management (PAM)**
2. **Deploy Advanced Threat Detection** 
3. **Regular Vulnerability Assessments**
4. **Security Awareness Training**
5. **Incident Response Plan Updates**
"""
    else:
        report += """
### General Recommendations
1. **Regular Security Updates**: Maintain current patch levels
2. **Network Monitoring**: Implement continuous security monitoring  
3. **Access Controls**: Review and strengthen access management
4. **Security Assessments**: Conduct regular penetration testing
"""
    
    # Technical Appendix
    report += "\n---\n\n## Technical Appendix\n"
    report += "\n### Raw Scan Data\n```json\n"
    report += json.dumps(scan_data, indent=2)
    report += "\n```\n"
    
    if poc_data:
        report += "\n### PoC Research Data\n```json\n"
        report += json.dumps(poc_data, indent=2)
        report += "\n```\n"
    
    # Footer
    report += f"""
---

## References
- [CVE-2020-1472 Details](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472)
- [Microsoft Security Advisory](https://msrc.microsoft.com/update-guide/en-US/vulnerability/CVE-2020-1472)
- [NIST National Vulnerability Database](https://nvd.nist.gov/vuln/detail/CVE-2020-1472)

---
*Report generated by BreachPilot v2.0 - AI-Assisted Penetration Testing Platform*  
*Generated on: {timestamp}*
"""
    
    return report


def generate_pdf_from_markdown(markdown_content: str, output_path: Path) -> bool:
    """Convert Markdown to PDF using WeasyPrint"""
    try:
        # Convert Markdown to HTML
        html_content = markdown.markdown(
            markdown_content, 
            extensions=['tables', 'codehilite', 'toc']
        )
        
        # Add CSS styling
        css_content = """
        @page {
            margin: 2cm;
            @top-center {
                content: "BreachPilot Penetration Test Report";
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: counter(page) "/" counter(pages);
                font-size: 10pt;
                color: #666;
            }
        }
        
        body {
            font-family: 'Arial', sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: none;
        }
        
        h1 {
            color: #2c3e50;
            border-bottom: 3px solid #e74c3c;
            padding-bottom: 0.5em;
        }
        
        h2 {
            color: #34495e;
            border-bottom: 2px solid #3498db;
            padding-bottom: 0.3em;
            margin-top: 2em;
        }
        
        h3 {
            color: #7f8c8d;
            margin-top: 1.5em;
        }
        
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 1em 0;
        }
        
        th, td {
            border: 1px solid #bdc3c7;
            padding: 8px;
            text-align: left;
        }
        
        th {
            background-color: #ecf0f1;
            font-weight: bold;
        }
        
        code {
            background-color: #f8f9fa;
            padding: 2px 4px;
            border-radius: 3px;
            font-family: 'Courier New', monospace;
        }
        
        pre {
            background-color: #f8f9fa;
            padding: 1em;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            overflow-x: auto;
        }
        
        .highlight {
            background-color: #fff3cd;
            padding: 0.5em;
            border-radius: 5px;
            border-left: 4px solid #ffc107;
        }
        
        strong {
            color: #2c3e50;
        }
        """
        
        # Create complete HTML document
        full_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>BreachPilot Penetration Test Report</title>
        </head>
        <body>
            {html_content}
        </body>
        </html>
        """
        
        # Generate PDF
        font_config = FontConfiguration()
        html_doc = HTML(string=full_html)
        css_doc = CSS(string=css_content, font_config=font_config)
        
        html_doc.write_pdf(output_path, stylesheets=[css_doc], font_config=font_config)
        return True
        
    except Exception as e:
        print(f"PDF generation error: {e}")
        return False


def create_placeholder_pdf(output_path: Path):
    """Create a simple placeholder PDF"""
    try:
        simple_html = """
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <title>BreachPilot Report</title>
        </head>
        <body>
            <h1>BreachPilot Penetration Test Report</h1>
            <p>PDF generation encountered an issue. Please refer to the Markdown version of this report.</p>
            <p><strong>Note:</strong> This is a placeholder PDF. The complete report is available in Markdown format.</p>
        </body>
        </html>
        """
        
        HTML(string=simple_html).write_pdf(output_path)
        
    except Exception:
        # Last resort: write minimal binary PDF
        output_path.write_bytes(
            b"%PDF-1.4\n1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\nxref\n0 4\n0000000000 65535 f \n0000000009 00000 n \n0000000058 00000 n \n0000000115 00000 n \ntrailer<</Size 4/Root 1 0 R>>\nstartxref\n189\n%%EOF"
        )
