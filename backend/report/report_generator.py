import json
import markdown
from datetime import datetime
from pathlib import Path
from typing import Optional
from jinja2 import Template
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, PageBreak, Table, TableStyle
from reportlab.lib import colors
from backend.models import ReportData, ScanSession
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class ReportGenerator:
    def __init__(self):
        self.reports_dir = config.REPORTS_DIR
    
    def generate_report(self, session: ScanSession) -> ReportData:
        """Generate comprehensive penetration test report"""
        logger.info(f"Generating report for {session.target_ip}")
        
        report_data = ReportData(
            target_ip=session.target_ip,
            osint_result=session.osint_result,
            nmap_result=session.nmap_result,
            analyst_result=session.analyst_result,
            poc_results=session.poc_results,
            exploit_results=session.exploit_results
        )
        
        # Generate executive summary
        report_data.executive_summary = self._generate_executive_summary(session)
        
        # Generate markdown report
        report_data.markdown_report = self._generate_markdown_report(session)
        
        # Save markdown
        md_path = self.reports_dir / f"{session.target_ip}_report.md"
        with open(md_path, 'w', encoding='utf-8') as f:
            f.write(report_data.markdown_report)
        logger.info(f"Markdown report saved to {md_path}")
        
        # Generate PDF
        pdf_path = self._generate_pdf_report(session, report_data)
        report_data.pdf_path = str(pdf_path)
        
        # Save report data
        self._save_report_data(session.target_ip, report_data)
        
        return report_data
    
    def _generate_executive_summary(self, session: ScanSession) -> str:
        """Generate executive summary"""
        summary_parts = []
        
        # Header
        summary_parts.append(f"# Executive Summary - Penetration Test Report")
        summary_parts.append(f"**Target:** {session.target_ip}")
        summary_parts.append(f"**Date:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        summary_parts.append("\n")
        
        # Key findings
        if session.analyst_result and session.analyst_result.identified_cves:
            cve_count = len(session.analyst_result.identified_cves)
            critical_count = sum(1 for cve in session.analyst_result.identified_cves 
                               if cve.cvss_score and cve.cvss_score >= 9.0)
            
            summary_parts.append(f"## Key Findings")
            summary_parts.append(f"- **Total Vulnerabilities:** {cve_count}")
            summary_parts.append(f"- **Critical Vulnerabilities:** {critical_count}")
            
            if session.exploit_results:
                successful = sum(1 for e in session.exploit_results if e.success)
                summary_parts.append(f"- **Successfully Exploited:** {successful}/{len(session.exploit_results)}")
        
        # Risk assessment
        if session.analyst_result:
            summary_parts.append("\n## Risk Assessment")
            summary_parts.append(session.analyst_result.risk_assessment)
        
        # Recommendations
        summary_parts.append("\n## Immediate Actions Required")
        if session.analyst_result and session.analyst_result.identified_cves:
            for cve in session.analyst_result.identified_cves[:3]:  # Top 3
                summary_parts.append(f"- **{cve.cve_id}**: {cve.recommendation}")
        
        return "\n".join(summary_parts)
    
    def _generate_markdown_report(self, session: ScanSession) -> str:
        """Generate detailed markdown report"""
        template_str = """# Penetration Test Report

## Target Information
- **IP Address:** {{ session.target_ip }}
- **Scan Date:** {{ scan_date }}
- **Report Generated:** {{ report_date }}

## Executive Summary
{{ executive_summary }}

---

## 1. OSINT Results

{% if session.osint_result %}
### Target Intelligence
- **Hostname:** {{ session.osint_result.hostname or 'N/A' }}
- **Domain:** {{ session.osint_result.domain or 'N/A' }}

### Subdomains Discovered
{% if session.osint_result.subdomains %}
{% for subdomain in session.osint_result.subdomains %}
- {{ subdomain }}
{% endfor %}
{% else %}
- None found
{% endif %}

### Public Services
{% if session.osint_result.public_services %}
{% for service in session.osint_result.public_services %}
- **Port {{ service.port }}:** {{ service.product or 'Unknown' }} {{ service.version or '' }}
{% endfor %}
{% else %}
- No public services identified
{% endif %}
{% endif %}

---

## 2. Network Scan Results

{% if session.nmap_result %}
### Open Ports
{% for port in session.nmap_result.open_ports %}
- **Port {{ port.port }}** ({{ port.state }}): {{ port.service }} - {{ port.product }} {{ port.version }}
{% endfor %}

### OS Detection
{% if session.nmap_result.os_detection %}
- **OS Name:** {{ session.nmap_result.os_detection.name }}
- **Accuracy:** {{ session.nmap_result.os_detection.accuracy }}%
{% endif %}
{% endif %}

---

## 3. Vulnerability Analysis

{% if session.analyst_result %}
### Identified Vulnerabilities

{% for cve in session.analyst_result.identified_cves %}
#### {{ cve.cve_id }}
- **CVSS Score:** {{ cve.cvss_score or 'N/A' }}
- **Affected Service:** {{ cve.affected_service }}
- **Description:** {{ cve.description }}
- **Exploit Available:** {{ 'Yes' if cve.exploit_available else 'No' }}

**Analysis:**
{{ cve.xai_explanation }}

**Recommendation:**
{{ cve.recommendation }}

---
{% endfor %}

### Risk Assessment
{{ session.analyst_result.risk_assessment }}
{% endif %}

---

## 4. Exploitation Results

{% if session.exploit_results %}
{% for exploit in session.exploit_results %}
### {{ exploit.cve_id }}
- **Status:** {{ 'Success ✓' if exploit.success else 'Failed ✗' }}
- **Command:** `{{ exploit.exploit_command }}`

**Output:**
```
{{ exploit.execution_output[:500] }}...
```

{% if exploit.evidence %}
**Evidence:**
{% for evidence in exploit.evidence %}
- {{ evidence }}
{% endfor %}
{% endif %}

---
{% endfor %}
{% else %}
No exploitation attempts were made.
{% endif %}

---

## 5. Recommendations

### Immediate Actions
{% if session.analyst_result and session.analyst_result.priority_vulnerabilities %}
{% for cve_id in session.analyst_result.priority_vulnerabilities[:5] %}
- Address {{ cve_id }} immediately
{% endfor %}
{% endif %}

### Long-term Security Improvements
1. Implement regular security patching schedule
2. Enable security monitoring and logging
3. Conduct periodic vulnerability assessments
4. Implement network segmentation
5. Enable multi-factor authentication

---

## 6. Conclusion

This penetration test identified {{ session.analyst_result.identified_cves|length if session.analyst_result else 0 }} vulnerabilities in the target system. 
{% if session.exploit_results %}
{{ session.exploit_results|selectattr('success')|list|length }} vulnerabilities were successfully exploited, demonstrating real-world risk.
{% endif %}

Immediate remediation is recommended for all critical and high-severity findings.

---

*Report generated by BreachPilot - Automated Penetration Testing System*
"""
        
        template = Template(template_str)
        
        return template.render(
            session=session,
            scan_date=session.created_at.strftime('%Y-%m-%d %H:%M:%S'),
            report_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            executive_summary=self._generate_executive_summary(session)
        )
    
    def _generate_pdf_report(self, session: ScanSession, report_data: ReportData) -> Path:
        """Generate PDF report from markdown"""
        pdf_path = self.reports_dir / f"{session.target_ip}_report.pdf"
        
        # Create PDF document
        doc = SimpleDocTemplate(
            str(pdf_path),
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18
        )
        
        # Container for PDF elements
        story = []
        styles = getSampleStyleSheet()
        
        # Custom styles
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30
        )
        
        heading_style = ParagraphStyle(
            'CustomHeading',
            parent=styles['Heading2'],
            fontSize=16,
            textColor=colors.HexColor('#2c3e50'),
            spaceAfter=12
        )
        
        # Title
        story.append(Paragraph("Penetration Test Report", title_style))
        story.append(Spacer(1, 12))
        
        # Target info
        target_info = [
            ['Target IP:', session.target_ip],
            ['Scan Date:', session.created_at.strftime('%Y-%m-%d %H:%M:%S')],
            ['Report Date:', datetime.now().strftime('%Y-%m-%d %H:%M:%S')]
        ]
        
        t = Table(target_info, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#f0f0f0')),
            ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('GRID', (0, 0), (-1, -1), 1, colors.grey)
        ]))
        story.append(t)
        story.append(Spacer(1, 20))
        
        # Executive Summary
        story.append(Paragraph("Executive Summary", heading_style))
        for line in report_data.executive_summary.split('\n'):
            if line.strip():
                story.append(Paragraph(line, styles['Normal']))
                story.append(Spacer(1, 6))
        
        story.append(PageBreak())
        
        # Vulnerabilities table
        if session.analyst_result and session.analyst_result.identified_cves:
            story.append(Paragraph("Identified Vulnerabilities", heading_style))
            story.append(Spacer(1, 12))
            
            vuln_data = [['CVE ID', 'CVSS', 'Service', 'Exploit Available']]
            for cve in session.analyst_result.identified_cves:
                vuln_data.append([
                    cve.cve_id,
                    str(cve.cvss_score) if cve.cvss_score else 'N/A',
                    cve.affected_service[:30],
                    'Yes' if cve.exploit_available else 'No'
                ])
            
            t = Table(vuln_data, colWidths=[1.5*inch, 0.8*inch, 2*inch, 1.2*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#34495e')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 12),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                ('GRID', (0, 0), (-1, -1), 1, colors.black)
            ]))
            story.append(t)
        
        # Build PDF
        doc.build(story)
        logger.info(f"PDF report saved to {pdf_path}")
        
        return pdf_path
    
    def _save_report_data(self, target_ip: str, report_data: ReportData):
        """Save report data to JSON"""
        output_file = config.DATA_DIR / f"{target_ip}_report.json"
        with open(output_file, 'w') as f:
            json.dump(report_data.model_dump(), f, indent=2, default=str)
        logger.info(f"Report data saved to {output_file}")
