#!/usr/bin/env python3
"""
Professional PDF Report Generator
Generates executive-level penetration testing reports
"""

import os
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
import logging

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4, letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch, cm
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image, KeepTogether
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT, TA_JUSTIFY
    from reportlab.pdfgen import canvas
    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False

logger = logging.getLogger(__name__)

class ProfessionalPDFGenerator:
    """Generate professional penetration testing reports"""
    
    def __init__(self):
        if not REPORTLAB_AVAILABLE:
            raise ImportError("reportlab is required for PDF generation. Install with: pip install reportlab")
        
        self.styles = getSampleStyleSheet()
        self._setup_custom_styles()
    
    def _setup_custom_styles(self):
        """Setup custom paragraph styles"""
        # Title style
        self.styles.add(ParagraphStyle(
            name='CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER,
            fontName='Helvetica-Bold'
        ))
        
        # Executive Summary style
        self.styles.add(ParagraphStyle(
            name='ExecutiveSummary',
            parent=self.styles['BodyText'],
            fontSize=11,
            leading=16,
            spaceAfter=12,
            alignment=TA_JUSTIFY
        ))
        
        # Section Header
        self.styles.add(ParagraphStyle(
            name='SectionHeader',
            parent=self.styles['Heading2'],
            fontSize=14,
            textColor=colors.HexColor('#2c3e50'),
            spaceBefore=20,
            spaceAfter=12,
            fontName='Helvetica-Bold'
        ))
        
        # Finding Title
        self.styles.add(ParagraphStyle(
            name='FindingTitle',
            parent=self.styles['Heading3'],
            fontSize=12,
            textColor=colors.HexColor('#e74c3c'),
            spaceBefore=15,
            spaceAfter=8,
            fontName='Helvetica-Bold'
        ))
    
    def generate_report(self, scan_data: Dict[str, Any], output_path: str):
        """Generate complete penetration testing report"""
        logger.info(f"Generating PDF report: {output_path}")
        
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            rightMargin=72,
            leftMargin=72,
            topMargin=72,
            bottomMargin=18,
        )
        
        story = []
        
        # Cover Page
        story.extend(self._create_cover_page(scan_data))
        story.append(PageBreak())
        
        # Table of Contents
        story.extend(self._create_toc())
        story.append(PageBreak())
        
        # Executive Summary
        story.extend(self._create_executive_summary(scan_data))
        story.append(PageBreak())
        
        # Methodology
        story.extend(self._create_methodology())
        story.append(PageBreak())
        
        # Findings
        story.extend(self._create_findings(scan_data))
        story.append(PageBreak())
        
        # Recommendations
        story.extend(self._create_recommendations(scan_data))
        story.append(PageBreak())
        
        # Technical Details
        story.extend(self._create_technical_details(scan_data))
        story.append(PageBreak())
        
        # Appendix
        story.extend(self._create_appendix(scan_data))
        
        # Build PDF
        doc.build(story, onFirstPage=self._add_page_number, onLaterPages=self._add_page_number)
        logger.info(f"PDF report generated successfully: {output_path}")
    
    def _create_cover_page(self, data: Dict[str, Any]) -> List:
        """Create professional cover page"""
        story = []
        
        story.append(Spacer(1, 1*inch))
        
        # Report Title
        title = Paragraph(
            "<b>PENETRATION TESTING REPORT</b>",
            self.styles['CustomTitle']
        )
        story.append(title)
        story.append(Spacer(1, 0.5*inch))
        
        # Client Information
        client_info = f"""
            <para alignment='center'>
            <b>Target:</b> {data.get('target', 'N/A')}<br/>
            <b>Assessment Type:</b> Network Infrastructure<br/>
            <b>Date:</b> {datetime.now().strftime('%B %d, %Y')}<br/>
            <b>Version:</b> 1.0<br/>
            </para>
        """
        story.append(Paragraph(client_info, self.styles['BodyText']))
        story.append(Spacer(1, 1*inch))
        
        # Confidentiality Notice
        confidentiality = """
            <para alignment='center' fontSize='10' textColor='red'>
            <b>CONFIDENTIAL</b><br/>
            This document contains sensitive security information.<br/>
            Unauthorized disclosure is prohibited.
            </para>
        """
        story.append(Paragraph(confidentiality, self.styles['BodyText']))
        
        return story
    
    def _create_toc(self) -> List:
        """Create table of contents"""
        story = []
        
        story.append(Paragraph("<b>TABLE OF CONTENTS</b>", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.3*inch))
        
        toc_data = [
            ['1.', 'Executive Summary', '3'],
            ['2.', 'Methodology', '4'],
            ['3.', 'Findings Summary', '5'],
            ['4.', 'Detailed Findings', '6'],
            ['5.', 'Recommendations', '10'],
            ['6.', 'Technical Details', '12'],
            ['7.', 'Appendix', '15'],
        ]
        
        toc_table = Table(toc_data, colWidths=[0.5*inch, 5*inch, 0.5*inch])
        toc_table.setStyle(TableStyle([
            ('FONT', (0, 0), (-1, -1), 'Helvetica', 11),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 12),
            ('ALIGN', (0, 0), (0, -1), 'RIGHT'),
            ('ALIGN', (2, 0), (2, -1), 'RIGHT'),
        ]))
        
        story.append(toc_table)
        
        return story
    
    def _create_executive_summary(self, data: Dict[str, Any]) -> List:
        """Create executive summary"""
        story = []
        
        story.append(Paragraph("1. EXECUTIVE SUMMARY", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Assessment Overview
        summary_text = f"""
            BreachPilot conducted a comprehensive penetration test of the target infrastructure 
            at {data.get('target', 'N/A')} on {datetime.now().strftime('%B %d, %Y')}. 
            The assessment identified {len(data.get('vulnerabilities', []))} security vulnerabilities 
            of varying severity levels.
            <br/><br/>
            <b>Key Findings:</b><br/>
        """
        
        # Count vulnerabilities by severity
        vulns = data.get('vulnerabilities', [])
        critical = len([v for v in vulns if v.get('severity') == 'CRITICAL'])
        high = len([v for v in vulns if v.get('severity') == 'HIGH'])
        medium = len([v for v in vulns if v.get('severity') == 'MEDIUM'])
        low = len([v for v in vulns if v.get('severity') == 'LOW'])
        
        summary_text += f"""
            • <font color='red'><b>Critical:</b> {critical}</font><br/>
            • <font color='orange'><b>High:</b> {high}</font><br/>
            • <font color='yellow'><b>Medium:</b> {medium}</font><br/>
            • <font color='green'><b>Low:</b> {low}</font><br/>
        """
        
        story.append(Paragraph(summary_text, self.styles['ExecutiveSummary']))
        story.append(Spacer(1, 0.2*inch))
        
        # Risk Summary Table
        risk_data = [
            ['Severity', 'Count', 'Risk Level'],
            ['Critical', str(critical), 'Immediate Action Required'],
            ['High', str(high), 'Urgent Remediation'],
            ['Medium', str(medium), 'Planned Remediation'],
            ['Low', str(low), 'Best Practice'],
        ]
        
        risk_table = Table(risk_data, colWidths=[2*inch, 1*inch, 3*inch])
        risk_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        
        story.append(risk_table)
        
        return story
    
    def _create_methodology(self) -> List:
        """Create methodology section"""
        story = []
        
        story.append(Paragraph("2. METHODOLOGY", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        methodology_text = """
            The penetration test followed industry-standard methodologies including:
            <br/><br/>
            <b>2.1 Information Gathering</b><br/>
            • Network reconnaissance<br/>
            • Service enumeration<br/>
            • Operating system fingerprinting<br/>
            <br/>
            <b>2.2 Vulnerability Analysis</b><br/>
            • Automated vulnerability scanning<br/>
            • Manual verification of findings<br/>
            • CVE database correlation<br/>
            <br/>
            <b>2.3 Exploitation</b><br/>
            • Proof-of-concept exploitation<br/>
            • Privilege escalation attempts<br/>
            • Lateral movement assessment<br/>
            <br/>
            <b>2.4 Post-Exploitation</b><br/>
            • Data access verification<br/>
            • Persistence mechanisms<br/>
            • Impact analysis<br/>
        """
        
        story.append(Paragraph(methodology_text, self.styles['ExecutiveSummary']))
        
        return story
    
    def _create_findings(self, data: Dict[str, Any]) -> List:
        """Create detailed findings section"""
        story = []
        
        story.append(Paragraph("3. DETAILED FINDINGS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        vulnerabilities = data.get('vulnerabilities', [])
        
        for i, vuln in enumerate(vulnerabilities, 1):
            # Finding Title
            finding_title = f"<b>Finding {i}: {vuln.get('cve_id', 'Unknown')} - {vuln.get('title', 'Vulnerability')}</b>"
            story.append(Paragraph(finding_title, self.styles['FindingTitle']))
            
            # Severity Badge
            severity = vuln.get('severity', 'UNKNOWN')
            severity_color = {
                'CRITICAL': 'red',
                'HIGH': 'orange',
                'MEDIUM': 'yellow',
                'LOW': 'green'
            }.get(severity, 'grey')
            
            severity_text = f"<font color='{severity_color}'><b>Severity: {severity}</b></font>"
            story.append(Paragraph(severity_text, self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
            
            # Finding Details
            finding_data = [
                ['Description:', vuln.get('description', 'No description available')],
                ['CVSS Score:', f"{vuln.get('cvss_score', 'N/A')}"],
                ['Affected System:', vuln.get('affected_system', data.get('target', 'N/A'))],
                ['Status:', vuln.get('status', 'Verified')],
            ]
            
            finding_table = Table(finding_data, colWidths=[1.5*inch, 4.5*inch])
            finding_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('LEFTPADDING', (0, 0), (-1, -1), 6),
                ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ]))
            
            story.append(finding_table)
            story.append(Spacer(1, 0.2*inch))
            
            # Impact
            impact_text = f"<b>Impact:</b> {vuln.get('impact', 'Potential compromise of system security')}"
            story.append(Paragraph(impact_text, self.styles['BodyText']))
            story.append(Spacer(1, 0.1*inch))
            
            # Evidence
            if vuln.get('evidence'):
                evidence_text = f"<b>Evidence:</b><br/>{vuln.get('evidence')}"
                story.append(Paragraph(evidence_text, self.styles['BodyText']))
            
            story.append(Spacer(1, 0.3*inch))
        
        return story
    
    def _create_recommendations(self, data: Dict[str, Any]) -> List:
        """Create recommendations section"""
        story = []
        
        story.append(Paragraph("4. RECOMMENDATIONS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        recommendations_text = """
            Based on the findings, we recommend the following remediation actions:
            <br/><br/>
            <b>Immediate Actions (Critical/High):</b><br/>
            1. Apply all available security patches immediately<br/>
            2. Disable vulnerable services where possible<br/>
            3. Implement network segmentation<br/>
            4. Review and update access controls<br/>
            <br/>
            <b>Short-term Actions (30 days):</b><br/>
            1. Conduct security awareness training<br/>
            2. Implement monitoring and alerting<br/>
            3. Review and update security policies<br/>
            4. Schedule regular vulnerability assessments<br/>
            <br/>
            <b>Long-term Actions (90 days):</b><br/>
            1. Implement defense-in-depth strategy<br/>
            2. Establish incident response procedures<br/>
            3. Conduct regular penetration tests<br/>
            4. Maintain security patch management program<br/>
        """
        
        story.append(Paragraph(recommendations_text, self.styles['ExecutiveSummary']))
        
        return story
    
    def _create_technical_details(self, data: Dict[str, Any]) -> List:
        """Create technical details section"""
        story = []
        
        story.append(Paragraph("5. TECHNICAL DETAILS", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        # Scan Information
        scan_info = f"""
            <b>Target Information:</b><br/>
            • Target: {data.get('target', 'N/A')}<br/>
            • Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
            • Scanner: BreachPilot v2.0<br/>
            • Scan Duration: {data.get('scan_duration', 'N/A')}<br/>
            <br/>
            <b>Tools Used:</b><br/>
            • Nmap - Network scanning<br/>
            • Metasploit - Exploitation framework<br/>
            • Custom CVE exploits<br/>
            • BreachPilot AI Analysis<br/>
        """
        
        story.append(Paragraph(scan_info, self.styles['BodyText']))
        
        return story
    
    def _create_appendix(self, data: Dict[str, Any]) -> List:
        """Create appendix section"""
        story = []
        
        story.append(Paragraph("6. APPENDIX", self.styles['SectionHeader']))
        story.append(Spacer(1, 0.2*inch))
        
        appendix_text = """
            <b>A. References</b><br/>
            • OWASP Testing Guide<br/>
            • PTES - Penetration Testing Execution Standard<br/>
            • NIST SP 800-115<br/>
            • CVE Database (cve.mitre.org)<br/>
            <br/>
            <b>B. Glossary</b><br/>
            • <b>CVE:</b> Common Vulnerabilities and Exposures<br/>
            • <b>CVSS:</b> Common Vulnerability Scoring System<br/>
            • <b>PoC:</b> Proof of Concept<br/>
            • <b>RCE:</b> Remote Code Execution<br/>
            <br/>
            <b>C. Contact Information</b><br/>
            For questions regarding this report, please contact:<br/>
            Email: security@breachpilot.com<br/>
            Report ID: {data.get('report_id', 'N/A')}<br/>
        """
        
        story.append(Paragraph(appendix_text, self.styles['BodyText']))
        
        return story
    
    def _add_page_number(self, canvas, doc):
        """Add page numbers to each page"""
        page_num = canvas.getPageNumber()
        text = f"Page {page_num}"
        canvas.saveState()
        canvas.setFont('Helvetica', 9)
        canvas.drawRightString(200*cm, 0.75*cm, text)
        canvas.drawString(1*cm, 0.75*cm, "BreachPilot Report")
        canvas.restoreState()


def generate_pentest_report(scan_data: Dict[str, Any], output_dir: str) -> str:
    """Generate a professional penetration testing PDF report"""
    if not REPORTLAB_AVAILABLE:
        raise ImportError("reportlab is required. Install with: pip install reportlab")
    
    # Generate unique filename
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    target = scan_data.get('target', 'unknown').replace('.', '_')
    filename = f"pentest_report_{target}_{timestamp}.pdf"
    output_path = os.path.join(output_dir, filename)
    
    # Create output directory if it doesn't exist
    os.makedirs(output_dir, exist_ok=True)
    
    # Generate report
    generator = ProfessionalPDFGenerator()
    generator.generate_report(scan_data, output_path)
    
    return output_path
