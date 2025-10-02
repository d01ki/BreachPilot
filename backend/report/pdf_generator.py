"""
PDF Report Generator - Professional PDF report generation with charts and formatting
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, Any
import logging
import tempfile
import subprocess
import json

logger = logging.getLogger(__name__)

class PDFReportGenerator:
    """Generate professional PDF reports with advanced formatting"""
    
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.reports_dir.mkdir(exist_ok=True)
    
    def generate_pdf_report(self, target_ip: str, report_data: Dict[str, Any], output_path: Path) -> Path:
        """Generate comprehensive PDF report"""
        logger.info(f"Generating PDF report for {target_ip}")
        
        try:
            # Try to use weasyprint for HTML to PDF conversion
            from weasyprint import HTML, CSS
            from weasyprint.text.fonts import FontConfiguration
            
            # Generate HTML content first
            html_content = self._generate_html_content(target_ip, report_data)
            
            # Create CSS for PDF styling
            css_content = self._generate_pdf_css()
            
            # Generate PDF
            font_config = FontConfiguration()
            html_doc = HTML(string=html_content)
            css_doc = CSS(string=css_content, font_config=font_config)
            
            html_doc.write_pdf(str(output_path), stylesheets=[css_doc], font_config=font_config)
            logger.info(f"PDF report generated successfully: {output_path}")
            
        except ImportError:
            logger.warning("WeasyPrint not available, using fallback method")
            self._generate_fallback_pdf(target_ip, report_data, output_path)
            
        except Exception as e:
            logger.error(f"PDF generation failed: {e}")
            self._generate_error_pdf(output_path, target_ip, str(e))
        
        return output_path
    
    def _generate_html_content(self, target_ip: str, report_data: Dict[str, Any]) -> str:
        """Generate HTML content for PDF conversion"""
        
        metadata = report_data.get("report_metadata", {})
        executive_summary = report_data.get("executive_summary", {})
        risk_assessment = report_data.get("risk_assessment", {})
        technical_analysis = report_data.get("technical_analysis", {})
        compliance_analysis = report_data.get("compliance_analysis", {})
        recommendations = report_data.get("detailed_recommendations", [])
        roadmap = report_data.get("remediation_roadmap", {})
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="UTF-8">
            <title>Security Assessment Report - {target_ip}</title>
        </head>
        <body>
            <!-- Cover Page -->
            <div class="cover-page">
                <div class="header">
                    <h1>SECURITY ASSESSMENT REPORT</h1>
                    <h2>{target_ip}</h2>
                    <div class="metadata">
                        <p><strong>Report ID:</strong> {metadata.get('report_id', 'N/A')}</p>
                        <p><strong>Date:</strong> {metadata.get('generation_date', 'N/A')}</p>
                        <p><strong>Classification:</strong> {metadata.get('classification', 'CONFIDENTIAL')}</p>
                    </div>
                </div>
            </div>
            
            <!-- Executive Summary -->
            <div class="section">
                <h1>Executive Summary</h1>
                <div class="executive-content">
                    <h2>Assessment Overview</h2>
                    <p>{executive_summary.get('assessment_overview', 'Assessment completed.')}</p>
                    
                    <h2>Key Findings</h2>
                    <ul>
                        {"".join(f"<li>{finding}</li>" for finding in executive_summary.get('key_findings', []))}
                    </ul>
                    
                    <h2>Critical Risks</h2>
                    <ul>
                        {"".join(f"<li>{risk}</li>" for risk in executive_summary.get('critical_risks', []))}
                    </ul>
                    
                    <h2>Immediate Actions Required</h2>
                    <ul>
                        {"".join(f"<li>{action}</li>" for action in executive_summary.get('immediate_actions', []))}
                    </ul>
                </div>
            </div>
            
            <!-- Risk Assessment -->
            <div class="section">
                <h1>Risk Assessment</h1>
                <div class="risk-metrics">
                    <div class="metric-row">
                        <div class="metric">
                            <strong>Overall Risk Level:</strong> {risk_assessment.get('overall_risk_level', 'Unknown')}
                        </div>
                        <div class="metric">
                            <strong>Risk Score:</strong> {risk_assessment.get('risk_score', 0):.1f}/10
                        </div>
                    </div>
                    <div class="metric-row">
                        <div class="metric">
                            <strong>Critical Vulnerabilities:</strong> {risk_assessment.get('critical_vulnerabilities', 0)}
                        </div>
                        <div class="metric">
                            <strong>High Vulnerabilities:</strong> {risk_assessment.get('high_vulnerabilities', 0)}
                        </div>
                    </div>
                    <div class="metric-row">
                        <div class="metric">
                            <strong>Financial Impact:</strong> {risk_assessment.get('financial_impact_estimate', 'Unknown')}
                        </div>
                        <div class="metric">
                            <strong>Remediation Priority:</strong> {risk_assessment.get('remediation_priority', 'Unknown')}
                        </div>
                    </div>
                </div>
                
                <h2>Business Impact Analysis</h2>
                <p><strong>Impact:</strong> {risk_assessment.get('business_impact', 'Assessment in progress.')}</p>
                <p><strong>Technical Impact:</strong> {risk_assessment.get('technical_impact', 'Assessment in progress.')}</p>
                <p><strong>Likelihood:</strong> {risk_assessment.get('likelihood', 'Assessment in progress.')}</p>
            </div>
            
            <!-- Technical Analysis -->
            <div class="section">
                <h1>Technical Analysis</h1>
                
                <h2>Attack Vectors</h2>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>CVE ID</th>
                            <th>Attack Type</th>
                            <th>Target Service</th>
                            <th>Complexity</th>
                            <th>Impact</th>
                        </tr>
                    </thead>
                    <tbody>
                        {"".join(f"""
                        <tr>
                            <td>{vector.get('cve_id', 'N/A')}</td>
                            <td>{vector.get('attack_type', 'Unknown')}</td>
                            <td>{vector.get('target_service', 'Unknown')}</td>
                            <td>{vector.get('complexity', 'Unknown')}</td>
                            <td>{vector.get('impact', 'Unknown')}</td>
                        </tr>
                        """ for vector in technical_analysis.get('attack_vectors', [])[:10])}
                    </tbody>
                </table>
                
                <h2>Lateral Movement Analysis</h2>
                <p><strong>Network Segments:</strong> {technical_analysis.get('lateral_movement_potential', {}).get('network_segments', 'Unknown')}</p>
                <p><strong>Privileged Services:</strong> {technical_analysis.get('lateral_movement_potential', {}).get('privileged_services', 'Unknown')}</p>
                <p><strong>Risk Level:</strong> {technical_analysis.get('lateral_movement_potential', {}).get('risk_level', 'Unknown')}</p>
            </div>
            
            <!-- Recommendations -->
            <div class="section">
                <h1>Detailed Recommendations</h1>
                {"".join(f"""
                <div class="recommendation">
                    <h3>{rec.get('title', 'Recommendation')}</h3>
                    <p><strong>Priority:</strong> {rec.get('priority', 'Unknown')}</p>
                    <p><strong>Category:</strong> {rec.get('category', 'Unknown')}</p>
                    <p><strong>Description:</strong> {rec.get('description', 'No description available.')}</p>
                    <p><strong>Business Justification:</strong> {rec.get('business_justification', 'No justification provided.')}</p>
                    <p><strong>Timeline:</strong> {rec.get('timeline', 'Unknown')}</p>
                    <p><strong>Estimated Cost:</strong> {rec.get('estimated_cost', 'Unknown')}</p>
                </div>
                """ for rec in recommendations)}
            </div>
            
            <!-- Remediation Roadmap -->
            <div class="section">
                <h1>Remediation Roadmap</h1>
                {"".join(f"""
                <div class="roadmap-phase">
                    <h3>{phase.get('phase', 'Phase')}</h3>
                    <p><strong>Focus:</strong> {phase.get('focus', 'Unknown')}</p>
                    <p><strong>Activities:</strong></p>
                    <ul>
                        {"".join(f"<li>{activity}</li>" for activity in phase.get('activities', []))}
                    </ul>
                    <p><strong>Success Criteria:</strong> {phase.get('success_criteria', 'Unknown')}</p>
                    <p><strong>Budget:</strong> {phase.get('budget', 'Unknown')}</p>
                </div>
                """ for phase in roadmap.get('phases', []))}
                
                <div class="roadmap-summary">
                    <h3>Summary</h3>
                    <p><strong>Total Estimated Cost:</strong> {roadmap.get('total_estimated_cost', 'Unknown')}</p>
                    <p><strong>Expected ROI:</strong> {roadmap.get('expected_roi', 'Unknown')}</p>
                    <p><strong>Timeline:</strong> {roadmap.get('timeline', 'Unknown')}</p>
                </div>
            </div>
            
            <!-- Compliance Analysis -->
            <div class="section">
                <h1>Compliance Analysis</h1>
                <h2>Applicable Frameworks</h2>
                <ul>
                    {"".join(f"<li>{framework}</li>" for framework in compliance_analysis.get('applicable_frameworks', []))}
                </ul>
                
                <h2>Compliance Gaps</h2>
                {"".join(f"""
                <div class="compliance-gap">
                    <h4>{gap.get('framework', 'Unknown Framework')}</h4>
                    <p><strong>Requirement:</strong> {gap.get('requirement', 'Unknown')}</p>
                    <p><strong>Gap:</strong> {gap.get('gap', 'Unknown')}</p>
                    <p><strong>Impact:</strong> {gap.get('impact', 'Unknown')}</p>
                </div>
                """ for gap in compliance_analysis.get('compliance_gaps', []))}
            </div>
            
            <!-- Footer -->
            <div class="footer">
                <p>Generated by BreachPilot Professional Security Assessment Platform</p>
                <p>Report Classification: {metadata.get('classification', 'CONFIDENTIAL')}</p>
                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
        </body>
        </html>
        """
        
        return html_content
    
    def _generate_pdf_css(self) -> str:
        """Generate CSS styles for PDF formatting"""
        return """
        @page {
            size: A4;
            margin: 2cm;
            @top-center {
                content: "Security Assessment Report";
                font-size: 10pt;
                color: #666;
            }
            @bottom-center {
                content: "Page " counter(page) " of " counter(pages);
                font-size: 10pt;
                color: #666;
            }
        }
        
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            font-size: 11pt;
        }
        
        .cover-page {
            text-align: center;
            page-break-after: always;
            padding-top: 10cm;
        }
        
        .header h1 {
            font-size: 24pt;
            color: #2c3e50;
            margin-bottom: 20pt;
            font-weight: bold;
        }
        
        .header h2 {
            font-size: 18pt;
            color: #34495e;
            margin-bottom: 30pt;
        }
        
        .metadata {
            font-size: 12pt;
            color: #666;
            text-align: left;
            max-width: 400pt;
            margin: 0 auto;
        }
        
        .section {
            page-break-before: always;
            margin-bottom: 30pt;
        }
        
        .section:first-of-type {
            page-break-before: auto;
        }
        
        h1 {
            font-size: 18pt;
            color: #2c3e50;
            border-bottom: 2pt solid #3498db;
            padding-bottom: 5pt;
            margin-bottom: 20pt;
            font-weight: bold;
        }
        
        h2 {
            font-size: 14pt;
            color: #34495e;
            margin-top: 20pt;
            margin-bottom: 10pt;
            font-weight: bold;
        }
        
        h3 {
            font-size: 12pt;
            color: #34495e;
            margin-top: 15pt;
            margin-bottom: 8pt;
            font-weight: bold;
        }
        
        h4 {
            font-size: 11pt;
            color: #34495e;
            margin-top: 10pt;
            margin-bottom: 5pt;
            font-weight: bold;
        }
        
        .risk-metrics {
            background: #f8f9fa;
            padding: 15pt;
            border: 1pt solid #dee2e6;
            margin-bottom: 20pt;
        }
        
        .metric-row {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8pt;
        }
        
        .metric {
            flex: 1;
            padding: 5pt;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin: 15pt 0;
            font-size: 10pt;
        }
        
        .data-table th {
            background: #34495e;
            color: white;
            padding: 8pt;
            text-align: left;
            font-weight: bold;
            border: 1pt solid #2c3e50;
        }
        
        .data-table td {
            padding: 6pt 8pt;
            border: 1pt solid #dee2e6;
            vertical-align: top;
        }
        
        .data-table tr:nth-child(even) {
            background: #f8f9fa;
        }
        
        .recommendation {
            background: #fff3cd;
            border: 1pt solid #ffeaa7;
            padding: 12pt;
            margin: 10pt 0;
            border-radius: 3pt;
        }
        
        .roadmap-phase {
            background: #e8f4fd;
            border: 1pt solid #3498db;
            padding: 12pt;
            margin: 10pt 0;
            border-radius: 3pt;
        }
        
        .roadmap-summary {
            background: #d4edda;
            border: 1pt solid #c3e6cb;
            padding: 12pt;
            margin: 15pt 0;
            border-radius: 3pt;
        }
        
        .compliance-gap {
            background: #f8d7da;
            border: 1pt solid #f5c6cb;
            padding: 10pt;
            margin: 8pt 0;
            border-radius: 3pt;
        }
        
        .executive-content {
            background: #e8f4fd;
            padding: 15pt;
            border-left: 4pt solid #3498db;
        }
        
        ul, ol {
            margin-left: 20pt;
            margin-bottom: 10pt;
        }
        
        li {
            margin-bottom: 5pt;
        }
        
        p {
            margin-bottom: 10pt;
            text-align: justify;
        }
        
        .footer {
            margin-top: 30pt;
            padding-top: 15pt;
            border-top: 1pt solid #dee2e6;
            font-size: 9pt;
            color: #666;
            text-align: center;
        }
        
        strong {
            font-weight: bold;
        }
        
        /* Ensure proper page breaks */
        .section h1 {
            page-break-after: avoid;
        }
        
        .section h2 {
            page-break-after: avoid;
        }
        
        .data-table {
            page-break-inside: avoid;
        }
        
        .recommendation {
            page-break-inside: avoid;
        }
        """
    
    def _generate_fallback_pdf(self, target_ip: str, report_data: Dict[str, Any], output_path: Path):
        """Generate fallback PDF using basic text formatting"""
        logger.info("Generating fallback PDF report")
        
        # Create a simple text-based PDF content
        content = f"""
SECURITY ASSESSMENT REPORT
Target: {target_ip}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

EXECUTIVE SUMMARY
================
{report_data.get('executive_summary', {}).get('assessment_overview', 'Assessment completed.')}

Key Findings:
{chr(10).join(f"- {finding}" for finding in report_data.get('executive_summary', {}).get('key_findings', []))}

RISK ASSESSMENT
===============
Overall Risk Level: {report_data.get('risk_assessment', {}).get('overall_risk_level', 'Unknown')}
Risk Score: {report_data.get('risk_assessment', {}).get('risk_score', 0):.1f}/10
Critical Vulnerabilities: {report_data.get('risk_assessment', {}).get('critical_vulnerabilities', 0)}

RECOMMENDATIONS
===============
{chr(10).join(f"- {rec.get('title', 'Recommendation')}: {rec.get('description', 'No description')}" for rec in report_data.get('detailed_recommendations', []))}

Generated by BreachPilot Professional Security Assessment Platform
        """
        
        # Try to use pandoc if available
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.md', delete=False) as temp_file:
                temp_file.write(content)
                temp_file.flush()
                
                # Convert to PDF using pandoc
                subprocess.run([
                    'pandoc', temp_file.name,
                    '-o', str(output_path),
                    '--pdf-engine=wkhtmltopdf',
                    '--margin-top=2cm',
                    '--margin-bottom=2cm',
                    '--margin-left=2cm',
                    '--margin-right=2cm'
                ], check=True, capture_output=True)
                
                os.unlink(temp_file.name)
                logger.info(f"Fallback PDF generated successfully: {output_path}")
                
        except (subprocess.CalledProcessError, FileNotFoundError):
            # Final fallback: create a simple text file with .pdf extension
            logger.warning("Pandoc not available, creating text-based PDF")
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(content)
    
    def _generate_error_pdf(self, output_path: Path, target_ip: str, error_msg: str):
        """Generate error PDF file"""
        error_content = f"""
SECURITY ASSESSMENT REPORT - ERROR
Target: {target_ip}
Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

PDF GENERATION FAILED
====================
Error: {error_msg}

Please contact the system administrator or check the HTML report instead.

Generated by BreachPilot Professional Security Assessment Platform
        """
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(error_content)
