"""
HTML Report Generator - Professional HTML/PDF report generation
"""

from pathlib import Path
from datetime import datetime
from typing import Dict, Any
from jinja2 import Template
import logging

logger = logging.getLogger(__name__)

class HTMLReportGenerator:
    """Generate professional HTML and PDF reports"""
    
    def __init__(self, reports_dir: Path):
        self.reports_dir = reports_dir
        self.templates_dir = Path(__file__).parent / "templates"
        self.templates_dir.mkdir(exist_ok=True)
        self._create_html_template()
    
    def generate_html_report(self, target_ip: str, crew_report: Dict[str, Any], 
                           assessment_data: Dict[str, Any], metrics, business_impact) -> Path:
        """Generate professional HTML report"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path = self.reports_dir / f"enterprise_assessment_{target_ip}_{timestamp}.html"
        
        # Load template
        template_path = self.templates_dir / "professional_report.html"
        with open(template_path, 'r', encoding='utf-8') as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # Prepare data for template
        vulnerabilities = self._extract_vulnerabilities(assessment_data)
        services = self._extract_services(assessment_data)
        exploit_results = self._extract_exploit_results(assessment_data)
        
        # Format executive summary for HTML
        executive_summary_html = crew_report.get('executive_summary', '').replace('\n', '<br>')
        
        # Render template
        html_content = template.render(
            report_title=f"Security Assessment - {target_ip}",
            target_ip=target_ip,
            assessment_date=datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            classification="Confidential",
            generation_time=datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC'),
            executive_summary=executive_summary_html,
            metrics=metrics,
            business_impact=business_impact,
            vulnerabilities=vulnerabilities,
            services=services,
            exploit_results=exploit_results
        )
        
        # Save HTML report
        with open(html_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        logger.info(f"Professional HTML report generated: {html_path}")
        return html_path
    
    def generate_pdf_report(self, target_ip: str, html_path: Path) -> Path:
        """Generate PDF report from HTML"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_path = self.reports_dir / f"enterprise_assessment_{target_ip}_{timestamp}.pdf"
        
        try:
            # Try to use weasyprint if available
            from weasyprint import HTML
            HTML(filename=str(html_path)).write_pdf(str(pdf_path))
            logger.info(f"PDF report generated using WeasyPrint: {pdf_path}")
            
        except ImportError:
            # Fallback: Create a text-based PDF placeholder
            logger.warning("WeasyPrint not available, creating text-based PDF")
            self._create_text_pdf_fallback(html_path, pdf_path, target_ip)
            
        except Exception as e:
            logger.error(f"Failed to generate PDF: {e}")
            self._create_error_pdf(pdf_path, target_ip, str(e))
        
        return pdf_path
    
    def _extract_vulnerabilities(self, assessment_data: Dict[str, Any]) -> list:
        """Extract vulnerability data for template"""
        vulnerabilities = []
        vulnerability_data = assessment_data.get('vulnerability_analysis', {})
        
        if isinstance(vulnerability_data, dict):
            vuln_list = vulnerability_data.get('identified_cves', 
                       vulnerability_data.get('vulnerabilities', 
                       vulnerability_data.get('cves', [])))
            
            for vuln in vuln_list[:20]:  # Limit to top 20
                if isinstance(vuln, dict):
                    vulnerabilities.append({
                        'cve_id': vuln.get('cve_id', vuln.get('id', 'N/A')),
                        'severity': vuln.get('severity', '').lower(),
                        'cvss_score': vuln.get('cvss_score', ''),
                        'affected_service': vuln.get('affected_service', vuln.get('service', '')),
                        'exploit_available': vuln.get('exploit_available', False),
                        'description': vuln.get('description', '')
                    })
        
        return vulnerabilities
    
    def _extract_services(self, assessment_data: Dict[str, Any]) -> list:
        """Extract services data for template"""
        services = []
        nmap_data = assessment_data.get('nmap_results', {})
        
        if isinstance(nmap_data, dict):
            services_list = nmap_data.get('open_ports', 
                          nmap_data.get('services', 
                          nmap_data.get('ports', [])))
            
            for service in services_list:
                if isinstance(service, dict):
                    services.append({
                        'port': service.get('port', ''),
                        'protocol': service.get('protocol', 'TCP'),
                        'name': service.get('name', service.get('service', '')),
                        'version': service.get('version', service.get('product', '')),
                        'state': service.get('state', 'open')
                    })
        
        return services
    
    def _extract_exploit_results(self, assessment_data: Dict[str, Any]) -> list:
        """Extract exploit results for template"""
        exploit_results = []
        exploit_data = assessment_data.get('exploit_results', {})
        
        if isinstance(exploit_data, dict):
            exploit_list = exploit_data.get('results', 
                          exploit_data.get('exploits', 
                          [exploit_data] if exploit_data else []))
            
            for exploit in exploit_list:
                if isinstance(exploit, dict):
                    exploit_results.append({
                        'cve_id': exploit.get('cve_id', ''),
                        'success': exploit.get('success', False),
                        'exploit_command': exploit.get('exploit_command', exploit.get('command', '')),
                        'evidence': exploit.get('evidence', exploit.get('output', ''))
                    })
        
        return exploit_results
    
    def _create_text_pdf_fallback(self, html_path: Path, pdf_path: Path, target_ip: str):
        """Create text-based PDF fallback"""
        with open(html_path, 'r', encoding='utf-8') as f:
            html_content = f.read()
        
        # Strip HTML tags for basic text version
        import re
        text_content = re.sub(r'<[^>]+>', '', html_content)
        text_content = re.sub(r'\s+', ' ', text_content).strip()
        
        # Save as text file with .pdf extension (temporary solution)
        with open(pdf_path, 'w', encoding='utf-8') as f:
            f.write(f"SECURITY ASSESSMENT REPORT - {target_ip}\n")
            f.write("=" * 50 + "\n\n")
            f.write("NOTE: This is a text-based report. Install WeasyPrint for full PDF formatting.\n\n")
            f.write(text_content)
    
    def _create_error_pdf(self, pdf_path: Path, target_ip: str, error_msg: str):
        """Create error PDF file"""
        with open(pdf_path, 'w', encoding='utf-8') as f:
            f.write(f"PDF generation failed for {target_ip}\n")
            f.write(f"Error: {error_msg}\n")
            f.write("Please check the HTML report instead.")
    
    def _create_html_template(self):
        """Create professional HTML template"""
        html_template = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ report_title }}</title>
    <style>
        body { font-family: Arial, sans-serif; line-height: 1.6; color: #333; background: #f8f9fa; margin: 0; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; background: white; box-shadow: 0 0 20px rgba(0,0,0,0.1); }
        .header { background: linear-gradient(135deg, #2c3e50, #34495e); color: white; padding: 40px; text-align: center; margin-bottom: 30px; }
        .header h1 { font-size: 2.5em; margin-bottom: 10px; font-weight: 300; }
        .header .subtitle { font-size: 1.2em; opacity: 0.9; }
        .header .meta { margin-top: 20px; font-size: 0.95em; opacity: 0.8; }
        .executive-summary { background: #e8f4fd; padding: 30px; margin: 30px 0; border-left: 5px solid #3498db; border-radius: 5px; }
        .executive-summary h2 { color: #2c3e50; margin-bottom: 20px; font-size: 1.8em; }
        .metrics-dashboard { display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 20px; margin: 30px 0; }
        .metric-card { background: white; padding: 25px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); text-align: center; border-top: 4px solid #3498db; }
        .metric-card.critical { border-top-color: #e74c3c; }
        .metric-card.high { border-top-color: #f39c12; }
        .metric-card.medium { border-top-color: #f1c40f; }
        .metric-card.success { border-top-color: #27ae60; }
        .metric-value { font-size: 2.5em; font-weight: bold; margin-bottom: 10px; }
        .metric-card.critical .metric-value { color: #e74c3c; }
        .metric-card.high .metric-value { color: #f39c12; }
        .metric-card.medium .metric-value { color: #f1c40f; }
        .metric-card.success .metric-value { color: #27ae60; }
        .metric-label { font-size: 0.9em; color: #7f8c8d; text-transform: uppercase; letter-spacing: 1px; }
        .section { margin: 40px 0; }
        .section h2 { color: #2c3e50; border-bottom: 3px solid #3498db; padding-bottom: 10px; margin-bottom: 25px; font-size: 1.8em; }
        .section h3 { color: #34495e; margin: 25px 0 15px 0; font-size: 1.4em; }
        .vulnerability-table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; box-shadow: 0 2px 5px rgba(0,0,0,0.1); }
        .vulnerability-table th { background: #34495e; color: white; padding: 15px; text-align: left; font-weight: 600; }
        .vulnerability-table td { padding: 12px 15px; border-bottom: 1px solid #ecf0f1; }
        .vulnerability-table tr:nth-child(even) { background: #f8f9fa; }
        .vulnerability-table tr:hover { background: #e8f4fd; }
        .severity-badge { display: inline-block; padding: 4px 12px; border-radius: 20px; font-size: 0.8em; font-weight: bold; text-transform: uppercase; color: white; }
        .severity-critical { background: #e74c3c; }
        .severity-high { background: #f39c12; }
        .severity-medium { background: #f1c40f; color: #333; }
        .severity-low { background: #27ae60; }
        .recommendations { background: #fff3cd; border: 1px solid #ffeaa7; padding: 25px; border-radius: 5px; margin: 20px 0; }
        .recommendations h3 { color: #856404; margin-bottom: 15px; }
        .recommendations ul { margin-left: 20px; }
        .recommendations li { margin-bottom: 10px; color: #856404; }
        .timeline { background: #f8f9fa; padding: 20px; border-radius: 5px; margin: 20px 0; }
        .timeline-item { display: flex; align-items: center; margin: 15px 0; padding: 10px; background: white; border-radius: 5px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        .timeline-priority { width: 20px; height: 20px; border-radius: 50%; margin-right: 15px; }
        .timeline-priority.immediate { background: #e74c3c; }
        .timeline-priority.short-term { background: #f39c12; }
        .timeline-priority.long-term { background: #3498db; }
        .footer { margin-top: 50px; padding: 30px; background: #2c3e50; color: white; text-align: center; }
        .footer p { margin: 5px 0; opacity: 0.8; }
        .page-break { page-break-before: always; }
        @media print {
            body { background: white; }
            .container { box-shadow: none; max-width: none; margin: 0; padding: 0; }
            .page-break { page-break-before: always; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>{{ report_title }}</h1>
            <div class="subtitle">Professional Security Assessment Report</div>
            <div class="meta">
                <strong>Target:</strong> {{ target_ip }} | <strong>Date:</strong> {{ assessment_date }} | <strong>Classification:</strong> {{ classification }}
            </div>
        </div>

        <div class="executive-summary">
            <h2>Executive Summary</h2>
            <div>{{ executive_summary | safe }}</div>
        </div>

        <div class="section">
            <h2>Security Metrics Dashboard</h2>
            <div class="metrics-dashboard">
                <div class="metric-card">
                    <div class="metric-value">{{ metrics.total_services }}</div>
                    <div class="metric-label">Network Services</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ metrics.total_vulnerabilities }}</div>
                    <div class="metric-label">Total Vulnerabilities</div>
                </div>
                <div class="metric-card critical">
                    <div class="metric-value">{{ metrics.critical_vulnerabilities }}</div>
                    <div class="metric-label">Critical Issues</div>
                </div>
                <div class="metric-card high">
                    <div class="metric-value">{{ metrics.high_vulnerabilities }}</div>
                    <div class="metric-label">High Severity</div>
                </div>
                <div class="metric-card success">
                    <div class="metric-value">{{ metrics.successful_exploits }}</div>
                    <div class="metric-label">Successful Exploits</div>
                </div>
                <div class="metric-card">
                    <div class="metric-value">{{ "%.1f"|format(metrics.risk_score) }}/10</div>
                    <div class="metric-label">Risk Score</div>
                </div>
            </div>
        </div>

        <div class="section page-break">
            <h2>Business Impact Analysis</h2>
            <div class="recommendations">
                <h3>Financial Impact Assessment</h3>
                <p><strong>Risk Level:</strong> {{ business_impact.overall_risk_level }}</p>
                <p><strong>Financial Risk:</strong> {{ business_impact.financial_impact_estimate }}</p>
                <p><strong>Remediation Priority:</strong> {{ business_impact.remediation_priority }}</p>
                <p><strong>Timeline:</strong> {{ business_impact.estimated_remediation_time }}</p>
            </div>
        </div>

        {% if vulnerabilities %}
        <div class="section">
            <h2>Vulnerability Analysis</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr><th>CVE ID</th><th>Severity</th><th>CVSS</th><th>Service</th><th>Exploit</th></tr>
                </thead>
                <tbody>
                    {% for vuln in vulnerabilities %}
                    <tr>
                        <td><strong>{{ vuln.cve_id }}</strong></td>
                        <td><span class="severity-badge severity-{{ vuln.severity }}">{{ vuln.severity|upper }}</span></td>
                        <td>{{ vuln.cvss_score or 'N/A' }}</td>
                        <td>{{ vuln.affected_service or 'N/A' }}</td>
                        <td>{{ 'Yes' if vuln.exploit_available else 'No' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        {% if services %}
        <div class="section">
            <h2>Network Services</h2>
            <table class="vulnerability-table">
                <thead>
                    <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th></tr>
                </thead>
                <tbody>
                    {% for service in services %}
                    <tr>
                        <td><strong>{{ service.port }}</strong></td>
                        <td>{{ service.protocol }}</td>
                        <td>{{ service.name or 'Unknown' }}</td>
                        <td>{{ service.version or 'N/A' }}</td>
                    </tr>
                    {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}

        <div class="section page-break">
            <h2>Recommendations & Timeline</h2>
            <div class="timeline">
                <div class="timeline-item">
                    <div class="timeline-priority immediate"></div>
                    <div><strong>Immediate (0-24h):</strong> Address {{ metrics.critical_vulnerabilities }} critical vulnerabilities</div>
                </div>
                <div class="timeline-item">
                    <div class="timeline-priority short-term"></div>
                    <div><strong>Short-term (1-4w):</strong> Patch {{ metrics.high_vulnerabilities }} high-severity issues</div>
                </div>
                <div class="timeline-item">
                    <div class="timeline-priority long-term"></div>
                    <div><strong>Long-term (1-6m):</strong> Implement continuous security monitoring</div>
                </div>
            </div>
        </div>

        <div class="footer">
            <p><strong>Generated by BreachPilot Professional Security Assessment Platform</strong></p>
            <p>Classification: {{ classification }} | Generated: {{ generation_time }}</p>
        </div>
    </div>
</body>
</html>"""
        
        template_path = self.templates_dir / "professional_report.html"
        with open(template_path, 'w', encoding='utf-8') as f:
            f.write(html_template.strip())
        
        logger.info(f"HTML template created at {template_path}")
