"""
Enhanced Professional Report Generator - Fixed imports
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from backend.models import ReportData, ScanSession
from backend.config import config
from backend.report.html_generator import HTMLReportGenerator

# Try to import PDF generator - gracefully handle if not available
try:
    from backend.report.pdf_generator import generate_pentest_report
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

try:
    from backend.report.word_generator import WordReportGenerator
    WORD_AVAILABLE = True
except ImportError:
    WORD_AVAILABLE = False

import logging

logger = logging.getLogger(__name__)

@dataclass
class RiskAssessment:
    overall_risk_level: str
    risk_score: float
    critical_vulnerabilities: int
    high_vulnerabilities: int
    medium_vulnerabilities: int
    low_vulnerabilities: int
    exploitable_vulnerabilities: int
    business_impact: str
    technical_impact: str
    likelihood: str
    remediation_priority: str
    estimated_remediation_time: str
    financial_impact_estimate: str
    compliance_implications: List[str]
    regulatory_risks: List[str]

@dataclass
class ExecutiveSummary:
    assessment_overview: str
    key_findings: List[str]
    critical_risks: List[str]
    business_impact: str
    immediate_actions: List[str]
    strategic_recommendations: List[str]
    investment_requirements: str
    roi_analysis: str
    compliance_status: str

@dataclass
class TechnicalAnalysis:
    attack_vectors: List[Dict[str, Any]]
    exploit_chains: List[Dict[str, Any]]
    lateral_movement_potential: Dict[str, Any]
    data_exposure_risks: List[Dict[str, Any]]
    privilege_escalation_paths: List[Dict[str, Any]]
    network_segmentation_analysis: Dict[str, Any]
    security_control_effectiveness: Dict[str, Any]

@dataclass
class ComplianceAnalysis:
    applicable_frameworks: List[str]
    compliance_gaps: List[Dict[str, Any]]
    regulatory_requirements: List[str]
    audit_readiness: str
    remediation_roadmap: List[Dict[str, Any]]

class EnhancedProfessionalReportGenerator:
    """Enhanced professional report generator - simplified and working"""
    
    def __init__(self):
        self.reports_dir = config.REPORTS_DIR
        self.reports_dir.mkdir(exist_ok=True)
        self.html_generator = HTMLReportGenerator(self.reports_dir)
        self.pdf_available = PDF_AVAILABLE
        self.word_available = WORD_AVAILABLE
        
        if self.word_available:
            self.word_generator = WordReportGenerator(self.reports_dir)
        
        if not self.pdf_available:
            logger.warning("PDF generation not available - install reportlab: pip install reportlab")
    
    def generate_enterprise_report(self, target_ip: str, session: Optional[ScanSession] = None) -> Dict[str, Any]:
        """Generate enterprise report - simplified version"""
        logger.info(f"Generating enterprise report for {target_ip}")
        
        try:
            assessment_data = self._load_assessment_data(target_ip)
            metrics = self._calculate_security_metrics(assessment_data)
            risk_assessment = self._generate_risk_assessment(assessment_data)
            executive_summary = self._generate_executive_summary(assessment_data, risk_assessment)
            
            report_data = {
                "report_metadata": {
                    "report_id": f"SEC-{target_ip.replace('.', '-')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                    "target_ip": target_ip,
                    "generation_date": datetime.now().isoformat(),
                    "report_version": "2.0.0",
                },
                "executive_summary": executive_summary.__dict__,
                "risk_assessment": risk_assessment.__dict__,
                "assessment_data": assessment_data,
                "metrics": metrics,
            }
            
            report_files = {}
            
            # Generate HTML
            try:
                html_path = self._generate_html_report(target_ip, report_data)
                report_files["html_path"] = str(html_path)
            except Exception as e:
                logger.error(f"HTML generation failed: {e}")
                report_files["html_path"] = None
            
            # Save JSON
            try:
                json_path = self._save_json_report(target_ip, report_data)
                report_files["json_path"] = str(json_path)
            except Exception as e:
                logger.error(f"JSON save failed: {e}")
                report_files["json_path"] = None
            
            # Generate PDF if available
            if self.pdf_available:
                try:
                    pdf_path = self._generate_pdf_report(target_ip, assessment_data)
                    report_files["pdf_path"] = str(pdf_path)
                except Exception as e:
                    logger.warning(f"PDF generation failed: {e}")
                    report_files["pdf_path"] = None
            else:
                report_files["pdf_path"] = None
            
            report_data["report_files"] = report_files
            
            logger.info(f"Enterprise report generated successfully for {target_ip}")
            return report_data
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}", exc_info=True)
            return {
                "error": str(e),
                "report_files": {"html_path": None, "pdf_path": None, "json_path": None}
            }
    
    def _load_assessment_data(self, target_ip: str) -> Dict[str, Any]:
        """Load assessment data"""
        assessment_data = {
            "target_ip": target_ip,
            "nmap_results": {"services": []},
            "vulnerability_analysis": {"identified_cves": []},
            "exploit_results": [],
        }
        
        try:
            nmap_file = config.DATA_DIR / f"{target_ip}_nmap.json"
            if nmap_file.exists():
                with open(nmap_file, 'r') as f:
                    assessment_data["nmap_results"] = json.load(f)
            
            analysis_file = config.DATA_DIR / f"{target_ip}_analysis.json"
            if analysis_file.exists():
                with open(analysis_file, 'r') as f:
                    assessment_data["vulnerability_analysis"] = json.load(f)
        except Exception as e:
            logger.warning(f"Error loading assessment data: {e}")
        
        return assessment_data
    
    def _generate_risk_assessment(self, assessment_data: Dict[str, Any]) -> RiskAssessment:
        """Generate risk assessment"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        critical = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")
        medium = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")
        low = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
        
        if len(vulnerabilities) > 0:
            risk_score = (critical * 3.0 + high * 2.0 + medium * 1.0 + low * 0.5) / len(vulnerabilities) * 2
            risk_score = min(10.0, risk_score)
        else:
            risk_score = 0.0
        
        if risk_score >= 8.0 or critical > 0:
            risk_level, priority, time, cost = "CRITICAL", "IMMEDIATE", "24-48 hours", "$500K+"
        elif risk_score >= 6.0 or high > 0:
            risk_level, priority, time, cost = "HIGH", "URGENT", "1-2 weeks", "$100K-$500K"
        elif risk_score >= 4.0 or medium > 0:
            risk_level, priority, time, cost = "MEDIUM", "HIGH", "1-2 months", "$25K-$100K"
        else:
            risk_level, priority, time, cost = "LOW", "MEDIUM", "3-6 months", "<$25K"
        
        return RiskAssessment(
            overall_risk_level=risk_level,
            risk_score=risk_score,
            critical_vulnerabilities=critical,
            high_vulnerabilities=high,
            medium_vulnerabilities=medium,
            low_vulnerabilities=low,
            exploitable_vulnerabilities=len([v for v in vulnerabilities if v.get("exploit_available", False)]),
            business_impact=f"{risk_level} risk level identified",
            technical_impact=f"System compromise potential: {risk_level}",
            likelihood=f"{risk_level} probability",
            remediation_priority=priority,
            estimated_remediation_time=time,
            financial_impact_estimate=cost,
            compliance_implications=[],
            regulatory_risks=[]
        )
    
    def _generate_executive_summary(self, assessment_data: Dict[str, Any], risk_assessment: RiskAssessment) -> ExecutiveSummary:
        """Generate executive summary"""
        target_ip = assessment_data.get("target_ip", "Unknown")
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        return ExecutiveSummary(
            assessment_overview=f"Security assessment conducted on {target_ip}",
            key_findings=[f"Found {len(vulnerabilities)} vulnerabilities"],
            critical_risks=[f"{risk_assessment.critical_vulnerabilities} critical issues"],
            business_impact=risk_assessment.business_impact,
            immediate_actions=["Patch critical vulnerabilities"],
            strategic_recommendations=["Implement security monitoring"],
            investment_requirements=risk_assessment.financial_impact_estimate,
            roi_analysis="300-500% risk reduction",
            compliance_status="Review required"
        )
    
    def _calculate_security_metrics(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate metrics"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        services = assessment_data.get("nmap_results", {}).get("services", [])
        
        return {
            "total_services": len(services),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]),
            "high_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"]),
        }
    
    def _generate_html_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Generate HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path = self.reports_dir / f"report_{target_ip}_{timestamp}.html"
        
        self.html_generator.generate_enhanced_html_report(target_ip, report_data, html_path)
        return html_path
    
    def _generate_pdf_report(self, target_ip: str, assessment_data: Dict[str, Any]) -> Path:
        """Generate PDF report"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        scan_data = {
            'target': target_ip,
            'vulnerabilities': vulnerabilities,
            'scan_duration': 'N/A',
            'report_id': f"SEC-{target_ip}-{datetime.now().strftime('%Y%m%d')}"
        }
        
        pdf_path = generate_pentest_report(scan_data, str(self.reports_dir))
        return Path(pdf_path)
    
    def _save_json_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Save JSON report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = self.reports_dir / f"report_{target_ip}_{timestamp}.json"
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return json_path
