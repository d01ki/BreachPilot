"""
Enhanced Professional Report Generator - Enterprise-grade security assessment reports
"""

import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from backend.models import ReportData, ScanSession
from backend.config import config
# from backend.agents.enhanced_report_crew import EnhancedReportGeneratorCrew
from backend.report.html_generator import HTMLReportGenerator
from backend.report.pdf_generator import PDFReportGenerator
from backend.report.word_generator import WordReportGenerator
import logging

logger = logging.getLogger(__name__)

@dataclass
class RiskAssessment:
    """Comprehensive risk assessment data"""
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
    """Executive summary data"""
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
    """Detailed technical analysis"""
    attack_vectors: List[Dict[str, Any]]
    exploit_chains: List[Dict[str, Any]]
    lateral_movement_potential: Dict[str, Any]
    data_exposure_risks: List[Dict[str, Any]]
    privilege_escalation_paths: List[Dict[str, Any]]
    network_segmentation_analysis: Dict[str, Any]
    security_control_effectiveness: Dict[str, Any]

@dataclass
class ComplianceAnalysis:
    """Compliance and regulatory analysis"""
    applicable_frameworks: List[str]
    compliance_gaps: List[Dict[str, Any]]
    regulatory_requirements: List[str]
    audit_readiness: str
    remediation_roadmap: List[Dict[str, Any]]

class EnhancedProfessionalReportGenerator:
    """Enhanced professional report generator with enterprise-grade features"""
    
    def __init__(self):
        self.reports_dir = config.REPORTS_DIR
        self.reports_dir.mkdir(exist_ok=True)
        # self.enhanced_crew = EnhancedReportGeneratorCrew(str(config.DATA_DIR))
        self.html_generator = HTMLReportGenerator(self.reports_dir)
        self.pdf_generator = PDFReportGenerator(self.reports_dir)
        self.word_generator = WordReportGenerator(self.reports_dir)
    
    def generate_enterprise_report(self, target_ip: str, session: Optional[ScanSession] = None) -> Dict[str, Any]:
        """Generate comprehensive enterprise-grade security assessment report"""
        logger.info(f"Generating enterprise report for {target_ip}")
        
        # Load and analyze assessment data
        assessment_data = self._load_assessment_data(target_ip)
        
        # Calculate metrics and business impact
        metrics = self._calculate_security_metrics(assessment_data)
        business_impact = self._assess_business_impact(metrics, assessment_data)
        
        # Generate comprehensive analysis components
        risk_assessment = self._generate_risk_assessment(assessment_data)
        executive_summary = self._generate_executive_summary(assessment_data, risk_assessment)
        technical_analysis = self._generate_technical_analysis(assessment_data)
        compliance_analysis = self._generate_compliance_analysis(assessment_data)
        
        # Generate detailed recommendations
        recommendations = self._generate_detailed_recommendations(assessment_data, risk_assessment)
        
        # Generate timeline and roadmap
        remediation_roadmap = self._generate_remediation_roadmap(risk_assessment, recommendations)
        
        # Generate business case
        business_case = self._generate_business_case(risk_assessment, recommendations)
        
        # Generate comprehensive report data
        report_data = {
            "report_metadata": {
                "report_id": f"SEC-{target_ip.replace('.', '-')}-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
                "target_ip": target_ip,
                "generation_date": datetime.now().isoformat(),
                "report_version": "2.0.0",
                "classification": "CONFIDENTIAL",
                "distribution": "INTERNAL USE ONLY",
                "validity_period": (datetime.now() + timedelta(days=90)).isoformat()
            },
            "executive_summary": executive_summary.__dict__,
            "risk_assessment": risk_assessment.__dict__,
            "technical_analysis": technical_analysis.__dict__,
            "compliance_analysis": compliance_analysis.__dict__,
            "detailed_recommendations": recommendations,
            "remediation_roadmap": remediation_roadmap,
            "business_case": business_case,
            "assessment_data": assessment_data,
            "metrics": metrics,
            "business_impact": business_impact
        }
        
        # Generate multiple report formats
        html_path = self._generate_html_report(target_ip, report_data)
        pdf_path = self._generate_pdf_report(target_ip, report_data)
        word_path = self._generate_word_report(target_ip, report_data)
        
        # Update report data with file paths
        report_data["report_files"] = {
            "html_path": str(html_path),
            "pdf_path": str(pdf_path),
            "word_path": str(word_path),
            "json_path": str(self._save_json_report(target_ip, report_data))
        }
        
        logger.info(f"Enterprise report generated successfully for {target_ip}")
        return report_data
    
    def _load_assessment_data(self, target_ip: str) -> Dict[str, Any]:
        """Load and consolidate assessment data from all sources"""
        assessment_data = {
            "target_ip": target_ip,
            "nmap_results": {},
            "vulnerability_analysis": {},
            "exploit_results": [],
            "poc_results": [],
            "osint_results": {},
            "session_metadata": {}
        }
        
        # Load nmap results
        nmap_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        if nmap_file.exists():
            with open(nmap_file, 'r') as f:
                assessment_data["nmap_results"] = json.load(f)
        
        # Load vulnerability analysis
        analysis_file = config.DATA_DIR / f"{target_ip}_analysis.json"
        if analysis_file.exists():
            with open(analysis_file, 'r') as f:
                assessment_data["vulnerability_analysis"] = json.load(f)
        
        # Load exploit results
        exploits_file = config.DATA_DIR / f"{target_ip}_exploits.json"
        if exploits_file.exists():
            with open(exploits_file, 'r') as f:
                assessment_data["exploit_results"] = json.load(f)
        
        return assessment_data
    
    def _generate_risk_assessment(self, assessment_data: Dict[str, Any]) -> RiskAssessment:
        """Generate comprehensive risk assessment"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        # Count vulnerabilities by severity
        critical = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "critical")
        high = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "high")
        medium = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "medium")
        low = sum(1 for v in vulnerabilities if v.get("severity", "").lower() == "low")
        
        # Calculate risk score (0-10 scale)
        risk_score = (critical * 3.0 + high * 2.0 + medium * 1.0 + low * 0.5) / max(1, len(vulnerabilities)) * 2
        risk_score = min(10.0, risk_score)
        
        # Determine overall risk level
        if risk_score >= 8.0:
            risk_level = "CRITICAL"
            business_impact = "Severe business disruption, potential data breach, regulatory penalties"
            remediation_priority = "IMMEDIATE"
            remediation_time = "24-48 hours"
            financial_impact = "$500K - $2M+"
        elif risk_score >= 6.0:
            risk_level = "HIGH"
            business_impact = "Significant operational impact, potential compliance violations"
            remediation_priority = "URGENT"
            remediation_time = "1-2 weeks"
            financial_impact = "$100K - $500K"
        elif risk_score >= 4.0:
            risk_level = "MEDIUM"
            business_impact = "Moderate operational impact, increased security posture concerns"
            remediation_priority = "HIGH"
            remediation_time = "1-2 months"
            financial_impact = "$25K - $100K"
        else:
            risk_level = "LOW"
            business_impact = "Minimal operational impact, good security posture"
            remediation_priority = "MEDIUM"
            remediation_time = "3-6 months"
            financial_impact = "<$25K"
        
        return RiskAssessment(
            overall_risk_level=risk_level,
            risk_score=risk_score,
            critical_vulnerabilities=critical,
            high_vulnerabilities=high,
            medium_vulnerabilities=medium,
            low_vulnerabilities=low,
            exploitable_vulnerabilities=len([v for v in vulnerabilities if v.get("exploit_available", False)]),
            business_impact=business_impact,
            technical_impact=f"System compromise potential: {'High' if risk_score >= 7 else 'Medium' if risk_score >= 4 else 'Low'}",
            likelihood=f"{'High' if risk_score >= 7 else 'Medium' if risk_score >= 4 else 'Low'} probability of exploitation",
            remediation_priority=remediation_priority,
            estimated_remediation_time=remediation_time,
            financial_impact_estimate=financial_impact,
            compliance_implications=self._assess_compliance_implications(vulnerabilities),
            regulatory_risks=self._assess_regulatory_risks(vulnerabilities)
        )
    
    def _generate_executive_summary(self, assessment_data: Dict[str, Any], risk_assessment: RiskAssessment) -> ExecutiveSummary:
        """Generate comprehensive executive summary"""
        target_ip = assessment_data.get("target_ip", "Unknown")
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        services = assessment_data.get("nmap_results", {}).get("services", [])
        
        # Generate assessment overview
        assessment_overview = f"""
        A comprehensive security assessment was conducted on {target_ip} on {datetime.now().strftime('%B %d, %Y')}. 
        The assessment identified {len(services)} network services and {len(vulnerabilities)} security vulnerabilities.
        The overall risk level is {risk_assessment.overall_risk_level} with a risk score of {risk_assessment.risk_score:.1f}/10.
        """
        
        # Generate key findings
        key_findings = [
            f"Identified {risk_assessment.critical_vulnerabilities} critical vulnerabilities requiring immediate attention",
            f"Found {risk_assessment.high_vulnerabilities} high-severity issues that pose significant risk",
            f"Discovered {len(services)} network services with varying security postures",
            f"Assessment revealed {risk_assessment.exploitable_vulnerabilities} vulnerabilities with known exploits"
        ]
        
        # Generate critical risks
        critical_risks = []
        if risk_assessment.critical_vulnerabilities > 0:
            critical_risks.append(f"{risk_assessment.critical_vulnerabilities} critical vulnerabilities could lead to complete system compromise")
        if risk_assessment.exploitable_vulnerabilities > 0:
            critical_risks.append(f"{risk_assessment.exploitable_vulnerabilities} vulnerabilities have publicly available exploits")
        
        # Generate immediate actions
        immediate_actions = []
        if risk_assessment.critical_vulnerabilities > 0:
            immediate_actions.append("Patch critical vulnerabilities within 24-48 hours")
        if risk_assessment.high_vulnerabilities > 0:
            immediate_actions.append("Address high-severity vulnerabilities within 1-2 weeks")
        immediate_actions.extend([
            "Implement continuous vulnerability monitoring",
            "Establish incident response procedures",
            "Conduct security awareness training"
        ])
        
        # Generate strategic recommendations
        strategic_recommendations = [
            "Implement a comprehensive vulnerability management program",
            "Establish regular security assessments and penetration testing",
            "Deploy advanced threat detection and response capabilities",
            "Enhance network segmentation and access controls",
            "Develop and test incident response procedures"
        ]
        
        return ExecutiveSummary(
            assessment_overview=assessment_overview.strip(),
            key_findings=key_findings,
            critical_risks=critical_risks,
            business_impact=risk_assessment.business_impact,
            immediate_actions=immediate_actions,
            strategic_recommendations=strategic_recommendations,
            investment_requirements=f"Estimated investment: {risk_assessment.financial_impact_estimate} for comprehensive remediation",
            roi_analysis="ROI: 300-500% reduction in security risk and potential breach costs",
            compliance_status="Current compliance status requires immediate attention to meet regulatory requirements"
        )
    
    def _generate_technical_analysis(self, assessment_data: Dict[str, Any]) -> TechnicalAnalysis:
        """Generate detailed technical analysis"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        services = assessment_data.get("nmap_results", {}).get("services", [])
        
        # Analyze attack vectors
        attack_vectors = []
        for vuln in vulnerabilities[:10]:  # Top 10 vulnerabilities
            if vuln.get("exploit_available", False):
                attack_vectors.append({
                    "cve_id": vuln.get("cve_id", "N/A"),
                    "attack_type": "Remote Code Execution" if "rce" in vuln.get("description", "").lower() else "Privilege Escalation",
                    "target_service": vuln.get("affected_service", "Unknown"),
                    "complexity": "Low" if vuln.get("cvss_score", 0) >= 7 else "Medium",
                    "impact": vuln.get("severity", "Unknown").upper()
                })
        
        # Analyze exploit chains
        exploit_chains = []
        if len(attack_vectors) >= 2:
            exploit_chains.append({
                "chain_id": "CHAIN-001",
                "description": "Multi-stage attack chain leveraging multiple vulnerabilities",
                "vulnerabilities": [v["cve_id"] for v in attack_vectors[:3]],
                "total_impact": "Complete system compromise"
            })
        
        # Assess lateral movement potential
        lateral_movement = {
            "network_segments": len(set(s.get("name", "") for s in services)),
            "privileged_services": len([s for s in services if s.get("name", "").lower() in ["ssh", "rdp", "smb"]]),
            "risk_level": "High" if len(services) > 10 else "Medium"
        }
        
        # Analyze data exposure risks
        data_exposure_risks = []
        for service in services:
            if service.get("name", "").lower() in ["http", "https", "ftp", "smb"]:
                data_exposure_risks.append({
                    "service": service.get("name", "Unknown"),
                    "port": service.get("port", "Unknown"),
                    "risk": "Potential data exposure" if "http" in service.get("name", "").lower() else "File access risk"
                })
        
        return TechnicalAnalysis(
            attack_vectors=attack_vectors,
            exploit_chains=exploit_chains,
            lateral_movement_potential=lateral_movement,
            data_exposure_risks=data_exposure_risks,
            privilege_escalation_paths=attack_vectors[:5],
            network_segmentation_analysis=lateral_movement,
            security_control_effectiveness={"overall": "Insufficient", "recommendations": ["Implement WAF", "Deploy IPS", "Enable logging"]}
        )
    
    def _generate_compliance_analysis(self, assessment_data: Dict[str, Any]) -> ComplianceAnalysis:
        """Generate compliance and regulatory analysis"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        # Determine applicable frameworks
        applicable_frameworks = ["ISO 27001", "NIST Cybersecurity Framework", "PCI DSS", "SOC 2"]
        
        # Identify compliance gaps
        compliance_gaps = []
        if any(v.get("severity") == "critical" for v in vulnerabilities):
            compliance_gaps.append({
                "framework": "ISO 27001",
                "requirement": "A.12.6.1 Management of technical vulnerabilities",
                "gap": "Critical vulnerabilities not addressed",
                "impact": "Non-compliance with vulnerability management requirements"
            })
        
        # Regulatory requirements
        regulatory_requirements = [
            "Implement vulnerability management program",
            "Conduct regular security assessments",
            "Maintain incident response capabilities",
            "Ensure data protection measures"
        ]
        
        # Generate remediation roadmap
        remediation_roadmap = [
            {
                "phase": "Immediate (0-30 days)",
                "actions": ["Patch critical vulnerabilities", "Implement monitoring"],
                "compliance_impact": "Address immediate compliance gaps"
            },
            {
                "phase": "Short-term (1-6 months)",
                "actions": ["Deploy security controls", "Establish processes"],
                "compliance_impact": "Achieve baseline compliance"
            },
            {
                "phase": "Long-term (6-12 months)",
                "actions": ["Continuous improvement", "Regular assessments"],
                "compliance_impact": "Maintain ongoing compliance"
            }
        ]
        
        return ComplianceAnalysis(
            applicable_frameworks=applicable_frameworks,
            compliance_gaps=compliance_gaps,
            regulatory_requirements=regulatory_requirements,
            audit_readiness="Requires significant improvements",
            remediation_roadmap=remediation_roadmap
        )
    
    def _generate_detailed_recommendations(self, assessment_data: Dict[str, Any], risk_assessment: RiskAssessment) -> List[Dict[str, Any]]:
        """Generate detailed, actionable recommendations"""
        recommendations = []
        
        # Critical vulnerabilities
        if risk_assessment.critical_vulnerabilities > 0:
            recommendations.append({
                "priority": "CRITICAL",
                "category": "Vulnerability Management",
                "title": "Immediate Critical Vulnerability Remediation",
                "description": f"Address {risk_assessment.critical_vulnerabilities} critical vulnerabilities immediately",
                "business_justification": "Critical vulnerabilities pose immediate risk of system compromise",
                "technical_implementation": "Apply security patches, disable vulnerable services, implement compensating controls",
                "timeline": "24-48 hours",
                "resources_required": "Security team, system administrators",
                "estimated_cost": "$10K - $50K",
                "success_metrics": "Zero critical vulnerabilities, reduced risk score"
            })
        
        # High vulnerabilities
        if risk_assessment.high_vulnerabilities > 0:
            recommendations.append({
                "priority": "HIGH",
                "category": "Security Controls",
                "title": "High-Severity Vulnerability Management",
                "description": f"Systematically address {risk_assessment.high_vulnerabilities} high-severity vulnerabilities",
                "business_justification": "High-severity vulnerabilities significantly increase attack surface",
                "technical_implementation": "Implement patch management process, vulnerability scanning",
                "timeline": "1-2 weeks",
                "resources_required": "Security team, IT operations",
                "estimated_cost": "$25K - $100K",
                "success_metrics": "Reduced high-severity vulnerabilities by 90%"
            })
        
        # Continuous monitoring
        recommendations.append({
            "priority": "MEDIUM",
            "category": "Monitoring & Detection",
            "title": "Implement Continuous Security Monitoring",
            "description": "Deploy 24/7 security monitoring and threat detection",
            "business_justification": "Enable rapid detection and response to security incidents",
            "technical_implementation": "Deploy SIEM, endpoint detection, network monitoring",
            "timeline": "1-3 months",
            "resources_required": "Security operations team, tools",
            "estimated_cost": "$100K - $300K",
            "success_metrics": "Mean time to detection < 15 minutes"
        })
        
        return recommendations
    
    def _generate_remediation_roadmap(self, risk_assessment: RiskAssessment, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate comprehensive remediation roadmap"""
        return {
            "phases": [
                {
                    "phase": "Phase 1: Immediate Response (0-30 days)",
                    "focus": "Critical vulnerability remediation",
                    "activities": [
                        "Patch critical vulnerabilities",
                        "Implement emergency controls",
                        "Establish incident response procedures"
                    ],
                    "success_criteria": "Zero critical vulnerabilities",
                    "budget": "$50K - $100K"
                },
                {
                    "phase": "Phase 2: Security Hardening (1-6 months)",
                    "focus": "Comprehensive security improvement",
                    "activities": [
                        "Deploy security monitoring",
                        "Implement access controls",
                        "Conduct security training"
                    ],
                    "success_criteria": "Risk score < 5.0",
                    "budget": "$200K - $500K"
                },
                {
                    "phase": "Phase 3: Continuous Improvement (6-12 months)",
                    "focus": "Mature security program",
                    "activities": [
                        "Regular assessments",
                        "Continuous monitoring",
                        "Process optimization"
                    ],
                    "success_criteria": "Maintain risk score < 3.0",
                    "budget": "$100K - $200K annually"
                }
            ],
            "total_estimated_cost": "$350K - $800K",
            "expected_roi": "300-500% risk reduction",
            "timeline": "12 months"
        }
    
    def _generate_business_case(self, risk_assessment: RiskAssessment, recommendations: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Generate business case for security investments"""
        total_cost = sum(rec.get("estimated_cost", "$0").replace("$", "").replace("K", "000").replace("-", "").split()[0] for rec in recommendations)
        
        return {
            "investment_summary": {
                "total_estimated_cost": f"${total_cost}",
                "annual_operating_cost": "$100K - $200K",
                "expected_payback_period": "12-18 months"
            },
            "risk_reduction": {
                "current_risk_score": risk_assessment.risk_score,
                "target_risk_score": 3.0,
                "risk_reduction_percentage": f"{((risk_assessment.risk_score - 3.0) / risk_assessment.risk_score * 100):.1f}%"
            },
            "business_benefits": [
                "Reduced cyber insurance premiums",
                "Improved compliance posture",
                "Enhanced customer trust",
                "Reduced breach response costs",
                "Improved operational efficiency"
            ],
            "financial_impact": {
                "potential_breach_cost": "$3M - $10M",
                "investment_protection": f"{total_cost}",
                "net_benefit": f"${3000000 - int(total_cost)} - ${10000000 - int(total_cost)}"
            }
        }
    
    def _assess_compliance_implications(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Assess compliance implications of vulnerabilities"""
        implications = []
        
        critical_count = len([v for v in vulnerabilities if v.get("severity") == "critical"])
        if critical_count > 0:
            implications.append(f"{critical_count} critical vulnerabilities violate ISO 27001 A.12.6.1")
        
        if len(vulnerabilities) > 10:
            implications.append("High vulnerability count indicates inadequate vulnerability management")
        
        return implications
    
    def _assess_regulatory_risks(self, vulnerabilities: List[Dict[str, Any]]) -> List[str]:
        """Assess regulatory risks"""
        risks = []
        
        if any("personal" in str(v).lower() or "data" in str(v).lower() for v in vulnerabilities):
            risks.append("Potential GDPR/privacy regulation violations")
        
        if len(vulnerabilities) > 5:
            risks.append("May trigger regulatory scrutiny and audits")
        
        return risks
    
    def _generate_html_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Generate enhanced HTML report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_path = self.reports_dir / f"enterprise_security_report_{target_ip}_{timestamp}.html"
        
        # Use enhanced HTML generator
        self.html_generator.generate_enhanced_html_report(target_ip, report_data, html_path)
        
        return html_path
    
    def _generate_pdf_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Generate PDF report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        pdf_path = self.reports_dir / f"enterprise_security_report_{target_ip}_{timestamp}.pdf"
        
        # Use PDF generator
        self.pdf_generator.generate_pdf_report(target_ip, report_data, pdf_path)
        
        return pdf_path
    
    def _generate_word_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Generate Word report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        word_path = self.reports_dir / f"enterprise_security_report_{target_ip}_{timestamp}.docx"
        
        # Use Word generator
        self.word_generator.generate_word_report(target_ip, report_data, word_path)
        
        return word_path
    
    def _save_json_report(self, target_ip: str, report_data: Dict[str, Any]) -> Path:
        """Save comprehensive JSON report"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        json_path = self.reports_dir / f"enterprise_security_report_{target_ip}_{timestamp}.json"
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(report_data, f, indent=2, default=str)
        
        return json_path
    
    def _calculate_security_metrics(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate security metrics from assessment data"""
        vulnerabilities = assessment_data.get("vulnerability_analysis", {}).get("identified_cves", [])
        
        return {
            "total_services": len(assessment_data.get("nmap_results", {}).get("services", [])),
            "total_vulnerabilities": len(vulnerabilities),
            "critical_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "critical"]),
            "high_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "high"]),
            "medium_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "medium"]),
            "low_vulnerabilities": len([v for v in vulnerabilities if v.get("severity", "").lower() == "low"]),
            "exploitable_vulnerabilities": len([v for v in vulnerabilities if v.get("exploit_available", False)]),
            "successful_exploits": len(assessment_data.get("exploit_results", [])),
            "risk_score": 5.0  # Default risk score
        }
    
    def _assess_business_impact(self, metrics: Dict[str, Any], assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Assess business impact from metrics"""
        return {
            "overall_risk_level": "MEDIUM",
            "financial_impact_estimate": "$25K - $100K",
            "operational_impact": "Moderate operational impact",
            "remediation_priority": "HIGH",
            "estimated_remediation_time": "1-2 months"
        }
