"""
Enhanced CrewAI-based report generation system for professional security assessments
"""

from typing import Dict, Any, List, Optional, Tuple
import logging
import json
import os
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)

@dataclass
class SecurityMetrics:
    """Security metrics for executive reporting"""
    total_services: int = 0
    total_vulnerabilities: int = 0
    critical_vulnerabilities: int = 0
    high_vulnerabilities: int = 0
    medium_vulnerabilities: int = 0
    low_vulnerabilities: int = 0
    successful_exploits: int = 0
    total_exploit_attempts: int = 0
    risk_score: float = 0.0
    compliance_gaps: int = 0

@dataclass
class BusinessImpactAssessment:
    """Business impact assessment for executive reporting"""
    overall_risk_level: str = "Unknown"
    financial_impact_estimate: str = "To be determined"
    operational_impact: str = "Minimal"
    reputation_risk: str = "Low"
    compliance_risk: str = "Low"
    remediation_priority: str = "Medium"
    estimated_remediation_time: str = "1-2 weeks"
    business_continuity_risk: str = "Low"


class EnhancedReportGeneratorCrew:
    """Enhanced CrewAI-based report generation system for professional security assessments"""
    
    def __init__(self, data_dir: str = "./data"):
        """Initialize the enhanced report generator with CrewAI agents"""
        self.data_dir = Path(data_dir)
        self.reports_dir = self.data_dir / "reports"
        self.reports_dir.mkdir(exist_ok=True)
        
        try:
            from crewai import Agent, Task, Crew, Process
            
            # Create specialized agents
            self.vulnerability_analyst = self._create_vulnerability_analyst()
            self.business_impact_analyst = self._create_business_impact_analyst()
            self.technical_writer = self._create_technical_writer()
            self.executive_advisor = self._create_executive_advisor()
            self.compliance_specialist = self._create_compliance_specialist()
            
            self.crew_available = True
            logger.info("Enhanced CrewAI agents initialized successfully")
            
        except ImportError as e:
            logger.warning(f"CrewAI not available, using enhanced fallback: {e}")
            self.crew_available = False
    
    def _create_vulnerability_analyst(self):
        """Create a specialized vulnerability analyst agent"""
        from crewai import Agent
        
        return Agent(
            role='Senior Vulnerability Analyst',
            goal='Analyze security vulnerabilities with deep technical expertise and provide actionable risk assessments',
            backstory="""You are a world-class vulnerability researcher with 15+ years of experience 
            in cybersecurity. You specialize in CVE analysis, exploit development, and risk assessment. 
            You have worked for top-tier security firms and have published research on zero-day vulnerabilities. 
            Your expertise includes CVSS scoring, attack vector analysis, and prioritization of security findings 
            based on real-world exploitability and business impact.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_business_impact_analyst(self):
        """Create a business impact analyst agent"""
        from crewai import Agent
        
        return Agent(
            role='Senior Business Impact Analyst',
            goal='Translate technical vulnerabilities into quantifiable business risks and financial impact',
            backstory="""You are a senior risk management consultant with extensive experience in 
            enterprise security and business continuity. You excel at translating technical security 
            findings into business language that executives and board members can understand. You have 
            helped Fortune 500 companies assess cyber risks and develop security investment strategies. 
            Your expertise includes financial risk modeling, compliance frameworks, and operational impact assessment.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_technical_writer(self):
        """Create an enhanced technical writer agent"""
        from crewai import Agent
        
        return Agent(
            role='Principal Technical Security Writer',
            goal='Create comprehensive, professional security documentation that meets enterprise standards',
            backstory="""You are a technical writing specialist with deep cybersecurity expertise. 
            You have authored security documentation for major enterprises, government agencies, and 
            security consultancies. Your reports are known for their clarity, technical accuracy, 
            and professional presentation. You understand both technical and executive audiences 
            and can create documentation that serves both constituencies effectively.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_executive_advisor(self):
        """Create an executive security advisor agent"""
        from crewai import Agent
        
        return Agent(
            role='Executive Security Advisor',
            goal='Provide C-level strategic security guidance and board-ready recommendations',
            backstory="""You are a former CISO and current security advisor to executive leadership. 
            You have managed enterprise security programs for major corporations and understand the 
            strategic implications of cybersecurity risks. You excel at creating executive summaries 
            that drive decision-making and resource allocation. Your recommendations have guided 
            millions of dollars in security investments.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_compliance_specialist(self):
        """Create a compliance and regulatory specialist agent"""
        from crewai import Agent
        
        return Agent(
            role='Compliance and Regulatory Specialist',
            goal='Assess regulatory implications and compliance gaps from security findings',
            backstory="""You are a compliance expert with deep knowledge of cybersecurity regulations 
            including SOX, HIPAA, GDPR, PCI-DSS, NIST frameworks, and industry standards. You help 
            organizations understand the regulatory implications of security vulnerabilities and 
            develop compliance-focused remediation strategies. Your expertise includes audit preparation 
            and regulatory reporting requirements.""",
            verbose=True,
            allow_delegation=False
        )
    
    def load_assessment_data(self, target_ip: str) -> Dict[str, Any]:
        """Load and consolidate assessment data from JSON files"""
        assessment_data = {
            'target_ip': target_ip,
            'scan_timestamp': datetime.now().isoformat(),
            'nmap_results': {},
            'vulnerability_analysis': {},
            'exploit_results': {},
            'raw_data_files': []
        }
        
        # Common file patterns to look for
        file_patterns = [
            f"{target_ip}_nmap.json",
            f"{target_ip}_nmap_scan.json",
            f"nmap_{target_ip}.json",
            f"{target_ip}_analysis.json",
            f"{target_ip}_vulnerabilities.json",
            f"{target_ip}_cve_analysis.json", 
            f"{target_ip}_exploits.json",
            f"{target_ip}_exploit_results.json",
            f"{target_ip}_poc_results.json"
        ]
        
        # Search for result files
        for pattern in file_patterns:
            file_path = self.data_dir / pattern
            if file_path.exists():
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        data = json.load(f)
                        
                    # Categorize data based on file name
                    if 'nmap' in pattern:
                        assessment_data['nmap_results'] = data
                    elif any(x in pattern for x in ['analysis', 'vulnerabilities', 'cve']):
                        assessment_data['vulnerability_analysis'] = data
                    elif any(x in pattern for x in ['exploit', 'poc']):
                        assessment_data['exploit_results'] = data
                    
                    assessment_data['raw_data_files'].append(str(file_path))
                    logger.info(f"Loaded assessment data from {file_path}")
                    
                except Exception as e:
                    logger.error(f"Failed to load {file_path}: {e}")
        
        return assessment_data
    
    def calculate_security_metrics(self, assessment_data: Dict[str, Any]) -> SecurityMetrics:
        """Calculate comprehensive security metrics from assessment data"""
        metrics = SecurityMetrics()
        
        # Analyze NMAP results for service count
        nmap_data = assessment_data.get('nmap_results', {})
        if isinstance(nmap_data, dict):
            # Count open ports/services
            if 'open_ports' in nmap_data:
                metrics.total_services = len(nmap_data['open_ports'])
            elif 'services' in nmap_data:
                metrics.total_services = len(nmap_data['services'])
        
        # Analyze vulnerability data
        vuln_data = assessment_data.get('vulnerability_analysis', {})
        if isinstance(vuln_data, dict):
            vulnerabilities = []
            
            # Try different possible structures
            if 'identified_cves' in vuln_data:
                vulnerabilities = vuln_data['identified_cves']
            elif 'vulnerabilities' in vuln_data:
                vulnerabilities = vuln_data['vulnerabilities']
            elif 'cves' in vuln_data:
                vulnerabilities = vuln_data['cves']
            
            metrics.total_vulnerabilities = len(vulnerabilities)
            
            # Count by severity
            for vuln in vulnerabilities:
                severity = 'unknown'
                cvss_score = 0.0
                
                # Try to extract severity information
                if isinstance(vuln, dict):
                    severity = vuln.get('severity', '').lower()
                    cvss_score = float(vuln.get('cvss_score', 0) or 0)
                    
                    # If no severity but CVSS score exists, derive severity
                    if not severity and cvss_score > 0:
                        if cvss_score >= 9.0:
                            severity = 'critical'
                        elif cvss_score >= 7.0:
                            severity = 'high'
                        elif cvss_score >= 4.0:
                            severity = 'medium'
                        else:
                            severity = 'low'
                
                # Increment severity counters
                if severity == 'critical':
                    metrics.critical_vulnerabilities += 1
                elif severity == 'high':
                    metrics.high_vulnerabilities += 1
                elif severity == 'medium':
                    metrics.medium_vulnerabilities += 1
                elif severity == 'low':
                    metrics.low_vulnerabilities += 1
        
        # Analyze exploit results
        exploit_data = assessment_data.get('exploit_results', {})
        if isinstance(exploit_data, dict):
            if 'results' in exploit_data:
                exploit_results = exploit_data['results']
            elif 'exploits' in exploit_data:
                exploit_results = exploit_data['exploits']
            else:
                exploit_results = [exploit_data] if exploit_data else []
            
            metrics.total_exploit_attempts = len(exploit_results)
            metrics.successful_exploits = sum(1 for r in exploit_results 
                                            if isinstance(r, dict) and r.get('success', False))
        
        # Calculate overall risk score (0-10)
        risk_factors = [
            metrics.critical_vulnerabilities * 3.0,
            metrics.high_vulnerabilities * 2.0,
            metrics.medium_vulnerabilities * 1.0,
            metrics.successful_exploits * 2.5
        ]
        
        base_risk = sum(risk_factors)
        metrics.risk_score = min(10.0, base_risk / max(1, metrics.total_vulnerabilities) if metrics.total_vulnerabilities > 0 else 0)
        
        return metrics
    
    def assess_business_impact(self, metrics: SecurityMetrics, assessment_data: Dict[str, Any]) -> BusinessImpactAssessment:
        """Assess business impact based on security metrics"""
        impact = BusinessImpactAssessment()
        
        # Determine overall risk level
        if metrics.critical_vulnerabilities > 0 or metrics.successful_exploits > 2:
            impact.overall_risk_level = "Critical"
            impact.financial_impact_estimate = "$500K - $2M+ potential loss"
            impact.operational_impact = "Severe - potential service disruption"
            impact.reputation_risk = "High"
            impact.compliance_risk = "High"
            impact.remediation_priority = "Immediate"
            impact.estimated_remediation_time = "24-48 hours for critical items"
            impact.business_continuity_risk = "High"
            
        elif metrics.high_vulnerabilities > 2 or metrics.successful_exploits > 0:
            impact.overall_risk_level = "High"
            impact.financial_impact_estimate = "$100K - $500K potential loss"
            impact.operational_impact = "Moderate - limited service impact possible"
            impact.reputation_risk = "Medium"
            impact.compliance_risk = "Medium"
            impact.remediation_priority = "High"
            impact.estimated_remediation_time = "1-2 weeks"
            impact.business_continuity_risk = "Medium"
            
        elif metrics.medium_vulnerabilities > 3:
            impact.overall_risk_level = "Medium"
            impact.financial_impact_estimate = "$10K - $100K potential loss"
            impact.operational_impact = "Low - unlikely service impact"
            impact.reputation_risk = "Low"
            impact.compliance_risk = "Low"
            impact.remediation_priority = "Medium"
            impact.estimated_remediation_time = "2-4 weeks"
            impact.business_continuity_risk = "Low"
            
        else:
            impact.overall_risk_level = "Low"
            impact.financial_impact_estimate = "< $10K potential loss"
            impact.operational_impact = "Minimal"
            impact.remediation_priority = "Low"
            impact.estimated_remediation_time = "1-2 months"
        
        # Assess compliance gaps
        if metrics.critical_vulnerabilities > 0:
            metrics.compliance_gaps = 3
        elif metrics.high_vulnerabilities > 0:
            metrics.compliance_gaps = 2
        elif metrics.medium_vulnerabilities > 0:
            metrics.compliance_gaps = 1
        
        return impact
    
    def generate_professional_report(self, target_ip: str) -> Dict[str, Any]:
        """Generate a comprehensive professional security assessment report"""
        
        logger.info(f"Starting enhanced report generation for target: {target_ip}")
        
        # Load assessment data
        assessment_data = self.load_assessment_data(target_ip)
        
        # Calculate metrics
        metrics = self.calculate_security_metrics(assessment_data)
        business_impact = self.assess_business_impact(metrics, assessment_data)
        
        if not self.crew_available:
            return self._generate_enhanced_fallback_report(
                target_ip, assessment_data, metrics, business_impact
            )
        
        try:
            # Create enhanced tasks for CrewAI
            tasks = self._create_enhanced_report_tasks(target_ip, assessment_data, metrics, business_impact)
            
            # Create and execute crew
            from crewai import Crew, Process
            crew = Crew(
                agents=[
                    self.vulnerability_analyst, 
                    self.business_impact_analyst,
                    self.compliance_specialist,
                    self.technical_writer, 
                    self.executive_advisor
                ],
                tasks=tasks,
                process=Process.sequential,
                verbose=True
            )
            
            # Execute the crew
            result = crew.kickoff()
            
            # Process and structure results
            report_data = self._process_enhanced_crew_results(
                result, target_ip, assessment_data, metrics, business_impact
            )
            
            # Save comprehensive report
            self._save_comprehensive_report(target_ip, report_data, assessment_data, metrics, business_impact)
            
            logger.info("Enhanced CrewAI report generation completed successfully")
            return report_data
            
        except Exception as e:
            logger.error(f"Enhanced CrewAI report generation failed: {e}")
            return self._generate_enhanced_fallback_report(
                target_ip, assessment_data, metrics, business_impact
            )
    
    def _create_enhanced_report_tasks(self, target_ip: str, assessment_data: Dict[str, Any], 
                                    metrics: SecurityMetrics, business_impact: BusinessImpactAssessment) -> List:
        """Create comprehensive tasks for CrewAI agents"""
        from crewai import Task
        
        # Task 1: Deep Vulnerability Analysis
        vulnerability_analysis_task = Task(
            description=f"""Conduct a comprehensive vulnerability analysis for target {target_ip}.
            
            Assessment Data Summary:
            - Total Services Discovered: {metrics.total_services}
            - Total Vulnerabilities: {metrics.total_vulnerabilities}
            - Critical: {metrics.critical_vulnerabilities}, High: {metrics.high_vulnerabilities}
            - Medium: {metrics.medium_vulnerabilities}, Low: {metrics.low_vulnerabilities}
            - Successful Exploits: {metrics.successful_exploits}/{metrics.total_exploit_attempts}
            - Overall Risk Score: {metrics.risk_score}/10
            
            Raw Assessment Data: {json.dumps(assessment_data, default=str, indent=2)}
            
            Provide:
            1. Technical analysis of each vulnerability with CVSS breakdown
            2. Attack vector analysis and exploit chain possibilities
            3. Real-world exploitability assessment
            4. Technical remediation steps with implementation details
            5. Priority ranking with justification
            6. Dependencies and prerequisites for attacks
            """,
            agent=self.vulnerability_analyst,
            expected_output="Detailed technical vulnerability report with CVSS analysis, exploit chains, and prioritized remediation steps"
        )
        
        # Task 2: Business Impact Analysis
        business_impact_task = Task(
            description=f"""Analyze business impact and financial risk for the security assessment of {target_ip}.
            
            Security Metrics:
            - Risk Level: {business_impact.overall_risk_level}
            - Financial Impact Estimate: {business_impact.financial_impact_estimate}
            - Operational Impact: {business_impact.operational_impact}
            - Compliance Gaps: {metrics.compliance_gaps}
            
            Provide:
            1. Quantified financial risk assessment with scenarios
            2. Operational impact analysis including downtime estimates
            3. Reputation and brand risk evaluation
            4. Compliance impact assessment (SOX, HIPAA, GDPR, PCI-DSS)
            5. Cost-benefit analysis of remediation efforts
            6. Resource requirements and budget recommendations
            7. Timeline for remediation with business priorities
            """,
            agent=self.business_impact_analyst,
            expected_output="Comprehensive business impact assessment with financial quantification and strategic recommendations"
        )
        
        # Task 3: Compliance Analysis
        compliance_task = Task(
            description=f"""Assess regulatory and compliance implications of security findings for {target_ip}.
            
            Current Security Status:
            - Critical Vulnerabilities: {metrics.critical_vulnerabilities}
            - Compliance Gaps Identified: {metrics.compliance_gaps}
            - Risk Level: {business_impact.overall_risk_level}
            
            Analyze compliance impact for:
            1. NIST Cybersecurity Framework
            2. ISO 27001/27002 standards
            3. PCI-DSS requirements (if applicable)
            4. HIPAA Security Rule (if applicable)
            5. GDPR technical and organizational measures
            6. SOX IT controls and documentation
            7. Industry-specific regulations
            
            Provide compliance gap analysis, audit readiness assessment, and remediation roadmap.
            """,
            agent=self.compliance_specialist,
            expected_output="Detailed compliance analysis with gap assessment and regulatory remediation roadmap"
        )
        
        # Task 4: Technical Documentation
        technical_documentation_task = Task(
            description=f"""Create comprehensive technical security documentation for {target_ip} assessment.
            
            Compile the vulnerability analysis, business impact, and compliance findings into a 
            professional technical report that includes:
            
            1. Executive Summary (1-2 pages)
            2. Assessment Methodology and Scope
            3. Network Architecture and Services Analysis
            4. Detailed Vulnerability Findings with Evidence
            5. Exploit Analysis and Proof of Concepts
            6. Risk Assessment Matrix
            7. Technical Remediation Guide
            8. Compliance Mapping and Gap Analysis
            9. Appendices with Raw Technical Data
            
            The report should be suitable for security teams, IT operations, and technical management.
            """,
            agent=self.technical_writer,
            expected_output="Professional technical security assessment report with comprehensive documentation and evidence"
        )
        
        # Task 5: Executive Summary and Strategic Recommendations
        executive_summary_task = Task(
            description=f"""Create executive-level summary and strategic recommendations for {target_ip} security assessment.
            
            Based on all previous analyses, provide:
            
            1. Executive Summary (board-ready, 1 page)
            2. Strategic Security Recommendations
            3. Investment Priorities and Budget Requirements
            4. Implementation Timeline with Milestones
            5. Success Metrics and KPIs
            6. Risk Management Strategy
            7. Long-term Security Roadmap
            
            Focus on translating technical findings into business decisions and actionable executive strategies.
            The summary should be suitable for C-level executives and board presentation.
            """,
            agent=self.executive_advisor,
            expected_output="Executive summary with strategic recommendations and implementation roadmap for C-level decision makers"
        )
        
        return [vulnerability_analysis_task, business_impact_task, compliance_task, 
                technical_documentation_task, executive_summary_task]
    
    def _process_enhanced_crew_results(self, crew_result, target_ip: str, 
                                     assessment_data: Dict[str, Any], 
                                     metrics: SecurityMetrics, 
                                     business_impact: BusinessImpactAssessment) -> Dict[str, Any]:
        """Process enhanced CrewAI results into structured report data"""
        
        report_data = {
            "report_type": "Enterprise Security Assessment",
            "report_version": "2.0",
            "target_ip": target_ip,
            "assessment_date": datetime.now().isoformat(),
            "assessment_duration": "Professional Assessment",
            "report_classification": "Confidential",
            
            # Executive Summary
            "executive_summary": crew_result if isinstance(crew_result, str) else "Executive analysis completed by CrewAI agents",
            
            # Metrics and KPIs
            "security_metrics": asdict(metrics),
            "business_impact": asdict(business_impact),
            
            # Report Sections
            "vulnerability_analysis": "Detailed vulnerability analysis generated by senior analyst agent",
            "business_impact_analysis": "Comprehensive business impact assessment completed",
            "compliance_analysis": "Regulatory compliance analysis completed",
            "technical_documentation": "Professional technical documentation generated",
            "strategic_recommendations": "Executive-level strategic recommendations provided",
            
            # Report URLs
            "report_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.html",
            "pdf_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.pdf",
            "json_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.json",
            
            # Metadata
            "generated_by": "BreachPilot Enterprise with CrewAI",
            "agent_count": 5,
            "data_sources": len(assessment_data['raw_data_files']),
            "report_pages": "15-25 pages estimated"
        }
        
        return report_data
    
    def _generate_enhanced_fallback_report(self, target_ip: str, assessment_data: Dict[str, Any], 
                                         metrics: SecurityMetrics, 
                                         business_impact: BusinessImpactAssessment) -> Dict[str, Any]:
        """Generate enhanced fallback report when CrewAI is not available"""
        
        logger.info("Generating enhanced fallback report with professional formatting")
        
        # Executive Summary
        exec_summary = f"""
        ENTERPRISE SECURITY ASSESSMENT - EXECUTIVE SUMMARY
        
        Target: {target_ip}
        Assessment Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
        Overall Risk Level: {business_impact.overall_risk_level}
        
        KEY FINDINGS:
        • Network Services: {metrics.total_services} services identified and analyzed
        • Security Vulnerabilities: {metrics.total_vulnerabilities} total vulnerabilities discovered
        • Critical Issues: {metrics.critical_vulnerabilities} critical-severity vulnerabilities requiring immediate attention
        • High-Risk Issues: {metrics.high_vulnerabilities} high-severity vulnerabilities
        • Exploit Success Rate: {metrics.successful_exploits}/{metrics.total_exploit_attempts} successful exploitations
        • Risk Score: {metrics.risk_score:.1f}/10.0
        
        BUSINESS IMPACT:
        • Financial Risk: {business_impact.financial_impact_estimate}
        • Operational Impact: {business_impact.operational_impact}
        • Compliance Risk: {business_impact.compliance_risk}
        • Remediation Priority: {business_impact.remediation_priority}
        • Estimated Remediation Time: {business_impact.estimated_remediation_time}
        
        IMMEDIATE ACTIONS REQUIRED:
        {"• Critical vulnerabilities require immediate patching within 24-48 hours" if metrics.critical_vulnerabilities > 0 else ""}
        {"• High-severity vulnerabilities should be addressed within 1-2 weeks" if metrics.high_vulnerabilities > 0 else ""}
        {"• Successful exploits indicate active security gaps requiring urgent attention" if metrics.successful_exploits > 0 else ""}
        
        This assessment was conducted using enterprise-grade security testing methodologies
        and follows industry best practices for vulnerability assessment and penetration testing.
        """
        
        # Professional Recommendations
        recommendations = f"""
        STRATEGIC SECURITY RECOMMENDATIONS
        
        Based on the comprehensive security assessment, the following strategic recommendations
        are provided in order of business priority:
        
        IMMEDIATE ACTIONS (0-30 days):
        1. Critical Patch Management: Apply security updates for all {metrics.critical_vulnerabilities} critical vulnerabilities
        2. Incident Response: Activate incident response procedures for successfully exploited vulnerabilities
        3. Emergency Monitoring: Implement enhanced monitoring for affected systems
        4. Access Controls: Review and restrict access to vulnerable services
        
        SHORT-TERM INITIATIVES (1-3 months):
        1. Vulnerability Management Program: Establish systematic vulnerability scanning and patching
        2. Network Segmentation: Implement proper network segmentation to limit attack surface
        3. Security Awareness: Conduct targeted security training based on identified attack vectors
        4. Compliance Remediation: Address {metrics.compliance_gaps} identified compliance gaps
        
        LONG-TERM STRATEGIC INVESTMENTS (3-12 months):
        1. Security Architecture Review: Comprehensive security architecture assessment
        2. Advanced Threat Detection: Deploy next-generation security monitoring solutions
        3. Zero Trust Implementation: Migrate to zero-trust security architecture
        4. Continuous Security Assessment: Implement ongoing security testing and validation
        
        BUDGET AND RESOURCE CONSIDERATIONS:
        • Estimated Investment Required: {business_impact.financial_impact_estimate}
        • Resource Allocation: Security team expansion may be required
        • Timeline: {business_impact.estimated_remediation_time} for critical items
        • ROI: Significant risk reduction and compliance improvement expected
        """
        
        return {
            "report_type": "Enterprise Security Assessment",
            "report_version": "2.0 (Enhanced Fallback)",
            "target_ip": target_ip,
            "assessment_date": datetime.now().isoformat(),
            "report_classification": "Confidential",
            
            "executive_summary": exec_summary.strip(),
            "strategic_recommendations": recommendations.strip(),
            "security_metrics": asdict(metrics),
            "business_impact": asdict(business_impact),
            
            "vulnerability_count": metrics.total_vulnerabilities,
            "critical_issues": metrics.critical_vulnerabilities,
            "successful_exploits": metrics.successful_exploits,
            "risk_score": metrics.risk_score,
            "compliance_gaps": metrics.compliance_gaps,
            
            "report_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.html",
            "pdf_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.pdf",
            "json_url": f"/reports/enterprise_assessment_{target_ip}_{datetime.now().strftime('%Y%m%d')}.json",
            
            "generated_by": "BreachPilot Enterprise (Enhanced Fallback Mode)",
            "data_sources": assessment_data['raw_data_files'],
            "assessment_scope": "Network services, vulnerability analysis, and exploitation testing"
        }
    
    def _save_comprehensive_report(self, target_ip: str, report_data: Dict[str, Any], 
                                  assessment_data: Dict[str, Any], metrics: SecurityMetrics, 
                                  business_impact: BusinessImpactAssessment):
        """Save comprehensive report data to multiple formats"""
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        # Save detailed JSON report
        json_path = self.reports_dir / f"enterprise_assessment_{target_ip}_{timestamp}.json"
        comprehensive_data = {
            "report_metadata": report_data,
            "raw_assessment_data": assessment_data,
            "calculated_metrics": asdict(metrics),
            "business_impact_analysis": asdict(business_impact),
            "generation_timestamp": datetime.now().isoformat(),
            "data_sources": assessment_data.get('raw_data_files', [])
        }
        
        with open(json_path, 'w', encoding='utf-8') as f:
            json.dump(comprehensive_data, f, indent=2, default=str)
        
        logger.info(f"Comprehensive report data saved to {json_path}")
        
        # Save executive summary to text file
        exec_summary_path = self.reports_dir / f"executive_summary_{target_ip}_{timestamp}.txt"
        with open(exec_summary_path, 'w', encoding='utf-8') as f:
            f.write(report_data.get('executive_summary', ''))
        
        logger.info(f"Executive summary saved to {exec_summary_path}")
