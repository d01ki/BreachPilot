from crewai import Agent, Task, Crew, Process
from backend.models import NmapResult, AnalystResult, ExploitResult, ReportData
from typing import Dict, Any, List
import logging
from datetime import datetime

logger = logging.getLogger(__name__)

class ReportGeneratorCrew:
    """CrewAI-based report generation system for professional security assessments"""
    
    def __init__(self):
        self.security_analyst = self._create_security_analyst()
        self.technical_writer = self._create_technical_writer()
        self.executive_advisor = self._create_executive_advisor()
    
    def _create_security_analyst(self) -> Agent:
        """Create a security analyst agent for technical assessment"""
        return Agent(
            role='Senior Security Analyst',
            goal='Analyze security assessment results and provide detailed technical findings',
            backstory="""You are a senior cybersecurity professional with 10+ years of experience 
            in penetration testing, vulnerability assessment, and security consulting. You specialize 
            in analyzing network security postures, identifying critical vulnerabilities, and 
            providing actionable security recommendations.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_technical_writer(self) -> Agent:
        """Create a technical writer agent for documentation"""
        return Agent(
            role='Technical Security Writer',
            goal='Create comprehensive and professional security assessment documentation',
            backstory="""You are an expert technical writer specializing in cybersecurity 
            documentation. You transform complex technical security findings into clear, 
            actionable reports for both technical teams and management. Your reports are 
            known for their clarity, completeness, and professional presentation.""",
            verbose=True,
            allow_delegation=False
        )
    
    def _create_executive_advisor(self) -> Agent:
        """Create an executive advisor for business impact analysis"""
        return Agent(
            role='Executive Security Advisor',
            goal='Provide executive-level security insights and business impact analysis',
            backstory="""You are a C-level security executive with extensive experience 
            in enterprise security strategy. You translate technical vulnerabilities into 
            business risks, provide strategic recommendations, and communicate security 
            concerns in terms that executive leadership can understand and act upon.""",
            verbose=True,
            allow_delegation=False
        )
    
    def generate_comprehensive_report(
        self, 
        target_ip: str,
        nmap_result: NmapResult = None,
        analyst_result: AnalystResult = None,
        exploit_results: List[ExploitResult] = None
    ) -> Dict[str, Any]:
        """Generate a comprehensive security assessment report using CrewAI"""
        
        logger.info(f"Starting CrewAI report generation for target: {target_ip}")
        
        # Prepare assessment data
        assessment_data = self._prepare_assessment_data(
            target_ip, nmap_result, analyst_result, exploit_results
        )
        
        # Create tasks for each agent
        tasks = self._create_report_tasks(assessment_data)
        
        # Create crew and execute
        crew = Crew(
            agents=[self.security_analyst, self.technical_writer, self.executive_advisor],
            tasks=tasks,
            process=Process.sequential,
            verbose=True
        )
        
        try:
            # Execute the crew
            result = crew.kickoff()
            
            # Process results
            report_data = self._process_crew_results(result, assessment_data)
            
            logger.info("CrewAI report generation completed successfully")
            return report_data
            
        except Exception as e:
            logger.error(f"CrewAI report generation failed: {e}")
            # Fallback to basic report
            return self._generate_basic_report(assessment_data)
    
    def _prepare_assessment_data(
        self, 
        target_ip: str,
        nmap_result: NmapResult = None,
        analyst_result: AnalystResult = None,
        exploit_results: List[ExploitResult] = None
    ) -> Dict[str, Any]:
        """Prepare assessment data for CrewAI processing"""
        
        # Network Services Summary
        services_summary = "No network services discovered"
        if nmap_result and nmap_result.open_ports:
            services = []
            for port in nmap_result.open_ports:
                service_info = f"Port {port['port']}: {port.get('service', 'unknown')}"
                if port.get('product'):
                    service_info += f" ({port['product']})"
                if port.get('version'):
                    service_info += f" version {port['version']}"
                services.append(service_info)
            services_summary = f"{len(services)} network services discovered:\n" + "\n".join(services)
        
        # Vulnerability Summary
        vulnerabilities_summary = "No vulnerabilities identified"
        critical_cves = []
        if analyst_result and analyst_result.identified_cves:
            cves_by_severity = {'critical': [], 'high': [], 'medium': [], 'low': []}
            
            for cve in analyst_result.identified_cves[:5]:  # Limit to 5 CVEs as requested
                severity = cve.severity.lower() if cve.severity else 'unknown'
                cve_info = {
                    'id': cve.cve_id,
                    'severity': severity,
                    'cvss_score': cve.cvss_score,
                    'description': cve.description,
                    'affected_service': cve.affected_service,
                    'exploit_available': cve.exploit_available
                }
                
                if severity in cves_by_severity:
                    cves_by_severity[severity].append(cve_info)
                
                if severity in ['critical', 'high']:
                    critical_cves.append(cve_info)
            
            total_cves = len(analyst_result.identified_cves)
            vulnerabilities_summary = f"{total_cves} vulnerabilities identified across severity levels"
        
        # Exploitation Summary
        exploitation_summary = "No exploitation attempts performed"
        successful_exploits = []
        if exploit_results:
            total_attempts = len(exploit_results)
            successful = [er for er in exploit_results if er.success]
            
            exploitation_summary = f"{total_attempts} exploitation attempts: {len(successful)} successful"
            
            for exploit in successful:
                successful_exploits.append({
                    'cve_id': exploit.cve_id,
                    'target_ip': exploit.target_ip,
                    'exploit_used': exploit.exploit_used,
                    'success': exploit.success
                })
        
        return {
            'target_ip': target_ip,
            'assessment_date': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            'services_summary': services_summary,
            'vulnerabilities_summary': vulnerabilities_summary,
            'exploitation_summary': exploitation_summary,
            'critical_cves': critical_cves,
            'successful_exploits': successful_exploits,
            'total_services': len(nmap_result.open_ports) if nmap_result and nmap_result.open_ports else 0,
            'total_vulnerabilities': len(analyst_result.identified_cves) if analyst_result and analyst_result.identified_cves else 0,
            'total_exploits': len(successful_exploits)
        }
    
    def _create_report_tasks(self, assessment_data: Dict[str, Any]) -> List[Task]:
        """Create tasks for each CrewAI agent"""
        
        # Task 1: Technical Analysis
        technical_analysis_task = Task(
            description=f"""Analyze the security assessment results for target {assessment_data['target_ip']} and provide detailed technical findings.

            Assessment Data:
            - Target: {assessment_data['target_ip']}
            - Assessment Date: {assessment_data['assessment_date']}
            - Network Services: {assessment_data['services_summary']}
            - Vulnerabilities: {assessment_data['vulnerabilities_summary']}
            - Exploitation Results: {assessment_data['exploitation_summary']}
            
            Critical Vulnerabilities Found: {len(assessment_data['critical_cves'])}
            Successful Exploits: {assessment_data['total_exploits']}
            
            Provide:
            1. Technical risk assessment
            2. Vulnerability analysis with CVSS scores
            3. Attack vector analysis
            4. Technical recommendations for remediation
            5. Priority ranking of security issues
            """,
            agent=self.security_analyst,
            expected_output="Detailed technical security analysis with vulnerability assessments, risk ratings, and technical remediation recommendations"
        )
        
        # Task 2: Documentation Creation
        documentation_task = Task(
            description=f"""Create comprehensive security assessment documentation based on the technical analysis.
            
            Transform the technical findings into a professional security assessment report that includes:
            1. Executive Summary
            2. Assessment Methodology
            3. Technical Findings
            4. Vulnerability Details
            5. Risk Analysis
            6. Remediation Recommendations
            7. Appendices with technical details
            
            The report should be suitable for both technical teams and management review.
            Target IP: {assessment_data['target_ip']}
            """,
            agent=self.technical_writer,
            expected_output="Professional security assessment report with clear structure, technical accuracy, and actionable recommendations"
        )
        
        # Task 3: Executive Summary
        executive_summary_task = Task(
            description=f"""Create an executive-level summary focusing on business impact and strategic recommendations.
            
            Based on the technical assessment, provide:
            1. Business risk summary
            2. Financial impact assessment
            3. Strategic security recommendations
            4. Implementation priorities
            5. Resource requirements
            6. Timeline recommendations
            
            Focus on translating technical vulnerabilities into business terms and actionable executive decisions.
            """,
            agent=self.executive_advisor,
            expected_output="Executive summary with business impact analysis, strategic recommendations, and implementation roadmap"
        )
        
        return [technical_analysis_task, documentation_task, executive_summary_task]
    
    def _process_crew_results(self, crew_result: Any, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Process CrewAI results into structured report data"""
        
        # Extract results from crew execution
        # Note: This is a simplified processing - actual implementation would depend on CrewAI's result structure
        
        report_data = {
            "report_type": "Professional Security Assessment",
            "target_ip": assessment_data['target_ip'],
            "assessment_date": assessment_data['assessment_date'],
            "executive_summary": "Executive summary generated by CrewAI",
            "technical_findings": "Technical findings generated by CrewAI",
            "recommendations": "Recommendations generated by CrewAI",
            "findings_count": assessment_data['total_vulnerabilities'],
            "critical_issues": len(assessment_data['critical_cves']),
            "successful_exploits": assessment_data['total_exploits'],
            "report_url": f"/reports/security_assessment_{assessment_data['target_ip']}.html",
            "pdf_url": f"/reports/security_assessment_{assessment_data['target_ip']}.pdf"
        }
        
        return report_data
    
    def _generate_basic_report(self, assessment_data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate basic report as fallback when CrewAI fails"""
        
        logger.warning("Generating basic report due to CrewAI failure")
        
        # Basic executive summary
        exec_summary = f"""
        Security Assessment Summary for {assessment_data['target_ip']}
        
        Network Services: {assessment_data['total_services']} services identified
        Security Vulnerabilities: {assessment_data['total_vulnerabilities']} vulnerabilities found
        Critical Issues: {len(assessment_data['critical_cves'])} high-severity vulnerabilities
        Exploitation Success: {assessment_data['total_exploits']} successful exploits
        
        Immediate Action Required: {"Yes" if assessment_data['critical_cves'] else "No"}
        Overall Risk Level: {"High" if assessment_data['critical_cves'] else "Medium"}
        """
        
        return {
            "report_type": "Basic Security Assessment",
            "target_ip": assessment_data['target_ip'],
            "assessment_date": assessment_data['assessment_date'],
            "executive_summary": exec_summary.strip(),
            "technical_findings": f"Detailed technical analysis available for {assessment_data['total_vulnerabilities']} identified vulnerabilities",
            "recommendations": "Professional remediation recommendations based on industry best practices",
            "findings_count": assessment_data['total_vulnerabilities'],
            "critical_issues": len(assessment_data['critical_cves']),
            "successful_exploits": assessment_data['total_exploits'],
            "report_url": f"/reports/basic_assessment_{assessment_data['target_ip']}.html",
            "pdf_url": f"/reports/basic_assessment_{assessment_data['target_ip']}.pdf"
        }