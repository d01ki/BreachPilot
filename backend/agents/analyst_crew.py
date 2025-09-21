import json
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from crewai_tools import tool
from langchain_openai import ChatOpenAI
from backend.models import AnalystResult, CVEAnalysis, NmapResult, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class AnalystCrew:
    def __init__(self):
        self.llm = ChatOpenAI(
            model=config.LLM_MODEL,
            temperature=config.LLM_TEMPERATURE,
            api_key=config.OPENAI_API_KEY
        )
    
    def analyze_vulnerabilities(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """Analyze vulnerabilities using CVE database and XAI"""
        logger.info(f"Starting vulnerability analysis for {target_ip}")
        
        result = AnalystResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Create CVE analysis agent
            cve_analyst = Agent(
                role='CVE Security Analyst',
                goal='Identify and analyze CVE vulnerabilities from scan results',
                backstory="""You are an expert security analyst specializing in CVE identification 
                and vulnerability assessment. You analyze scan results to identify known CVEs and 
                provide detailed explanations of their impact and exploitability.""",
                llm=self.llm,
                verbose=True
            )
            
            # Create XAI explainer agent
            xai_explainer = Agent(
                role='Security Explainability Specialist',
                goal='Provide clear, detailed explanations of security vulnerabilities',
                backstory="""You are an expert in explaining complex security vulnerabilities 
                in clear, actionable terms. You provide context, impact analysis, and 
                exploitation scenarios for identified CVEs.""",
                llm=self.llm,
                verbose=True
            )
            
            # Prepare scan data
            scan_context = self._prepare_scan_context(nmap_result)
            
            # Task 1: Identify CVEs
            identify_task = Task(
                description=f"""Analyze the following scan results and identify all relevant CVEs:
                
                {scan_context}
                
                For each vulnerability found, provide:
                1. CVE ID
                2. CVSS score
                3. Affected service and version
                4. Brief description
                5. Whether exploits are publicly available
                
                Focus on the most critical vulnerabilities that could lead to system compromise.""",
                agent=cve_analyst,
                expected_output="A detailed list of CVEs with their metadata and severity ratings"
            )
            
            # Task 2: Explain vulnerabilities
            explain_task = Task(
                description="""For each identified CVE, provide:
                
                1. A clear explanation of how the vulnerability works
                2. The potential impact if exploited
                3. Why this particular system is vulnerable
                4. Recommended mitigation steps
                5. Exploitation difficulty assessment
                
                Make explanations clear and actionable for security teams.""",
                agent=xai_explainer,
                expected_output="Comprehensive explanations for each vulnerability with actionable insights",
                context=[identify_task]
            )
            
            # Create and run crew
            crew = Crew(
                agents=[cve_analyst, xai_explainer],
                tasks=[identify_task, explain_task],
                process=Process.sequential,
                verbose=True
            )
            
            crew_result = crew.kickoff()
            
            # Parse results
            result.identified_cves = self._parse_cve_analysis(str(crew_result))
            result.risk_assessment = self._generate_risk_assessment(result.identified_cves)
            result.priority_vulnerabilities = self._prioritize_vulnerabilities(result.identified_cves)
            result.status = StepStatus.COMPLETED
            
            logger.info(f"Vulnerability analysis completed for {target_ip}")
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            result.status = StepStatus.FAILED
        
        # Save result
        self._save_result(target_ip, result)
        return result
    
    def _prepare_scan_context(self, nmap_result: NmapResult) -> str:
        """Prepare scan context for analysis"""
        context = f"Target IP: {nmap_result.target_ip}\n\n"
        
        if nmap_result.os_detection:
            context += f"OS Detection: {nmap_result.os_detection}\n\n"
        
        context += "Open Ports and Services:\n"
        for service in nmap_result.services:
            context += f"- Port {service['port']}: {service['name']} "
            if service.get('product'):
                context += f"({service['product']} {service.get('version', '')})"
            context += "\n"
        
        if nmap_result.vulnerabilities:
            context += "\nDetected Vulnerabilities:\n"
            for vuln in nmap_result.vulnerabilities:
                context += f"- {vuln.get('cve_id', vuln.get('description', 'Unknown'))}\n"
        
        return context
    
    def _parse_cve_analysis(self, analysis_text: str) -> List[CVEAnalysis]:
        """Parse CVE analysis from crew output"""
        cves = []
        
        # Simple parsing - in production, use more robust parsing
        import re
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        found_cves = re.findall(cve_pattern, analysis_text)
        
        for cve_id in set(found_cves):
            # Extract info for this CVE from text
            cve_section = self._extract_cve_section(analysis_text, cve_id)
            
            cve = CVEAnalysis(
                cve_id=cve_id,
                description=self._extract_description(cve_section),
                affected_service=self._extract_service(cve_section),
                xai_explanation=cve_section[:500],  # First 500 chars as explanation
                exploit_available=self._check_exploit_available(cve_section),
                recommendation=self._extract_recommendation(cve_section)
            )
            cves.append(cve)
        
        return cves
    
    def _extract_cve_section(self, text: str, cve_id: str) -> str:
        """Extract section related to specific CVE"""
        lines = text.split('\n')
        section = []
        capturing = False
        
        for line in lines:
            if cve_id in line:
                capturing = True
            elif capturing and 'CVE-' in line and cve_id not in line:
                break
            
            if capturing:
                section.append(line)
        
        return '\n'.join(section)
    
    def _extract_description(self, text: str) -> str:
        """Extract vulnerability description"""
        # Simple extraction - look for description patterns
        patterns = [
            r'Description:\s*(.+?)(?:\n|$)',
            r'allows\s+(.+?)(?:\.|\n)',
            r'vulnerability\s+(.+?)(?:\.|\n)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return text[:200]  # Fallback to first 200 chars
    
    def _extract_service(self, text: str) -> str:
        """Extract affected service"""
        import re
        patterns = [
            r'affects?\s+([\w\s]+?)(?:version|\n)',
            r'in\s+([\w\s]+?)(?:version|\n)',
            r'Service:\s*(.+?)(?:\n|$)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        return "Unknown"
    
    def _check_exploit_available(self, text: str) -> bool:
        """Check if exploit is mentioned as available"""
        keywords = ['exploit available', 'public exploit', 'metasploit', 'exploit-db']
        return any(kw in text.lower() for kw in keywords)
    
    def _extract_recommendation(self, text: str) -> str:
        """Extract mitigation recommendation"""
        import re
        patterns = [
            r'Recommendation:\s*(.+?)(?:\n\n|$)',
            r'Mitigation:\s*(.+?)(?:\n\n|$)',
            r'(?:patch|update|upgrade)\s+(.+?)(?:\.|\n)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        
        return "Update to the latest version"
    
    def _generate_risk_assessment(self, cves: List[CVEAnalysis]) -> str:
        """Generate overall risk assessment"""
        if not cves:
            return "No significant vulnerabilities identified."
        
        critical_count = sum(1 for cve in cves if cve.cvss_score and cve.cvss_score >= 9.0)
        high_count = sum(1 for cve in cves if cve.cvss_score and 7.0 <= cve.cvss_score < 9.0)
        
        assessment = f"Identified {len(cves)} vulnerabilities. "
        
        if critical_count > 0:
            assessment += f"{critical_count} critical vulnerabilities require immediate attention. "
        if high_count > 0:
            assessment += f"{high_count} high-severity vulnerabilities should be addressed soon."
        
        return assessment
    
    def _prioritize_vulnerabilities(self, cves: List[CVEAnalysis]) -> List[str]:
        """Prioritize vulnerabilities for exploitation"""
        # Sort by CVSS score and exploit availability
        sorted_cves = sorted(
            cves,
            key=lambda x: (x.exploit_available, x.cvss_score or 0),
            reverse=True
        )
        
        return [cve.cve_id for cve in sorted_cves[:5]]  # Top 5
    
    def _save_result(self, target_ip: str, result: AnalystResult):
        """Save analysis result to JSON"""
        output_file = config.DATA_DIR / f"{target_ip}_analyst.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Analysis result saved to {output_file}")
