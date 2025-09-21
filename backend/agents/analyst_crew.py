import json
import re
import requests
import time
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
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
        logger.info(f"Starting vulnerability analysis for {target_ip}")
        
        result = AnalystResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            cve_analyst = Agent(
                role='CVE Security Analyst',
                goal='Identify and analyze CVE vulnerabilities from scan results',
                backstory="""You are an expert security analyst specializing in CVE identification 
                and vulnerability assessment. You analyze scan results to identify known CVEs.""",
                llm=self.llm,
                verbose=True
            )
            
            scan_context = self._prepare_scan_context(nmap_result)
            
            identify_task = Task(
                description=f"""Analyze the scan results and identify all relevant CVEs:
                
                {scan_context}
                
                For each vulnerability, provide:
                1. CVE ID
                2. Affected service and version
                3. Brief description
                4. Whether exploits are publicly available""",
                agent=cve_analyst,
                expected_output="A detailed list of CVEs with metadata"
            )
            
            crew = Crew(
                agents=[cve_analyst],
                tasks=[identify_task],
                process=Process.sequential,
                verbose=True
            )
            
            crew_result = crew.kickoff()
            result.identified_cves = self._parse_and_enrich_cves(str(crew_result))
            result.risk_assessment = self._generate_risk_assessment(result.identified_cves)
            result.priority_vulnerabilities = self._prioritize_vulnerabilities(result.identified_cves)
            result.status = StepStatus.COMPLETED
            
            logger.info(f"Analysis completed for {target_ip}")
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            result.status = StepStatus.FAILED
        
        self._save_result(target_ip, result)
        return result
    
    def _prepare_scan_context(self, nmap_result: NmapResult) -> str:
        context = f"Target IP: {nmap_result.target_ip}\n\n"
        if nmap_result.os_detection:
            context += f"OS: {nmap_result.os_detection}\n\n"
        context += "Services:\n"
        for service in nmap_result.services:
            context += f"- Port {service['port']}: {service['name']} {service.get('product', '')} {service.get('version', '')}\n"
        return context
    
    def _parse_and_enrich_cves(self, analysis_text: str) -> List[CVEAnalysis]:
        cves = []
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        found_cves = re.findall(cve_pattern, analysis_text)
        
        for cve_id in set(found_cves):
            logger.info(f"Enriching {cve_id} with NVD data...")
            cve_section = self._extract_cve_section(analysis_text, cve_id)
            
            # Get CVSS score from NVD
            cvss_score = self._get_cvss_from_nvd(cve_id)
            
            cve = CVEAnalysis(
                cve_id=cve_id,
                description=self._extract_description(cve_section),
                affected_service=self._extract_service(cve_section),
                cvss_score=cvss_score,
                xai_explanation=cve_section[:500],
                exploit_available=self._check_exploit_available(cve_section),
                recommendation=self._extract_recommendation(cve_section)
            )
            cves.append(cve)
            logger.info(f"  {cve_id}: CVSS {cvss_score}")
        
        return cves
    
    def _get_cvss_from_nvd(self, cve_id: str) -> float:
        """Get CVSS score from NVD API"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=5)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]
                    cve_data = vuln.get('cve', {})
                    metrics = cve_data.get('metrics', {})
                    
                    # Try CVSS v3.1 first
                    if 'cvssMetricV31' in metrics:
                        return metrics['cvssMetricV31'][0]['cvssData']['baseScore']
                    # Then CVSS v3.0
                    elif 'cvssMetricV30' in metrics:
                        return metrics['cvssMetricV30'][0]['cvssData']['baseScore']
                    # Finally CVSS v2
                    elif 'cvssMetricV2' in metrics:
                        return metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            
            # Rate limiting
            time.sleep(0.6)  # NVD allows ~1 req/sec
            
        except Exception as e:
            logger.warning(f"Failed to get CVSS for {cve_id}: {e}")
        
        return None
    
    def _extract_cve_section(self, text: str, cve_id: str) -> str:
        lines = text.split('\n')
        section = []
        capturing = False
        
        for i, line in enumerate(lines):
            if cve_id in line:
                capturing = True
            elif capturing and 'CVE-' in line and cve_id not in line:
                break
            if capturing:
                section.append(line)
        
        return '\n'.join(section)
    
    def _extract_description(self, text: str) -> str:
        patterns = [
            r'Description:\s*(.+?)(?:\n|$)',
            r'allows\s+(.+?)(?:\.|\n)',
            r'vulnerability\s+(.+?)(?:\.|\n)'
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        return text[:200]
    
    def _extract_service(self, text: str) -> str:
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
        keywords = ['exploit available', 'public exploit', 'metasploit', 'exploit-db']
        return any(kw in text.lower() for kw in keywords)
    
    def _extract_recommendation(self, text: str) -> str:
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
        sorted_cves = sorted(
            cves,
            key=lambda x: (x.exploit_available, x.cvss_score or 0),
            reverse=True
        )
        return [cve.cve_id for cve in sorted_cves[:5]]
    
    def _save_result(self, target_ip: str, result: AnalystResult):
        output_file = config.DATA_DIR / f"{target_ip}_analyst.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Analysis result saved to {output_file}")
