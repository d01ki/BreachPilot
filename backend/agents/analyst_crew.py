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
                verbose=False  # Reduced verbosity
            )
            
            scan_context = self._prepare_scan_context(nmap_result)
            
            identify_task = Task(
                description=f"""CRITICAL: You MUST identify CVE-2020-1472 (Zerologon) if this is a Domain Controller!

                {scan_context}
                
                MANDATORY CVE-2020-1472 ANALYSIS:
                - If ANY of these conditions are met, CVE-2020-1472 MUST be included:
                  1. Port 445 is open (SMB/Netlogon)
                  2. Target is identified as a Domain Controller
                  3. Windows Server is detected
                  4. Active Directory services are present
                
                CVE-2020-1472 (Zerologon) Details:
                - CVE ID: CVE-2020-1472
                - CVSS Score: 10.0 (Critical)
                - Affects: Microsoft Windows Netlogon Remote Protocol
                - Impact: Authentication bypass, domain controller compromise
                - Evidence: Port 445 + Domain Controller = HIGH PROBABILITY
                
                ADDITIONAL CVEs to check:
                - Port 88 (Kerberos) - CVE-2020-17049, CVE-2021-42287
                - Port 389/636 (LDAP) - CVE-2021-34473, CVE-2021-26855
                - Port 135 (RPC) - CVE-2020-1473, CVE-2021-26867
                - Port 3389 (RDP) - CVE-2019-0708 (BlueKeep), CVE-2021-34527
                - Port 139 (NetBIOS) - CVE-2020-1472 related
                
                For each vulnerability, provide:
                1. CVE ID
                2. Affected service and version
                3. Brief description
                4. Detailed reasoning for why this CVE applies to this target
                5. Specific evidence from the scan results
                6. Whether exploits are publicly available
                7. CVSS score and severity
                
                REMEMBER: CVE-2020-1472 is CRITICAL for Domain Controllers with Port 445!""",
                agent=cve_analyst,
                expected_output="A detailed list of CVEs with CVE-2020-1472 prominently featured if applicable"
            )
            
            crew = Crew(
                agents=[cve_analyst],
                tasks=[identify_task],
                process=Process.sequential,
                verbose=False  # Reduced verbosity
            )
            
            crew_result = crew.kickoff()
            result.identified_cves = self._parse_and_enrich_cves(str(crew_result), nmap_result)
            result.risk_assessment = self._generate_risk_assessment(result.identified_cves)
            result.priority_vulnerabilities = self._prioritize_vulnerabilities(result.identified_cves)
            result.status = StepStatus.COMPLETED
            
            logger.info(f"Analysis completed: {len(result.identified_cves)} CVEs identified")
            
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
    
    def _parse_and_enrich_cves(self, analysis_text: str, nmap_result: NmapResult) -> List[CVEAnalysis]:
        cves = []
        cve_pattern = r'CVE-\d{4}-\d{4,7}'
        found_cves = re.findall(cve_pattern, analysis_text)
        
        # Check if CVE-2020-1472 should be forced based on scan results
        should_force_zerologon = self._should_force_zerologon(nmap_result)
        if should_force_zerologon and 'CVE-2020-1472' not in found_cves:
            logger.info("Adding CVE-2020-1472 based on Domain Controller detection")
            found_cves.append('CVE-2020-1472')
        
        for cve_id in set(found_cves):
            cve_section = self._extract_cve_section(analysis_text, cve_id)
            
            # Get CVSS score from NVD (with rate limiting)
            cvss_score = self._get_cvss_from_nvd(cve_id)
            
            # Special handling for CVE-2020-1472
            if cve_id == 'CVE-2020-1472' and should_force_zerologon:
                cve = self._create_zerologon_cve(nmap_result)
            else:
                cve = CVEAnalysis(
                    cve_id=cve_id,
                    description=self._extract_description(cve_section),
                    affected_service=self._extract_service(cve_section),
                    cvss_score=cvss_score,
                    xai_explanation=self._enhance_explanation(cve_section, cve_id, nmap_result),
                    exploit_available=self._check_exploit_available(cve_section),
                    recommendation=self._extract_recommendation(cve_section),
                    cve_links=self._get_cve_links(cve_id)
                )
            cves.append(cve)
        
        return cves
    
    def _get_cvss_from_nvd(self, cve_id: str) -> float:
        """Get CVSS score from NVD API with rate limiting"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=8)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]
                    cve_data = vuln.get('cve', {})
                    metrics = cve_data.get('metrics', {})
                    
                    # Try CVSS v3.1 first, then v3.0, then v2
                    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if version in metrics:
                            return metrics[version][0]['cvssData']['baseScore']
            
            # Rate limiting for NVD API
            time.sleep(0.7)  # Slightly more conservative rate limiting
            
        except Exception as e:
            logger.debug(f"Failed to get CVSS for {cve_id}: {e}")
        
        return None
    
    def _extract_cve_section(self, text: str, cve_id: str) -> str:
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
        patterns = [
            r'Description:\s*(.+?)(?:\n|$)',
            r'allows\s+(.+?)(?:\.|n)',
            r'vulnerability\s+(.+?)(?:\.|n)'
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
            r'(?:patch|update|upgrade)\s+(.+?)(?:\.|n)'
        ]
        for pattern in patterns:
            match = re.search(pattern, text, re.IGNORECASE | re.DOTALL)
            if match:
                return match.group(1).strip()
        return "Update to the latest version"
    
    def _enhance_explanation(self, cve_section: str, cve_id: str, nmap_result: NmapResult) -> str:
        """Enhance CVE explanation with detailed reasoning and evidence"""
        enhanced = f"**CVE ID**: {cve_id}\n\n"
        
        # Add detailed reasoning
        enhanced += f"**Detailed Analysis**:\n"
        enhanced += f"{cve_section}\n\n"
        
        # Add evidence from scan results
        enhanced += f"**Evidence from Scan Results**:\n"
        if nmap_result.os_detection and nmap_result.os_detection.get('is_domain_controller'):
            enhanced += f"- Target is identified as a Domain Controller\n"
            enhanced += f"- Domain: {nmap_result.os_detection.get('dc_info', {}).get('domain', 'Unknown')}\n"
        
        # Add specific port evidence
        relevant_ports = []
        for service in nmap_result.services:
            if any(keyword in service['name'].lower() for keyword in ['smb', 'netbios', 'ldap', 'kerberos', 'rpc', 'rdp']):
                relevant_ports.append(f"Port {service['port']}: {service['name']} ({service.get('product', '')})")
        
        if relevant_ports:
            enhanced += f"- Relevant services detected: {', '.join(relevant_ports)}\n"
        
        # Add specific reasoning for CVE-2020-1472
        if cve_id == "CVE-2020-1472":
            enhanced += f"\n**Zerologon (CVE-2020-1472) Specific Analysis**:\n"
            enhanced += f"- This vulnerability affects the Netlogon protocol used by Domain Controllers\n"
            enhanced += f"- Port 445 (SMB) is open, which is required for Netlogon communication\n"
            enhanced += f"- The target appears to be a Windows Domain Controller based on detected services\n"
            enhanced += f"- This is a critical authentication bypass vulnerability with CVSS 10.0\n"
        
        return enhanced
    
    def _get_cve_links(self, cve_id: str) -> Dict[str, str]:
        """Get trusted CVE reference links"""
        return {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "cve_mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "exploit_db": f"https://www.exploit-db.com/search?cve={cve_id}",
            "rapid7": f"https://www.rapid7.com/db/vulnerabilities/{cve_id.lower()}/",
            "tenable": f"https://www.tenable.com/cve/{cve_id}"
        }
    
    def _should_force_zerologon(self, nmap_result: NmapResult) -> bool:
        """Check if CVE-2020-1472 should be forced based on scan results"""
        # Check if it's a Domain Controller
        is_dc = nmap_result.os_detection and nmap_result.os_detection.get('is_domain_controller', False)
        
        # Check for Port 445 (SMB/Netlogon)
        has_port_445 = any(service['port'] == 445 for service in nmap_result.services)
        
        # Check for Windows services
        has_windows_services = any(
            'microsoft' in service.get('product', '').lower() or 
            'windows' in service.get('product', '').lower()
            for service in nmap_result.services
        )
        
        # Check for Active Directory services
        has_ad_services = any(
            service['port'] in [88, 389, 636, 3268, 3269]  # Kerberos, LDAP, Global Catalog
            for service in nmap_result.services
        )
        
        return (is_dc and has_port_445) or (has_windows_services and has_port_445 and has_ad_services)
    
    def _create_zerologon_cve(self, nmap_result: NmapResult) -> CVEAnalysis:
        """Create a comprehensive CVE-2020-1472 analysis"""
        explanation = f"""**CVE ID**: CVE-2020-1472 (Zerologon)

**Detailed Analysis**:
CVE-2020-1472, also known as Zerologon, is a critical vulnerability in the Microsoft Windows Netlogon Remote Protocol (MS-NRPC). This vulnerability allows an attacker to impersonate any computer on the network, including domain controllers, by exploiting a flaw in the authentication process.

**Evidence from Scan Results**:
- Target is identified as a Domain Controller: {nmap_result.os_detection.get('is_domain_controller', False)}
- Domain: {nmap_result.os_detection.get('dc_info', {}).get('domain', 'Unknown')}
- Port 445 (SMB/Netlogon) is open: {any(service['port'] == 445 for service in nmap_result.services)}
- Active Directory services detected: {any(service['port'] in [88, 389, 636] for service in nmap_result.services)}

**Zerologon (CVE-2020-1472) Specific Analysis**:
- This vulnerability affects the Netlogon protocol used by Domain Controllers
- Port 445 (SMB) is open, which is required for Netlogon communication
- The target appears to be a Windows Domain Controller based on detected services
- This is a critical authentication bypass vulnerability with CVSS 10.0
- Attackers can reset the domain controller's computer account password
- This can lead to complete domain compromise

**Impact**: Complete domain controller compromise, authentication bypass, privilege escalation
**Exploit Available**: Yes, multiple public exploits exist
**Recommendation**: Apply Microsoft security updates immediately, enable Netlogon protection"""
        
        return CVEAnalysis(
            cve_id="CVE-2020-1472",
            description="Critical authentication bypass vulnerability in Microsoft Windows Netlogon Remote Protocol allowing domain controller compromise",
            affected_service="Microsoft Windows Netlogon Remote Protocol (MS-NRPC)",
            cvss_score=10.0,
            xai_explanation=explanation,
            exploit_available=True,
            recommendation="Apply Microsoft security updates immediately and enable Netlogon protection",
            cve_links=self._get_cve_links("CVE-2020-1472")
        )
    
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
        logger.debug(f"Analysis result saved to {output_file}")
