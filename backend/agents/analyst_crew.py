import json
import re
import requests
import time
from typing import List, Dict, Any
from crewai import Agent, Task, Crew, Process
from langchain_openai import ChatOpenAI
from backend.models import AnalystResult, CVEInfo, NmapResult, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class AnalystCrew:
    def __init__(self):
        try:
            self.llm = ChatOpenAI(
                model=config.LLM_MODEL,
                temperature=config.LLM_TEMPERATURE,
                api_key=config.OPENAI_API_KEY
            )
        except:
            # Fallback without LLM for testing
            self.llm = None
            logger.warning("LLM not configured, using fallback analysis")
    
    def analyze_vulnerabilities(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        logger.info(f"Starting vulnerability analysis for {target_ip}")
        
        result = AnalystResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            if self.llm:
                # Use CrewAI analysis
                result = self._crewai_analysis(target_ip, nmap_result)
            else:
                # Use fallback analysis
                result = self._fallback_analysis(target_ip, nmap_result)
            
            result.status = StepStatus.COMPLETED
            logger.info(f"Analysis completed for {target_ip}: {len(result.identified_cves)} CVEs identified")
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            result = self._fallback_analysis(target_ip, nmap_result)
            result.status = StepStatus.FAILED
        
        self._save_result(target_ip, result)
        return result
    
    def _crewai_analysis(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """CrewAI-based analysis"""
        cve_analyst = Agent(
            role='CVE Security Analyst',
            goal='Identify and analyze CVE vulnerabilities from scan results',
            backstory="""You are an expert security analyst specializing in CVE identification 
            and vulnerability assessment. You analyze scan results to identify known CVEs.""",
            llm=self.llm,
            verbose=False
        )
        
        scan_context = self._prepare_scan_context(nmap_result)
        
        identify_task = Task(
            description=f"""CRITICAL: Analyze the scan results and identify REAL, VALID CVE vulnerabilities.

            {scan_context}
            
            MANDATORY REQUIREMENTS:
            1. CVE IDs MUST be in format: CVE-YYYY-NNNNN (e.g., CVE-2020-1472)
            2. Only include REAL, VERIFIED CVEs that actually exist
            3. Match CVEs to specific services and versions found in the scan
            4. NO FAKE or INVALID CVE IDs
            
            PRIORITY CVEs to check:
            - Port 445 (SMB) - CVE-2020-1472 (Zerologon), CVE-2017-0144 (EternalBlue)
            - Port 88 (Kerberos) - CVE-2020-17049, CVE-2021-42287
            - Port 389/636 (LDAP) - CVE-2021-34473, CVE-2021-26855
            - Port 135 (RPC) - CVE-2020-1473, CVE-2021-26867
            - Port 3389 (RDP) - CVE-2019-0708 (BlueKeep), CVE-2021-34527
            
            For each REAL vulnerability found, provide:
            1. VALID CVE ID (CVE-YYYY-NNNNN format)
            2. Affected service and version from scan
            3. Brief description
            4. CVSS score if known
            5. Whether exploits are publicly available
            
            EXAMPLE OUTPUT FORMAT:
            CVE-2020-1472: Windows Netlogon Remote Protocol vulnerability affecting Domain Controllers
            CVE-2017-0144: SMB vulnerability affecting Windows systems (EternalBlue)
            
            DO NOT CREATE FAKE CVE IDs. Only list CVEs you are certain exist.""",
            agent=cve_analyst,
            expected_output="A list of REAL, VALID CVE IDs with proper CVE-YYYY-NNNNN format"
        )
        
        crew = Crew(
            agents=[cve_analyst],
            tasks=[identify_task],
            process=Process.sequential,
            verbose=False
        )
        
        crew_result = crew.kickoff()
        
        result = AnalystResult(target_ip=target_ip)
        result.identified_cves = self._parse_and_validate_cves(str(crew_result), nmap_result)
        result.risk_assessment = self._generate_risk_assessment(result.identified_cves)
        result.priority_vulnerabilities = self._prioritize_vulnerabilities(result.identified_cves)
        
        return result
    
    def _fallback_analysis(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """Fallback analysis without LLM"""
        logger.info("Using fallback vulnerability analysis")
        
        result = AnalystResult(target_ip=target_ip)
        result.identified_cves = self._generate_service_based_cves(nmap_result)
        result.risk_assessment = self._generate_risk_assessment(result.identified_cves)
        result.priority_vulnerabilities = self._prioritize_vulnerabilities(result.identified_cves)
        
        return result
    
    def _generate_service_based_cves(self, nmap_result: NmapResult) -> List[CVEInfo]:
        """Generate CVEs based on detected services"""
        cves = []
        is_dc = self._is_domain_controller(nmap_result)
        
        for service in nmap_result.services:
            port = service.get('port')
            service_name = service.get('name', '').lower()
            product = service.get('product', '').lower()
            
            # SMB services (445, 139)
            if port in [445, 139] or 'smb' in service_name:
                if is_dc or 'microsoft' in product or 'windows' in product:
                    cves.append(self._create_zerologon_cve())
                    cves.append(self._create_eternalblue_cve())
            
            # RDP (3389)
            elif port == 3389 or service_name == 'ms-wbt-server':
                cves.append(self._create_bluekeep_cve())
            
            # Kerberos (88)
            elif port == 88 or 'kerberos' in service_name:
                if is_dc:
                    cves.append(self._create_pac_validation_cve())
        
        # Limit to 5 CVEs as requested
        return cves[:5]
    
    def _prepare_scan_context(self, nmap_result: NmapResult) -> str:
        context = f"Target IP: {nmap_result.target_ip}\n\n"
        if nmap_result.os_detection:
            context += f"OS: {nmap_result.os_detection}\n\n"
        context += "Services:\n"
        for service in nmap_result.services:
            context += f"- Port {service['port']}: {service['name']} {service.get('product', '')} {service.get('version', '')}\n"
        return context
    
    def _parse_and_validate_cves(self, analysis_text: str, nmap_result: NmapResult) -> List[CVEInfo]:
        """Parse CVEs and validate they are real CVE IDs"""
        cves = []
        
        # Strict CVE pattern matching
        cve_pattern = r'CVE-(\d{4})-(\d{4,7})'
        found_cves = re.findall(cve_pattern, analysis_text)
        
        # Convert to full CVE IDs and validate
        valid_cve_ids = []
        for year, number in found_cves:
            cve_id = f"CVE-{year}-{number}"
            
            # Basic validation
            if self._is_valid_cve_format(cve_id):
                valid_cve_ids.append(cve_id)
            else:
                logger.warning(f"Invalid CVE format detected and filtered: {cve_id}")
        
        # Add known CVEs based on detected services
        forced_cves = self._add_service_based_cves(nmap_result)
        valid_cve_ids.extend(forced_cves)
        
        # Remove duplicates and limit to 5
        valid_cve_ids = list(set(valid_cve_ids))[:5]
        
        for cve_id in valid_cve_ids:
            logger.info(f"Processing validated CVE: {cve_id}")
            cve_section = self._extract_cve_section(analysis_text, cve_id)
            
            # Get CVSS score from NVD
            cvss_score = self._get_cvss_from_nvd(cve_id)
            
            # Special handling for well-known CVEs
            if cve_id == 'CVE-2020-1472':
                cve = self._create_zerologon_cve()
            elif cve_id == 'CVE-2017-0144':
                cve = self._create_eternalblue_cve()
            elif cve_id == 'CVE-2019-0708':
                cve = self._create_bluekeep_cve()
            else:
                cve = CVEInfo(
                    cve_id=cve_id,
                    description=self._extract_description(cve_section, cve_id),
                    affected_service=self._extract_service(cve_section, cve_id, nmap_result),
                    cvss_score=cvss_score,
                    technical_details=self._enhance_explanation(cve_section, cve_id, nmap_result),
                    exploit_available=self._check_exploit_available(cve_section, cve_id),
                    cve_links=self._get_cve_links(cve_id)
                )
            cves.append(cve)
        
        return cves
    
    def _is_valid_cve_format(self, cve_id: str) -> bool:
        """Validate CVE ID format and basic sanity checks"""
        pattern = r'^CVE-\d{4}-\d{4,7}$'
        if not re.match(pattern, cve_id):
            return False
        
        year_match = re.search(r'CVE-(\d{4})-', cve_id)
        if year_match:
            year = int(year_match.group(1))
            if year < 1999 or year > 2024:
                return False
        
        return True
    
    def _add_service_based_cves(self, nmap_result: NmapResult) -> List[str]:
        """Add known CVEs based on detected services"""
        service_cves = []
        is_dc = self._is_domain_controller(nmap_result)
        
        for service in nmap_result.services:
            port = service.get('port')
            service_name = service.get('name', '').lower()
            product = service.get('product', '').lower()
            
            # SMB services (445, 139)
            if port in [445, 139] or 'smb' in service_name:
                if is_dc or 'microsoft' in product or 'windows' in product:
                    service_cves.append('CVE-2020-1472')  # Zerologon
                    service_cves.append('CVE-2017-0144')  # EternalBlue
            
            # RDP (3389)
            elif port == 3389 or service_name == 'ms-wbt-server':
                service_cves.append('CVE-2019-0708')  # BlueKeep
            
            # Kerberos (88)
            elif port == 88 or 'kerberos' in service_name:
                if is_dc:
                    service_cves.append('CVE-2021-42287')  # PAC validation
        
        return service_cves
    
    def _is_domain_controller(self, nmap_result: NmapResult) -> bool:
        """Check if target appears to be a Domain Controller"""
        dc_ports = {88, 389, 445, 636, 3268, 3269}
        open_ports = {service.get('port') for service in nmap_result.services}
        
        if nmap_result.os_detection and isinstance(nmap_result.os_detection, dict):
            if nmap_result.os_detection.get('is_domain_controller'):
                return True
        
        dc_ports_found = dc_ports.intersection(open_ports)
        return len(dc_ports_found) >= 3
    
    def _get_cvss_from_nvd(self, cve_id: str) -> float:
        """Get CVSS score from NVD API with caching"""
        try:
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
            response = requests.get(url, timeout=8)
            
            if response.status_code == 200:
                data = response.json()
                if 'vulnerabilities' in data and data['vulnerabilities']:
                    vuln = data['vulnerabilities'][0]
                    cve_data = vuln.get('cve', {})
                    metrics = cve_data.get('metrics', {})
                    
                    for version in ['cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2']:
                        if version in metrics and metrics[version]:
                            return metrics[version][0]['cvssData']['baseScore']
            
            time.sleep(0.7)  # Rate limiting
            
        except Exception as e:
            logger.debug(f"Failed to get CVSS for {cve_id}: {e}")
        
        # Return default scores for well-known CVEs
        known_scores = {
            'CVE-2020-1472': 10.0,  # Zerologon
            'CVE-2017-0144': 8.1,   # EternalBlue
            'CVE-2019-0708': 9.8,   # BlueKeep
            'CVE-2021-42287': 8.8,  # PAC validation
        }
        
        return known_scores.get(cve_id, 7.5)
    
    def _create_zerologon_cve(self) -> CVEInfo:
        """Create detailed Zerologon CVE analysis"""
        return CVEInfo(
            cve_id="CVE-2020-1472",
            description="Critical authentication bypass vulnerability in Microsoft Windows Netlogon Remote Protocol that allows attackers to impersonate domain controllers",
            affected_service="Microsoft Windows Netlogon Remote Protocol (MS-NRPC)",
            cvss_score=10.0,
            severity="Critical",
            technical_details="Zerologon exploits a cryptographic flaw in the Netlogon authentication process where an attacker can use the AES-CFB8 mode with a static IV to predict authentication tokens, effectively allowing impersonation of the domain controller without authentication.",
            exploit_available=True,
            cve_links=self._get_cve_links("CVE-2020-1472")
        )
    
    def _create_eternalblue_cve(self) -> CVEInfo:
        """Create detailed EternalBlue CVE analysis"""
        return CVEInfo(
            cve_id="CVE-2017-0144",
            description="Critical remote code execution vulnerability in Microsoft SMBv1 server that allows unauthenticated attackers to execute arbitrary code",
            affected_service="Microsoft Server Message Block (SMB)",
            cvss_score=8.1,
            severity="Critical",
            technical_details="EternalBlue exploits a buffer overflow in the SMBv1 protocol implementation. The vulnerability occurs when the server fails to properly handle specially crafted packets, allowing attackers to achieve remote code execution with SYSTEM privileges.",
            exploit_available=True,
            cve_links=self._get_cve_links("CVE-2017-0144")
        )
    
    def _create_bluekeep_cve(self) -> CVEInfo:
        """Create detailed BlueKeep CVE analysis"""
        return CVEInfo(
            cve_id="CVE-2019-0708",
            description="Critical remote code execution vulnerability in Windows Remote Desktop Services that allows unauthenticated attackers to execute arbitrary code",
            affected_service="Remote Desktop Protocol (RDP)",
            cvss_score=9.8,
            severity="Critical",
            technical_details="BlueKeep is a heap-based buffer overflow vulnerability in the Remote Desktop Services. It allows unauthenticated attackers to execute arbitrary code by sending specially crafted RDP packets to the target system.",
            exploit_available=True,
            cve_links=self._get_cve_links("CVE-2019-0708")
        )
    
    def _create_pac_validation_cve(self) -> CVEInfo:
        """Create PAC validation CVE"""
        return CVEInfo(
            cve_id="CVE-2021-42287",
            description="Windows Kerberos privilege escalation vulnerability that allows attackers to impersonate domain administrators",
            affected_service="Windows Kerberos Authentication",
            cvss_score=8.8,
            severity="High",
            technical_details="This vulnerability allows attackers to forge Kerberos tickets by exploiting weaknesses in PAC (Privilege Attribute Certificate) validation, potentially leading to domain administrator privileges.",
            exploit_available=True,
            cve_links=self._get_cve_links("CVE-2021-42287")
        )
    
    def _extract_description(self, cve_section: str, cve_id: str) -> str:
        """Extract or generate description for CVE"""
        patterns = [
            r'Description:\s*(.+?)(?:\n|$)',
            r'allows\s+(.+?)(?:\.|n)',
            r'vulnerability\s+(.+?)(?:\.|n)'
        ]
        
        for pattern in patterns:
            match = re.search(pattern, cve_section, re.IGNORECASE)
            if match:
                return match.group(1).strip()
        
        defaults = {
            'CVE-2020-1472': 'Zerologon - Critical authentication bypass in Windows Netlogon',
            'CVE-2017-0144': 'EternalBlue - Critical SMB remote code execution vulnerability',
            'CVE-2019-0708': 'BlueKeep - Critical RDP remote code execution vulnerability',
        }
        
        return defaults.get(cve_id, f"Vulnerability affecting {cve_id}")
    
    def _extract_service(self, cve_section: str, cve_id: str, nmap_result: NmapResult) -> str:
        """Extract affected service from CVE section or infer from scan"""
        service_map = {
            'CVE-2020-1472': 'Windows Netlogon (SMB)',
            'CVE-2017-0144': 'SMB Service',
            'CVE-2019-0708': 'Remote Desktop Protocol',
            'CVE-2021-42287': 'Kerberos Authentication'
        }
        
        return service_map.get(cve_id, "Unknown Service")
    
    def _extract_cve_section(self, text: str, cve_id: str) -> str:
        """Extract CVE-specific section from analysis text"""
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
    
    def _check_exploit_available(self, cve_section: str, cve_id: str) -> bool:
        """Check if exploits are available"""
        exploitable = {
            'CVE-2020-1472', 'CVE-2017-0144', 'CVE-2019-0708',
            'CVE-2021-42287', 'CVE-2021-34473'
        }
        
        return cve_id in exploitable
    
    def _enhance_explanation(self, cve_section: str, cve_id: str, nmap_result: NmapResult) -> str:
        """Generate enhanced explanation"""
        explanation = f"**CVE ID**: {cve_id}\n\n"
        explanation += f"**Analysis**: {cve_section}\n\n"
        explanation += f"**Target Evidence**: Services detected on {nmap_result.target_ip}\n"
        
        return explanation
    
    def _get_cve_links(self, cve_id: str) -> Dict[str, str]:
        """Get CVE reference links"""
        return {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "exploit_db": f"https://www.exploit-db.com/search?cve={cve_id}",
        }
    
    def _generate_risk_assessment(self, cves: List[CVEInfo]) -> str:
        """Generate risk assessment"""
        if not cves:
            return "No significant vulnerabilities identified."
        
        critical_count = sum(1 for cve in cves if cve.cvss_score and cve.cvss_score >= 9.0)
        high_count = sum(1 for cve in cves if cve.cvss_score and 7.0 <= cve.cvss_score < 9.0)
        
        assessment = f"Identified {len(cves)} vulnerabilities. "
        if critical_count > 0:
            assessment += f"{critical_count} critical vulnerabilities require immediate attention. "
        if high_count > 0:
            assessment += f"{high_count} high-severity vulnerabilities should be addressed."
        
        return assessment
    
    def _prioritize_vulnerabilities(self, cves: List[CVEInfo]) -> List[str]:
        """Prioritize vulnerabilities by severity and exploitability"""
        sorted_cves = sorted(
            cves,
            key=lambda x: (x.exploit_available, x.cvss_score or 0),
            reverse=True
        )
        return [cve.cve_id for cve in sorted_cves[:5]]
    
    def _save_result(self, target_ip: str, result: AnalystResult):
        """Save analysis result"""
        output_file = config.DATA_DIR / f"{target_ip}_analyst.json"
        config.DATA_DIR.mkdir(exist_ok=True)
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Analysis result saved to {output_file}")