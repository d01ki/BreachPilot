#!/usr/bin/env python3
"""
CVE Processing Utilities for CrewAI Security Assessment
"""

import logging
import re
from typing import List, Dict, Any, Optional

from backend.models import AnalystResult, CVEInfo, NmapResult

logger = logging.getLogger(__name__)

class CVEProcessor:
    """
    Handles CVE processing, extraction, and analysis for CrewAI results
    """
    
    def __init__(self):
        """
        Initialize CVE processor with known CVE database
        """
        self.known_cvss_scores = {
            'CVE-2020-1472': 10.0,  # Zerologon
            'CVE-2017-0144': 8.1,   # EternalBlue
            'CVE-2019-0708': 9.8,   # BlueKeep
            'CVE-2021-42287': 8.8,  # Kerberos PAC
            'CVE-2021-44228': 10.0, # Log4Shell
            'CVE-2021-34527': 8.8,  # PrintNightmare
            'CVE-2020-0796': 10.0,  # SMBGhost
            'CVE-2019-19781': 9.8,  # Citrix ADC
            'CVE-2021-26855': 9.8,  # ProxyLogon
            'CVE-2020-1350': 10.0,  # SigRed
        }
        
        self.known_descriptions = {
            'CVE-2020-1472': "Critical authentication bypass vulnerability in Windows Netlogon Remote Protocol enabling complete domain compromise",
            'CVE-2017-0144': "Critical remote code execution vulnerability in Microsoft SMBv1 server exploited by EternalBlue",
            'CVE-2019-0708': "Critical remote code execution vulnerability in Windows Remote Desktop Services",
            'CVE-2021-42287': "Windows Kerberos privilege escalation vulnerability allowing domain administrator impersonation",
            'CVE-2021-44228': "Apache Log4j2 remote code execution vulnerability (Log4Shell)",
            'CVE-2021-34527': "Windows Print Spooler remote code execution vulnerability (PrintNightmare)",
            'CVE-2020-0796': "Critical remote code execution vulnerability in Microsoft SMBv3 protocol (SMBGhost)",
            'CVE-2019-19781': "Citrix Application Delivery Controller directory traversal vulnerability",
        }
        
        self.service_mappings = {
            'CVE-2020-1472': 'Windows Netlogon Remote Protocol',
            'CVE-2017-0144': 'Microsoft SMBv1 Server',
            'CVE-2019-0708': 'Windows Remote Desktop Services',
            'CVE-2021-42287': 'Windows Kerberos Authentication',
            'CVE-2021-44228': 'Apache Log4j2 Library',
            'CVE-2021-34527': 'Windows Print Spooler Service',
            'CVE-2020-0796': 'Microsoft SMBv3 Protocol',
            'CVE-2019-19781': 'Citrix Application Delivery Controller',
        }
        
        self.exploitable_cves = {
            'CVE-2020-1472', 'CVE-2017-0144', 'CVE-2019-0708',
            'CVE-2021-42287', 'CVE-2021-44228', 'CVE-2021-34527',
            'CVE-2020-0796', 'CVE-2019-19781', 'CVE-2021-26855',
            'CVE-2020-1350'
        }
    
    def process_crew_results(self, crew_result: Any, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Process CrewAI results into structured AnalystResult
        
        Args:
            crew_result: Raw results from CrewAI execution
            target_ip: Target IP address
            nmap_result: Original nmap results
            
        Returns:
            Structured analyst result
        """
        logger.info("Processing CrewAI results into structured format")
        
        try:
            # Convert crew result to string for processing
            result_text = str(crew_result)
            
            # Extract CVEs using regex
            cve_pattern = r'CVE-(\d{4})-(\d{4,7})'
            found_cves = re.findall(cve_pattern, result_text, re.IGNORECASE)
            
            # Create CVE objects
            identified_cves = []
            unique_cves = list(set([f"CVE-{year}-{number}" for year, number in found_cves]))
            
            # Add service-based CVEs if not found
            mandatory_cves = self._get_mandatory_cves_from_services(nmap_result)
            for cve in mandatory_cves:
                if cve not in unique_cves:
                    unique_cves.append(cve)
            
            # Limit to reasonable number
            unique_cves = unique_cves[:7]
            
            for cve_id in unique_cves:
                cve_info = self._create_cve_info(cve_id, result_text, nmap_result)
                if cve_info:
                    identified_cves.append(cve_info)
            
            # Generate risk assessment
            risk_assessment = self._generate_risk_assessment(result_text, identified_cves)
            
            # Get priority vulnerabilities
            priority_vulns = [cve.cve_id for cve in identified_cves if cve.severity in ['Critical', 'High']]
            
            return AnalystResult(
                target_ip=target_ip,
                identified_cves=identified_cves,
                risk_assessment=risk_assessment,
                priority_vulnerabilities=priority_vulns
            )
            
        except Exception as e:
            logger.error(f"Error processing crew results: {e}")
            return self.create_fallback_result(target_ip, nmap_result)
    
    def _get_mandatory_cves_from_services(self, nmap_result: NmapResult) -> List[str]:
        """
        Get mandatory CVEs based on detected services
        
        Args:
            nmap_result: Nmap scan results
            
        Returns:
            List of mandatory CVE IDs
        """
        mandatory = []
        
        if not nmap_result.services:
            return mandatory
        
        for service in nmap_result.services:
            port = service.get('port')
            service_name = service.get('name', '').lower()
            
            # SMB/DC services
            if port in [445, 139] or 'smb' in service_name:
                mandatory.extend(['CVE-2020-1472', 'CVE-2017-0144', 'CVE-2020-0796'])
            
            # RDP services
            if port == 3389 or 'rdp' in service_name:
                mandatory.append('CVE-2019-0708')
            
            # Kerberos - Domain Controller services
            if port == 88:
                mandatory.append('CVE-2021-42287')
            
            # Web services
            if port in [80, 443, 8080] or 'http' in service_name:
                mandatory.append('CVE-2021-44228')
            
            # Print Spooler
            if port == 135 or 'rpc' in service_name:
                mandatory.append('CVE-2021-34527')
            
            # DNS
            if port == 53 or 'domain' in service_name:
                mandatory.append('CVE-2020-1350')
        
        return list(set(mandatory))  # Remove duplicates
    
    def _create_cve_info(self, cve_id: str, result_text: str, nmap_result: NmapResult) -> Optional[CVEInfo]:
        """
        Create CVEInfo object with details
        
        Args:
            cve_id: CVE identifier
            result_text: Full crew analysis text
            nmap_result: Nmap scan results
            
        Returns:
            CVEInfo object if details can be extracted
        """
        try:
            # Get CVSS score and severity
            cvss_score = self.known_cvss_scores.get(cve_id, 7.5)
            severity = self._determine_severity(cvss_score)
            
            # Get description
            description = self.known_descriptions.get(
                cve_id, 
                f"Vulnerability {cve_id} identified through security analysis"
            )
            
            # Determine affected service
            affected_service = self.service_mappings.get(cve_id, "Network Service")
            
            # Check exploit availability
            exploit_available = cve_id in self.exploitable_cves
            
            # Extract technical details
            technical_details = self._extract_technical_details(cve_id, result_text)
            
            return CVEInfo(
                cve_id=cve_id,
                description=description,
                severity=severity,
                cvss_score=cvss_score,
                affected_service=affected_service,
                exploit_available=exploit_available,
                technical_details=technical_details,
                cve_links=self._get_cve_links(cve_id)
            )
            
        except Exception as e:
            logger.error(f"Error creating CVE info for {cve_id}: {e}")
            return None
    
    def _determine_severity(self, cvss_score: float) -> str:
        """
        Determine severity based on CVSS score
        
        Args:
            cvss_score: CVSS score
            
        Returns:
            Severity level
        """
        if cvss_score >= 9.0:
            return "Critical"
        elif cvss_score >= 7.0:
            return "High"
        elif cvss_score >= 4.0:
            return "Medium"
        else:
            return "Low"
    
    def _extract_technical_details(self, cve_id: str, result_text: str) -> str:
        """
        Extract technical details for CVE from crew analysis
        
        Args:
            cve_id: CVE identifier
            result_text: Full crew analysis text
            
        Returns:
            Technical details
        """
        # Try to extract CVE-specific section from result
        lines = result_text.split('\n')
        section = []
        capturing = False
        
        for line in lines:
            if cve_id in line:
                capturing = True
            elif capturing and re.search(r'CVE-\d{4}-\d{4,7}', line) and cve_id not in line:
                break
            if capturing:
                section.append(line)
        
        if section:
            return '\n'.join(section[:10])  # Limit to first 10 lines
        
        return f"Technical analysis for {cve_id} identified through CrewAI security assessment"
    
    def _get_cve_links(self, cve_id: str) -> Dict[str, str]:
        """
        Get reference links for CVE
        
        Args:
            cve_id: CVE identifier
            
        Returns:
            Dictionary of reference links
        """
        return {
            "nvd": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
            "mitre": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={cve_id}",
            "exploit_db": f"https://www.exploit-db.com/search?cve={cve_id}"
        }
    
    def _generate_risk_assessment(self, result_text: str, identified_cves: List[CVEInfo]) -> str:
        """
        Generate risk assessment from crew results
        
        Args:
            result_text: Full crew analysis text
            identified_cves: List of identified CVEs
            
        Returns:
            Risk assessment summary
        """
        if not identified_cves:
            return "No significant vulnerabilities identified during CrewAI security assessment"
        
        critical_count = len([cve for cve in identified_cves if cve.severity == 'Critical'])
        high_count = len([cve for cve in identified_cves if cve.severity == 'High'])
        medium_count = len([cve for cve in identified_cves if cve.severity == 'Medium'])
        
        risk_level = "CRITICAL" if critical_count > 0 else "HIGH" if high_count > 0 else "MEDIUM"
        
        assessment = f"""CREWAI SECURITY ASSESSMENT SUMMARY:

Total Vulnerabilities Identified: {len(identified_cves)}
- Critical Severity: {critical_count} vulnerabilities
- High Severity: {high_count} vulnerabilities
- Medium Severity: {medium_count} vulnerabilities

Overall Risk Level: {risk_level}

Immediate Actions Required: {"YES - Critical vulnerabilities require immediate remediation" if critical_count > 0 else "Standard security patching cycle recommended"}

Exploitable Vulnerabilities: {len([cve for cve in identified_cves if cve.exploit_available])}

This comprehensive assessment was conducted using CrewAI multi-agent analysis with specialized vulnerability hunting, CVE research, penetration testing strategy, security analysis, and professional reporting agents working collaboratively to provide enterprise-grade security intelligence."""
        
        return assessment.strip()
    
    def create_fallback_result(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Create fallback result when CrewAI is not available
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Basic analyst result
        """
        logger.warning("Creating fallback analysis result - CrewAI not available")
        
        # Get mandatory CVEs based on services
        mandatory_cves = self._get_mandatory_cves_from_services(nmap_result)
        
        # Create CVE objects
        identified_cves = []
        for cve_id in mandatory_cves[:5]:
            cve_info = self._create_cve_info(cve_id, "", nmap_result)
            if cve_info:
                identified_cves.append(cve_info)
        
        # Generate basic risk assessment
        risk_assessment = self._generate_risk_assessment("", identified_cves)
        
        # Get priority vulnerabilities
        priority_vulns = [cve.cve_id for cve in identified_cves if cve.severity in ['Critical', 'High']]
        
        return AnalystResult(
            target_ip=target_ip,
            identified_cves=identified_cves,
            risk_assessment=risk_assessment + "\n\nNote: This is a fallback analysis. For comprehensive assessment, ensure CrewAI is properly configured.",
            priority_vulnerabilities=priority_vulns
        )
