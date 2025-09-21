import json
import nmap
import subprocess
import re
from typing import Dict, Any, List
from datetime import datetime
from backend.models import NmapResult, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()
    
    def scan(self, target_ip: str) -> NmapResult:
        """Perform comprehensive Nmap scan"""
        logger.info(f"Starting Nmap scan for {target_ip}")
        
        result = NmapResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Service detection and OS fingerprinting
            logger.info("Running service detection scan...")
            self.nm.scan(target_ip, arguments='-sV -O -sC --version-intensity 5')
            
            if target_ip in self.nm.all_hosts():
                host = self.nm[target_ip]
                
                # Extract open ports and services
                result.open_ports = self._extract_ports(host)
                result.services = self._extract_services(host)
                
                # OS detection
                if 'osmatch' in host:
                    result.os_detection = self._extract_os_info(host)
                
                # Run vulnerability scan
                logger.info("Running vulnerability scan...")
                vuln_scan = self._run_vuln_scan(target_ip)
                result.vulnerabilities = self._parse_vulnerabilities(vuln_scan)
                
                result.raw_output = str(self.nm[target_ip])
                result.status = StepStatus.COMPLETED
                
            else:
                result.status = StepStatus.FAILED
                logger.warning(f"Host {target_ip} appears to be down or not responding")
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            result.status = StepStatus.FAILED
        
        # Save result to JSON
        self._save_result(target_ip, result)
        return result
    
    def _extract_ports(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract open ports information"""
        ports = []
        
        if 'tcp' in host:
            for port, info in host['tcp'].items():
                ports.append({
                    "port": port,
                    "state": info.get('state'),
                    "service": info.get('name'),
                    "product": info.get('product', ''),
                    "version": info.get('version', '')
                })
        
        return ports
    
    def _extract_services(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract detailed service information"""
        services = []
        
        if 'tcp' in host:
            for port, info in host['tcp'].items():
                service = {
                    "port": port,
                    "protocol": "tcp",
                    "name": info.get('name'),
                    "product": info.get('product', ''),
                    "version": info.get('version', ''),
                    "extrainfo": info.get('extrainfo', ''),
                    "cpe": info.get('cpe', '')
                }
                services.append(service)
        
        return services
    
    def _extract_os_info(self, host: Dict[str, Any]) -> Dict[str, Any]:
        """Extract OS detection information"""
        os_info = {}
        
        if 'osmatch' in host and host['osmatch']:
            best_match = host['osmatch'][0]
            os_info = {
                "name": best_match.get('name'),
                "accuracy": best_match.get('accuracy'),
                "family": best_match.get('osclass', [{}])[0].get('osfamily') if best_match.get('osclass') else None,
                "vendor": best_match.get('osclass', [{}])[0].get('vendor') if best_match.get('osclass') else None
            }
        
        return os_info
    
    def _run_vuln_scan(self, target_ip: str) -> str:
        """Run Nmap vulnerability scripts"""
        try:
            cmd = [
                config.NMAP_CMD,
                '-sV',
                '--script', 'vuln',
                target_ip
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return ""
    
    def _parse_vulnerabilities(self, vuln_output: str) -> List[Dict[str, Any]]:
        """Parse vulnerability scan output"""
        vulnerabilities = []
        
        # Parse CVE references
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cves = re.findall(cve_pattern, vuln_output)
        
        for cve in set(cves):
            # Extract context around CVE
            context = self._extract_cve_context(vuln_output, cve)
            vulnerabilities.append({
                "cve_id": cve,
                "context": context,
                "severity": self._estimate_severity(context)
            })
        
        # Parse script output for known vulnerabilities
        script_pattern = r'\|(.*?):.*?VULNERABLE'
        vulnerable_scripts = re.findall(script_pattern, vuln_output, re.MULTILINE)
        
        for script in vulnerable_scripts:
            if not any(v.get('description') == script for v in vulnerabilities):
                vulnerabilities.append({
                    "description": script.strip(),
                    "type": "script_detection",
                    "severity": "unknown"
                })
        
        return vulnerabilities
    
    def _extract_cve_context(self, output: str, cve: str) -> str:
        """Extract context around CVE mention"""
        lines = output.split('\n')
        context_lines = []
        
        for i, line in enumerate(lines):
            if cve in line:
                # Get surrounding lines
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context_lines = lines[start:end]
                break
        
        return ' '.join(context_lines)
    
    def _estimate_severity(self, context: str) -> str:
        """Estimate severity from context"""
        context_lower = context.lower()
        
        if any(word in context_lower for word in ['critical', 'remote code execution', 'rce']):
            return 'critical'
        elif any(word in context_lower for word in ['high', 'authentication bypass', 'privilege escalation']):
            return 'high'
        elif any(word in context_lower for word in ['medium', 'denial of service', 'dos']):
            return 'medium'
        elif any(word in context_lower for word in ['low', 'information disclosure']):
            return 'low'
        else:
            return 'unknown'
    
    def _save_result(self, target_ip: str, result: NmapResult):
        """Save Nmap result to JSON file"""
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Nmap result saved to {output_file}")
