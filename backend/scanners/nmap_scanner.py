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
        logger.info(f"Starting Nmap scan for {target_ip}")
        
        result = NmapResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            scan_args = '-sV -O -sC --version-intensity 5'
            logger.info(f"Running: nmap {scan_args} {target_ip}")
            
            self.nm.scan(target_ip, arguments=scan_args)
            logger.info(f"Scan completed. Found hosts: {self.nm.all_hosts()}")
            
            if target_ip in self.nm.all_hosts():
                host = self.nm[target_ip]
                logger.info(f"Host {target_ip} is up")
                
                result.open_ports = self._extract_ports(host)
                logger.info(f"Found {len(result.open_ports)} open ports")
                
                result.services = self._extract_services(host)
                logger.info(f"Identified {len(result.services)} services")
                
                if 'osmatch' in host:
                    result.os_detection = self._extract_os_info(host)
                    logger.info(f"OS Detection: {result.os_detection.get('name', 'Unknown')}")
                
                logger.info("Running vulnerability scan...")
                vuln_scan = self._run_vuln_scan(target_ip)
                result.vulnerabilities = self._parse_vulnerabilities(vuln_scan)
                logger.info(f"Found {len(result.vulnerabilities)} vulnerabilities")
                
                result.raw_output = str(self.nm[target_ip])
                result.status = StepStatus.COMPLETED
                logger.info("Nmap scan completed successfully")
                
            else:
                result.status = StepStatus.FAILED
                logger.warning(f"Host {target_ip} appears to be down")
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}", exc_info=True)
            result.status = StepStatus.FAILED
        
        self._save_result(target_ip, result)
        return result
    
    def _extract_ports(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
        ports = []
        if 'tcp' in host:
            for port, info in host['tcp'].items():
                port_info = {
                    "port": port,
                    "state": info.get('state'),
                    "service": info.get('name'),
                    "product": info.get('product', ''),
                    "version": info.get('version', '')
                }
                ports.append(port_info)
                logger.info(f"  Port {port}: {info.get('name')} - {info.get('product', '')}")
        return ports
    
    def _extract_services(self, host: Dict[str, Any]) -> List[Dict[str, Any]]:
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
        try:
            cmd = [config.NMAP_CMD, '-sV', '--script', 'vuln', target_ip]
            logger.info(f"Running: {' '.join(cmd)}")
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            return result.stdout
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return ""
    
    def _parse_vulnerabilities(self, vuln_output: str) -> List[Dict[str, Any]]:
        vulnerabilities = []
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cves = re.findall(cve_pattern, vuln_output)
        
        for cve in set(cves):
            context = self._extract_cve_context(vuln_output, cve)
            vuln = {
                "cve_id": cve,
                "context": context,
                "severity": self._estimate_severity(context)
            }
            vulnerabilities.append(vuln)
            logger.info(f"  Found CVE: {cve}")
        
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
        lines = output.split('\n')
        context_lines = []
        for i, line in enumerate(lines):
            if cve in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                context_lines = lines[start:end]
                break
        return ' '.join(context_lines)
    
    def _estimate_severity(self, context: str) -> str:
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
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Nmap result saved to {output_file}")
