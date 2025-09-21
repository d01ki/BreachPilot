import json
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
        pass
    
    def scan(self, target_ip: str) -> NmapResult:
        logger.info(f"="*50)
        logger.info(f"Starting Nmap scan for {target_ip}")
        logger.info(f"="*50)
        
        result = NmapResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Run nmap command directly (no root required)
            cmd = ['nmap', '-sC', '-sV', target_ip]
            logger.info(f"Executing: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            output = process.stdout
            logger.info("Nmap command completed")
            logger.info(f"Output length: {len(output)} characters")
            
            if output:
                # Parse the output
                result.raw_output = output
                result.open_ports = self._parse_ports(output)
                result.services = self._parse_services(output)
                result.os_detection = self._parse_os(output)
                
                logger.info(f"Found {len(result.open_ports)} open ports")
                for port in result.open_ports:
                    logger.info(f"  Port {port['port']}: {port['service']} - {port['product']}")
                
                # Run vulnerability scan
                logger.info("Running vulnerability scan...")
                vuln_output = self._run_vuln_scan(target_ip)
                result.vulnerabilities = self._parse_vulnerabilities(vuln_output)
                logger.info(f"Found {len(result.vulnerabilities)} vulnerabilities")
                
                result.status = StepStatus.COMPLETED
                logger.info("Scan completed successfully")
            else:
                logger.warning("No output from nmap")
                result.status = StepStatus.FAILED
                
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timeout")
            result.status = StepStatus.FAILED
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}", exc_info=True)
            result.status = StepStatus.FAILED
        
        # Save result to JSON
        self._save_result(target_ip, result)
        logger.info(f"="*50)
        
        return result
    
    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        """Parse open ports from nmap output"""
        ports = []
        lines = output.split('\n')
        
        for line in lines:
            # Match lines like: 22/tcp   open  ssh     OpenSSH 8.2p1
            match = re.match(r'(\d+)/tcp\s+(open|filtered|closed)\s+(\S+)\s*(.*)', line)
            if match:
                port_num = match.group(1)
                state = match.group(2)
                service = match.group(3)
                details = match.group(4).strip()
                
                if state == 'open':
                    ports.append({
                        'port': int(port_num),
                        'state': state,
                        'service': service,
                        'product': details
                    })
        
        return ports
    
    def _parse_services(self, output: str) -> List[Dict[str, Any]]:
        """Parse service information from nmap output"""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            match = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if match:
                port_num = match.group(1)
                service_name = match.group(2)
                details = match.group(3).strip()
                
                # Extract product and version
                product = ''
                version = ''
                if details:
                    parts = details.split()
                    if parts:
                        product = parts[0]
                        if len(parts) > 1:
                            version = parts[1]
                
                services.append({
                    'port': int(port_num),
                    'protocol': 'tcp',
                    'name': service_name,
                    'product': product,
                    'version': version,
                    'extrainfo': details,
                    'cpe': ''
                })
        
        return services
    
    def _parse_os(self, output: str) -> Dict[str, Any]:
        """Parse OS detection from nmap output"""
        os_info = {}
        lines = output.split('\n')
        
        for i, line in enumerate(lines):
            if 'OS details:' in line or 'Running:' in line:
                os_info = {
                    'name': line.split(':', 1)[1].strip() if ':' in line else '',
                    'accuracy': 100,
                    'family': None,
                    'vendor': None
                }
                break
        
        return os_info if os_info else None
    
    def _run_vuln_scan(self, target_ip: str) -> str:
        """Run vulnerability scan"""
        try:
            cmd = ['nmap', '-sV', '--script', 'vuln', target_ip]
            logger.info(f"Running vulnerability scan: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            return process.stdout
        except Exception as e:
            logger.error(f"Vulnerability scan failed: {e}")
            return ''
    
    def _parse_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities from nmap vuln script output"""
        vulnerabilities = []
        
        # Find CVEs
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cves = re.findall(cve_pattern, output)
        
        for cve in set(cves):
            vulnerabilities.append({
                'cve_id': cve,
                'context': self._extract_cve_context(output, cve),
                'severity': 'unknown'
            })
            logger.info(f"  Found CVE: {cve}")
        
        # Find VULNERABLE markers
        vuln_pattern = r'\|\s+(.+?):\s+VULNERABLE'
        vuln_matches = re.findall(vuln_pattern, output)
        
        for vuln in vuln_matches:
            vulnerabilities.append({
                'description': vuln.strip(),
                'type': 'script_detection',
                'severity': 'unknown'
            })
            logger.info(f"  Found vulnerability: {vuln}")
        
        return vulnerabilities
    
    def _extract_cve_context(self, output: str, cve: str) -> str:
        """Extract context around CVE"""
        lines = output.split('\n')
        for i, line in enumerate(lines):
            if cve in line:
                start = max(0, i - 2)
                end = min(len(lines), i + 3)
                return ' '.join(lines[start:end])
        return ''
    
    def _save_result(self, target_ip: str, result: NmapResult):
        """Save result to JSON file"""
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Nmap result saved to {output_file}")
