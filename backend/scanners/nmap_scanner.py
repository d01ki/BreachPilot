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
        logger.info(f"Starting FAST Nmap scan for {target_ip}")
        logger.info(f="="*50)
        
        result = NmapResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Fast scan: -T4 (aggressive timing), -F (fast mode - top 100 ports)
            cmd = ['nmap', '-T4', '-F', '-sV', target_ip]
            logger.info(f"Executing: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # 1 minute max for fast scan
            )
            
            output = process.stdout
            logger.info(f"Fast scan completed ({len(output)} characters)")
            
            if output:
                result.raw_output = output
                result.open_ports = self._parse_ports(output)
                result.services = self._parse_services(output)
                result.os_detection = self._parse_os(output)
                
                logger.info(f"Found {len(result.open_ports)} open ports")
                for port in result.open_ports:
                    logger.info(f"  Port {port['port']}: {port['service']} - {port['product']}")
                
                # Quick vulnerability check (only if ports found)
                if result.open_ports:
                    logger.info("Running quick vulnerability check (30s timeout)...")
                    try:
                        vuln_output = self._run_quick_vuln_scan(target_ip, result.open_ports)
                        result.vulnerabilities = self._parse_vulnerabilities(vuln_output)
                        logger.info(f"Found {len(result.vulnerabilities)} potential vulnerabilities")
                    except (subprocess.TimeoutExpired, Exception) as e:
                        logger.warning(f"Vulnerability scan skipped or timed out: {e}")
                        result.vulnerabilities = []
                
                result.status = StepStatus.COMPLETED
                logger.info("Fast scan completed successfully")
            else:
                logger.warning("No output from nmap")
                result.status = StepStatus.FAILED
                
        except subprocess.TimeoutExpired:
            logger.error("Nmap scan timeout")
            result.status = StepStatus.FAILED
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}", exc_info=True)
            result.status = StepStatus.FAILED
        
        # Save result immediately
        self._save_result(target_ip, result)
        logger.info(f"="*50)
        
        return result
    
    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        """Parse open ports from nmap output"""
        ports = []
        lines = output.split('\n')
        
        for line in lines:
            # Match: 22/tcp   open  ssh     OpenSSH 8.2p1
            match = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if match:
                port_num = match.group(1)
                service = match.group(2)
                details = match.group(3).strip()
                
                ports.append({
                    'port': int(port_num),
                    'state': 'open',
                    'service': service,
                    'product': details if details else service,
                    'version': ''
                })
        
        return ports
    
    def _parse_services(self, output: str) -> List[Dict[str, Any]]:
        """Parse service information"""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            match = re.match(r'(\d+)/tcp\s+open\s+(\S+)\s*(.*)', line)
            if match:
                port_num = match.group(1)
                service_name = match.group(2)
                details = match.group(3).strip()
                
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
        """Parse OS detection"""
        os_info = None
        lines = output.split('\n')
        
        for line in lines:
            if 'OS details:' in line or 'Running:' in line or 'Service Info:' in line:
                if 'OS:' in line or 'Running:' in line:
                    os_info = {
                        'name': line.split(':', 1)[1].strip() if ':' in line else '',
                        'accuracy': 80,
                        'family': None,
                        'vendor': None
                    }
                    break
        
        return os_info
    
    def _run_quick_vuln_scan(self, target_ip: str, open_ports: List[Dict]) -> str:
        """Run quick vulnerability scan on specific ports only"""
        # Only scan specific open ports for speed
        port_list = ','.join([str(p['port']) for p in open_ports[:5]])  # Max 5 ports
        
        # Use only fast vuln scripts
        cmd = ['nmap', '-T4', '-p', port_list, '--script', 'vuln', '--script-timeout', '10s', target_ip]
        logger.info(f"Quick vuln scan: {' '.join(cmd)}")
        
        process = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=30  # 30 seconds max
        )
        
        return process.stdout
    
    def _parse_vulnerabilities(self, output: str) -> List[Dict[str, Any]]:
        """Parse vulnerabilities"""
        vulnerabilities = []
        
        # Find CVEs
        cve_pattern = r'(CVE-\d{4}-\d{4,7})'
        cves = re.findall(cve_pattern, output)
        
        for cve in set(cves):
            vulnerabilities.append({
                'cve_id': cve,
                'context': '',
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
    
    def _save_result(self, target_ip: str, result: NmapResult):
        """Save result to JSON file"""
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Nmap result saved to {output_file}")
