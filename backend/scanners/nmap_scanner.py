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
        logger.info("="*50)
        logger.info(f"Starting FAST Nmap scan for {target_ip}")
        logger.info("="*50)
        
        result = NmapResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Comprehensive scan for better service detection
            cmd = [
                'nmap', 
                '-T4',                    # Timing template 4 (aggressive)
                '-sV',                    # Version detection
                '-sC',                    # Default scripts
                '--script=vuln',          # Vulnerability scripts
                '--script-args=unsafe=1', # Allow potentially dangerous scripts
                '--script-timeout=30s',   # Script timeout
                '--max-retries=2',        # Retry failed attempts
                '--host-timeout=300s',    # Host timeout
                target_ip
            ]
            logger.info(f"Executing: {' '.join(cmd)}")
            
            process = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # Increased timeout for comprehensive scan
            )
            
            output = process.stdout
            logger.info(f"Scan completed ({len(output)} chars)")
            
            if output:
                result.raw_output = output
                result.open_ports = self._parse_ports(output)
                result.services = self._parse_services(output)
                result.os_detection = self._parse_os(output)
                
                # Detect if target is a Domain Controller
                is_dc = self._is_domain_controller(result.services, output)
                if is_dc:
                    logger.info("⚠️  DOMAIN CONTROLLER DETECTED!")
                    if result.os_detection is None:
                        result.os_detection = {}
                    result.os_detection['is_domain_controller'] = True
                    result.os_detection['dc_info'] = self._extract_dc_info(output)
                
                logger.info(f"Found {len(result.open_ports)} open ports")
                for port in result.open_ports:
                    logger.info(f"  Port {port['port']}: {port['service']} - {port['product']}")
                
                # Skip vuln scan for now to speed up
                result.vulnerabilities = []
                
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
        
        self._save_result(target_ip, result)
        logger.info("="*50)
        
        return result
    
    def _is_domain_controller(self, services: List[Dict], output: str) -> bool:
        """Detect if target is a Windows Domain Controller"""
        dc_ports = {389, 636, 3268, 3269, 88}  # LDAP, LDAPS, Global Catalog, Kerberos
        open_dc_ports = sum(1 for s in services if s['port'] in dc_ports)
        
        # If 3+ DC ports are open, likely a DC
        if open_dc_ports >= 3:
            return True
        
        # Check for Active Directory keywords
        dc_keywords = ['Active Directory', 'Domain Controller', 'AD', 'LDAP']
        return any(kw in output for kw in dc_keywords)
    
    def _extract_dc_info(self, output: str) -> Dict[str, Any]:
        """Extract Domain Controller information"""
        dc_info = {
            'domain': 'Unknown',
            'site': 'Unknown',
            'services': []
        }
        
        # Extract domain name
        domain_match = re.search(r'Domain: ([^,\)]+)', output)
        if domain_match:
            dc_info['domain'] = domain_match.group(1).strip()
        
        # Extract site name
        site_match = re.search(r'Site: ([^,\)]+)', output)
        if site_match:
            dc_info['site'] = site_match.group(1).strip()
        
        # List DC services
        dc_services = ['LDAP', 'Kerberos', 'DNS', 'SMB']
        for service in dc_services:
            if service.lower() in output.lower():
                dc_info['services'].append(service)
        
        return dc_info
    
    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        ports = []
        lines = output.split('\n')
        
        for line in lines:
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
    
    def _save_result(self, target_ip: str, result: NmapResult):
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Result saved to {output_file}")
