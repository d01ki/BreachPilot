import json
import subprocess
import re
import xml.etree.ElementTree as ET
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
            # XML output for better parsing
            xml_file = config.DATA_DIR / f"{target_ip}_nmap.xml"
            config.DATA_DIR.mkdir(exist_ok=True)
            
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
                '-oX', str(xml_file),     # XML output
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
            logger.info(f"Scan completed (stdout: {len(output)} chars)")
            
            # Parse both text output and XML
            result.raw_output = output
            
            # Try XML parsing first (more reliable)
            if xml_file.exists():
                try:
                    xml_data = self._parse_xml_output(xml_file)
                    result.open_ports = xml_data.get('open_ports', [])
                    result.services = xml_data.get('services', [])
                    result.os_detection = xml_data.get('os_detection')
                    logger.info(f"XML parsing successful: {len(result.open_ports)} ports found")
                except Exception as e:
                    logger.warning(f"XML parsing failed: {e}")
                    # Fall back to text parsing
                    result.open_ports = self._parse_ports_from_text(output)
                    result.services = self._parse_services_from_text(output)
                    result.os_detection = self._parse_os_from_text(output)
            else:
                # Parse from text output
                result.open_ports = self._parse_ports_from_text(output)
                result.services = self._parse_services_from_text(output)
                result.os_detection = self._parse_os_from_text(output)
            
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
                logger.info(f"  Port {port['port']}: {port['service']} - {port.get('product', 'Unknown')}")
            
            # Skip vuln scan for now to speed up
            result.vulnerabilities = []
            
            if result.open_ports or output.strip():
                result.status = StepStatus.COMPLETED
                logger.info("Scan completed successfully")
            else:
                logger.warning("No ports found and no output")
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
    
    def _parse_xml_output(self, xml_file) -> Dict[str, Any]:
        """Parse nmap XML output for more reliable data extraction"""
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            parsed_data = {
                'open_ports': [],
                'services': [],
                'os_detection': None
            }
            
            # Find the host element
            host = root.find('.//host')
            if host is None:
                return parsed_data
            
            # Parse ports
            ports = host.findall('.//port')
            for port in ports:
                port_num = port.get('portid')
                protocol = port.get('protocol', 'tcp')
                
                state_elem = port.find('state')
                if state_elem is None or state_elem.get('state') != 'open':
                    continue
                
                service_elem = port.find('service')
                service_name = service_elem.get('name', 'unknown') if service_elem is not None else 'unknown'
                product = service_elem.get('product', '') if service_elem is not None else ''
                version = service_elem.get('version', '') if service_elem is not None else ''
                extrainfo = service_elem.get('extrainfo', '') if service_elem is not None else ''
                
                port_info = {
                    'port': int(port_num),
                    'state': 'open',
                    'service': service_name,
                    'product': product,
                    'version': version
                }
                
                service_info = {
                    'port': int(port_num),
                    'protocol': protocol,
                    'name': service_name,
                    'product': product,
                    'version': version,
                    'extrainfo': extrainfo,
                    'cpe': ''
                }
                
                parsed_data['open_ports'].append(port_info)
                parsed_data['services'].append(service_info)
            
            # Parse OS detection
            os_elem = host.find('.//os')
            if os_elem is not None:
                osmatch = os_elem.find('osmatch')
                if osmatch is not None:
                    parsed_data['os_detection'] = {
                        'name': osmatch.get('name', 'Unknown'),
                        'accuracy': int(osmatch.get('accuracy', 0)),
                        'family': None,
                        'vendor': None
                    }
            
            return parsed_data
            
        except Exception as e:
            logger.error(f"XML parsing error: {e}")
            return {'open_ports': [], 'services': [], 'os_detection': None}
    
    def _parse_ports_from_text(self, output: str) -> List[Dict[str, Any]]:
        """Parse ports from text output (fallback method)"""
        ports = []
        lines = output.split('\n')
        
        # Look for port lines with improved regex
        for line in lines:
            # Pattern: PORT     STATE  SERVICE    VERSION
            # Example: 22/tcp   open   ssh        OpenSSH 8.2p1 Ubuntu 4ubuntu0.5
            match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', line.strip())
            if match:
                port_num = int(match.group(1))
                protocol = match.group(2)
                service = match.group(3)
                details = match.group(4) or ''
                
                ports.append({
                    'port': port_num,
                    'state': 'open',
                    'service': service,
                    'product': details.strip(),
                    'version': ''
                })
                logger.debug(f"Parsed port: {port_num}/{protocol} {service}")
        
        # If no ports found with the first method, try alternative parsing
        if not ports:
            logger.warning("No ports found with primary regex, trying alternative parsing")
            for line in lines:
                if '/tcp' in line and 'open' in line:
                    parts = line.strip().split()
                    if len(parts) >= 3:
                        port_service = parts[0]  # e.g., "22/tcp"
                        state = parts[1]         # "open"
                        service_name = parts[2]  # "ssh"
                        
                        if '/tcp' in port_service and state == 'open':
                            port_num = int(port_service.split('/')[0])
                            product = ' '.join(parts[3:]) if len(parts) > 3 else service_name
                            
                            ports.append({
                                'port': port_num,
                                'state': 'open',
                                'service': service_name,
                                'product': product,
                                'version': ''
                            })
                            logger.debug(f"Alt parsed port: {port_num} {service_name}")
        
        logger.info(f"Text parsing extracted {len(ports)} ports")
        return ports
    
    def _parse_services_from_text(self, output: str) -> List[Dict[str, Any]]:
        """Parse services from text output"""
        services = []
        lines = output.split('\n')
        
        for line in lines:
            match = re.search(r'(\d+)/(tcp|udp)\s+open\s+(\S+)(?:\s+(.+))?', line.strip())
            if match:
                port_num = int(match.group(1))
                protocol = match.group(2)
                service_name = match.group(3)
                details = match.group(4) or ''
                
                product = ''
                version = ''
                if details:
                    parts = details.split()
                    if parts:
                        product = parts[0]
                        if len(parts) > 1:
                            version = parts[1]
                
                services.append({
                    'port': port_num,
                    'protocol': protocol,
                    'name': service_name,
                    'product': product,
                    'version': version,
                    'extrainfo': details,
                    'cpe': ''
                })
        
        return services
    
    def _parse_os_from_text(self, output: str) -> Dict[str, Any]:
        """Parse OS information from text output"""
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
    
    # Keep the old method names for backward compatibility
    def _parse_ports(self, output: str) -> List[Dict[str, Any]]:
        return self._parse_ports_from_text(output)
    
    def _parse_services(self, output: str) -> List[Dict[str, Any]]:
        return self._parse_services_from_text(output)
    
    def _parse_os(self, output: str) -> Dict[str, Any]:
        return self._parse_os_from_text(output)
    
    def _save_result(self, target_ip: str, result: NmapResult):
        """Save result to JSON file"""
        config.DATA_DIR.mkdir(exist_ok=True)
        output_file = config.DATA_DIR / f"{target_ip}_nmap.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"Result saved to {output_file}")
