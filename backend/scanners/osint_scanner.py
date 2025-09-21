import json
import socket
import whois
import dns.resolver
import requests
from typing import Dict, Any, List, Optional
from datetime import datetime
from backend.models import OSINTResult, StepStatus
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class OSINTScanner:
    def __init__(self):
        self.shodan_api_key = config.SHODAN_API_KEY
    
    def scan(self, target_ip: str) -> OSINTResult:
        """Perform OSINT scan on target IP"""
        logger.info(f"Starting OSINT scan for {target_ip}")
        
        result = OSINTResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Get hostname
            result.hostname = self._get_hostname(target_ip)
            
            # Get domain from hostname
            if result.hostname:
                result.domain = self._extract_domain(result.hostname)
            
            # Get WHOIS information
            result.whois_info = self._get_whois_info(target_ip)
            
            # Get subdomains (if domain is available)
            if result.domain:
                result.subdomains = self._get_subdomains(result.domain)
            
            # Get Shodan data
            result.shodan_data = self._get_shodan_data(target_ip)
            
            # Extract public services from Shodan
            if result.shodan_data:
                result.public_services = self._extract_services(result.shodan_data)
            
            result.status = StepStatus.COMPLETED
            logger.info(f"OSINT scan completed for {target_ip}")
            
        except Exception as e:
            logger.error(f"OSINT scan failed: {e}")
            result.status = StepStatus.FAILED
        
        # Save result to JSON
        self._save_result(target_ip, result)
        return result
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        """Resolve hostname from IP"""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except:
            return None
    
    def _extract_domain(self, hostname: str) -> Optional[str]:
        """Extract domain from hostname"""
        try:
            parts = hostname.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
        except:
            pass
        return None
    
    def _get_whois_info(self, target: str) -> Optional[Dict[str, Any]]:
        """Get WHOIS information"""
        try:
            w = whois.whois(target)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers,
                "emails": w.emails,
                "org": w.org,
                "country": w.country
            }
        except Exception as e:
            logger.warning(f"WHOIS lookup failed: {e}")
            return None
    
    def _get_subdomains(self, domain: str) -> List[str]:
        """Attempt to find subdomains"""
        subdomains = []
        common_subdomains = ['www', 'mail', 'ftp', 'admin', 'dev', 'test', 'api', 'staging']
        
        resolver = dns.resolver.Resolver()
        resolver.timeout = 2
        resolver.lifetime = 2
        
        for sub in common_subdomains:
            try:
                test_domain = f"{sub}.{domain}"
                answers = resolver.resolve(test_domain, 'A')
                if answers:
                    subdomains.append(test_domain)
            except:
                continue
        
        return subdomains
    
    def _get_shodan_data(self, ip: str) -> Optional[Dict[str, Any]]:
        """Get data from Shodan"""
        if not self.shodan_api_key:
            logger.warning("Shodan API key not configured")
            return None
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            host = api.host(ip)
            return {
                "ip": host.get('ip_str'),
                "org": host.get('org'),
                "isp": host.get('isp'),
                "asn": host.get('asn'),
                "ports": host.get('ports', []),
                "hostnames": host.get('hostnames', []),
                "domains": host.get('domains', []),
                "data": host.get('data', [])
            }
        except Exception as e:
            logger.warning(f"Shodan lookup failed: {e}")
            return None
    
    def _extract_services(self, shodan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract service information from Shodan data"""
        services = []
        
        if 'data' in shodan_data:
            for item in shodan_data['data']:
                service = {
                    "port": item.get('port'),
                    "protocol": item.get('transport', 'tcp'),
                    "product": item.get('product'),
                    "version": item.get('version'),
                    "banner": item.get('data', '')[:200]  # First 200 chars
                }
                services.append(service)
        
        return services
    
    def _save_result(self, target_ip: str, result: OSINTResult):
        """Save OSINT result to JSON file"""
        output_file = config.DATA_DIR / f"{target_ip}_osint.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"OSINT result saved to {output_file}")
