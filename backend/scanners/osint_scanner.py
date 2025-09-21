import json
import socket
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
        logger.info(f"Starting OSINT scan for {target_ip}")
        
        result = OSINTResult(
            target_ip=target_ip,
            status=StepStatus.RUNNING
        )
        
        try:
            # Get hostname
            result.hostname = self._get_hostname(target_ip)
            
            # Get IP geolocation and ISP info
            result.whois_info = self._get_ip_info(target_ip)
            
            # Get DNS info
            result.dns_info = self._get_dns_info(target_ip)
            
            # Get Shodan data
            result.shodan_data = self._get_shodan_data(target_ip)
            
            if result.shodan_data:
                result.public_services = self._extract_services(result.shodan_data)
            
            result.status = StepStatus.COMPLETED
            logger.info(f"OSINT scan completed for {target_ip}")
            
        except Exception as e:
            logger.error(f"OSINT scan failed: {e}")
            result.status = StepStatus.FAILED
        
        self._save_result(target_ip, result)
        return result
    
    def _get_hostname(self, ip: str) -> Optional[str]:
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            logger.info(f"Hostname: {hostname}")
            return hostname
        except:
            return None
    
    def _get_ip_info(self, ip: str) -> Dict[str, Any]:
        """Get IP information using ip-api.com (free, no key needed)"""
        try:
            response = requests.get(f"http://ip-api.com/json/{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                info = {
                    "ip": ip,
                    "org": data.get('org', 'Unknown'),
                    "isp": data.get('isp', 'Unknown'),
                    "country": data.get('country', 'Unknown'),
                    "city": data.get('city', 'Unknown'),
                    "region": data.get('regionName', 'Unknown'),
                    "asn": data.get('as', 'Unknown'),
                    "timezone": data.get('timezone', 'Unknown')
                }
                logger.info(f"IP Info: {info['org']} - {info['country']}")
                return info
        except Exception as e:
            logger.warning(f"IP info lookup failed: {e}")
        
        return {"ip": ip, "org": "Unknown", "country": "Unknown"}
    
    def _get_dns_info(self, ip: str) -> List[str]:
        """Get DNS records"""
        dns_info = []
        try:
            import dns.resolver
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            
            # Try PTR record
            try:
                reversed_ip = '.'.join(reversed(ip.split('.'))) + '.in-addr.arpa'
                answers = resolver.resolve(reversed_ip, 'PTR')
                for rdata in answers:
                    dns_info.append(f"PTR: {rdata}")
            except:
                pass
        except ImportError:
            logger.warning("dnspython not installed, skipping DNS lookup")
        
        return dns_info
    
    def _get_shodan_data(self, ip: str) -> Optional[Dict[str, Any]]:
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
                "ports": host.get('ports', []),
                "hostnames": host.get('hostnames', []),
                "data": host.get('data', [])
            }
        except Exception as e:
            logger.warning(f"Shodan lookup failed: {e}")
            return None
    
    def _extract_services(self, shodan_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        services = []
        if 'data' in shodan_data:
            for item in shodan_data['data']:
                service = {
                    "port": item.get('port'),
                    "protocol": item.get('transport', 'tcp'),
                    "product": item.get('product'),
                    "version": item.get('version'),
                    "banner": item.get('data', '')[:200]
                }
                services.append(service)
        return services
    
    def _save_result(self, target_ip: str, result: OSINTResult):
        output_file = config.DATA_DIR / f"{target_ip}_osint.json"
        with open(output_file, 'w') as f:
            json.dump(result.model_dump(), f, indent=2, default=str)
        logger.info(f"OSINT result saved to {output_file}")
