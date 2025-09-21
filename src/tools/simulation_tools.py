"""
Simulation mode for testing without real tools
"""
import asyncio
import time
from typing import Dict, Any


class SimulationTools:
    """Simulation tools for testing"""
    
    @staticmethod
    async def run_osint(target: str) -> Dict[str, Any]:
        """Simulate OSINT gathering"""
        await asyncio.sleep(3)  # Simulate processing time
        
        return {
            "target": target,
            "timestamp": time.time(),
            "dns_records": {
                "A": ["192.168.1.100", "192.168.1.101"],
                "MX": ["mail.example.com"],
                "TXT": ["v=spf1 include:_spf.google.com ~all"],
                "AAAA": ["2001:db8::1"],
                "NS": ["ns1.example.com", "ns2.example.com"]
            },
            "whois_info": {
                "domain_name": target,
                "registrar": "Example Registrar Inc.",
                "creation_date": "2020-01-01",
                "expiration_date": "2025-01-01",
                "name_servers": ["ns1.example.com", "ns2.example.com"]
            },
            "ssl_info": {
                "issuer": {"organizationName": "Let's Encrypt"},
                "subject": {"commonName": target},
                "not_before": "2024-01-01",
                "not_after": "2025-01-01",
                "san": [f"*.{target}", f"www.{target}"]
            },
            "subdomains": [
                f"www.{target}",
                f"mail.{target}",
                f"ftp.{target}",
                f"admin.{target}",
                f"api.{target}",
                f"dev.{target}",
                f"staging.{target}"
            ],
            "ip_addresses": ["192.168.1.100", "2001:db8::1"]
        }
    
    @staticmethod
    async def run_nmap_scan(target: str, scan_type: str = "quick") -> Dict[str, Any]:
        """Simulate Nmap scan"""
        await asyncio.sleep(5)  # Simulate scanning time
        
        return {
            "target": target,
            "scan_type": scan_type,
            "timestamp": time.time(),
            "hosts": [{"host": target, "ports": []}],
            "ports": [
                {
                    "port": "22",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "ssh",
                    "version": "OpenSSH 7.4"
                },
                {
                    "port": "80",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http",
                    "version": "Apache httpd 2.4.6"
                },
                {
                    "port": "443",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "https",
                    "version": "Apache httpd 2.4.6"
                },
                {
                    "port": "3306",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "mysql",
                    "version": "MySQL 5.7.30"
                },
                {
                    "port": "8080",
                    "protocol": "tcp",
                    "state": "open",
                    "service": "http-proxy",
                    "version": "Tomcat 9.0.30"
                }
            ],
            "os_detection": {
                "os": "Linux 3.x - 4.x"
            },
            "vulnerabilities": []
        }
    
    @staticmethod
    async def identify_vulnerabilities(nmap_results: Dict[str, Any]) -> Dict[str, Any]:
        """Simulate vulnerability identification"""
        await asyncio.sleep(4)  # Simulate analysis time
        
        return {
            "target": nmap_results.get("target", ""),
            "timestamp": time.time(),
            "vulnerabilities": [
                {
                    "cve": "CVE-2021-44228",
                    "description": "Apache Log4j2 Remote Code Execution (Log4Shell)",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "port": "8080",
                    "service": "http-proxy"
                },
                {
                    "cve": "CVE-2017-5638",
                    "description": "Apache Struts2 Remote Code Execution",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "port": "8080",
                    "service": "http-proxy"
                },
                {
                    "cve": "CVE-2019-0708",
                    "description": "BlueKeep RDP Remote Code Execution",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "port": "3389",
                    "service": "rdp"
                },
                {
                    "cve": "CVE-2014-0160",
                    "description": "OpenSSL Heartbleed Information Disclosure",
                    "cvss_score": 7.5,
                    "severity": "HIGH",
                    "port": "443",
                    "service": "https"
                },
                {
                    "cve": "CVE-2012-2122",
                    "description": "MySQL Authentication Bypass",
                    "cvss_score": 6.5,
                    "severity": "MEDIUM",
                    "port": "3306",
                    "service": "mysql"
                }
            ],
            "risk_score": 8.72,
            "total_critical": 3,
            "total_high": 1,
            "total_medium": 1,
            "total_low": 0
        }


# Export simulation functions
async def run_simulation_osint(target: str) -> Dict[str, Any]:
    return await SimulationTools.run_osint(target)


async def run_simulation_nmap(target: str, scan_type: str = "quick") -> Dict[str, Any]:
    return await SimulationTools.run_nmap_scan(target, scan_type)


async def run_simulation_vuln_scan(nmap_results: Dict[str, Any]) -> Dict[str, Any]:
    return await SimulationTools.identify_vulnerabilities(nmap_results)
