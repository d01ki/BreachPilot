"""
OSINT Tools - Real implementation with free APIs
"""
import subprocess
import json
import socket
import ssl
import whois
import dns.resolver
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
import logging

logger = logging.getLogger(__name__)


class OSINTTool:
    """OSINT Intelligence Gathering Tool"""
    
    def __init__(self):
        self.results = {
            "target": "",
            "timestamp": "",
            "dns_records": {},
            "whois_info": {},
            "ssl_info": {},
            "subdomains": [],
            "ip_addresses": [],
            "shodan_data": {},
            "github_repos": []
        }
    
    async def gather_intelligence(self, target: str) -> Dict[str, Any]:
        """Main OSINT gathering function"""
        self.results["target"] = target
        self.results["timestamp"] = datetime.now().isoformat()
        
        logger.info(f"Starting OSINT for {target}")
        
        # DNS Enumeration
        self.results["dns_records"] = self._get_dns_records(target)
        
        # WHOIS Lookup
        self.results["whois_info"] = self._get_whois_info(target)
        
        # SSL Certificate Info
        self.results["ssl_info"] = self._get_ssl_info(target)
        
        # Subdomain Enumeration (using crt.sh)
        self.results["subdomains"] = self._enumerate_subdomains(target)
        
        # IP Resolution
        self.results["ip_addresses"] = self._resolve_ips(target)
        
        # Shodan (if API key available)
        # self.results["shodan_data"] = self._query_shodan(target)
        
        return self.results
    
    def _get_dns_records(self, target: str) -> Dict[str, List[str]]:
        """Get DNS records"""
        records = {
            "A": [],
            "AAAA": [],
            "MX": [],
            "NS": [],
            "TXT": [],
            "CNAME": []
        }
        
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(target, record_type)
                for rdata in answers:
                    if record_type == 'MX':
                        records[record_type].append(str(rdata.exchange))
                    else:
                        records[record_type].append(str(rdata))
            except Exception as e:
                logger.debug(f"No {record_type} records for {target}: {e}")
        
        return records
    
    def _get_whois_info(self, target: str) -> Dict[str, Any]:
        """Get WHOIS information"""
        try:
            w = whois.whois(target)
            return {
                "domain_name": w.domain_name,
                "registrar": w.registrar,
                "creation_date": str(w.creation_date) if w.creation_date else None,
                "expiration_date": str(w.expiration_date) if w.expiration_date else None,
                "name_servers": w.name_servers if w.name_servers else [],
                "status": w.status if w.status else [],
                "emails": w.emails if w.emails else [],
                "org": w.org if hasattr(w, 'org') else None
            }
        except Exception as e:
            logger.error(f"WHOIS lookup failed: {e}")
            return {"error": str(e)}
    
    def _get_ssl_info(self, target: str) -> Dict[str, Any]:
        """Get SSL certificate information"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((target, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert()
                    
                    return {
                        "issuer": dict(x[0] for x in cert.get('issuer', [])),
                        "subject": dict(x[0] for x in cert.get('subject', [])),
                        "version": cert.get('version'),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": cert.get('notBefore'),
                        "not_after": cert.get('notAfter'),
                        "san": cert.get('subjectAltName', [])
                    }
        except Exception as e:
            logger.error(f"SSL info failed: {e}")
            return {"error": str(e)}
    
    def _enumerate_subdomains(self, target: str) -> List[str]:
        """Enumerate subdomains using crt.sh"""
        subdomains = []
        try:
            url = f"https://crt.sh/?q=%.{target}&output=json"
            response = requests.get(url, timeout=30)
            if response.status_code == 200:
                data = response.json()
                for entry in data:
                    name = entry.get('name_value', '')
                    if name and name not in subdomains:
                        # Split on newlines (crt.sh returns multiple names)
                        for subdomain in name.split('\n'):
                            subdomain = subdomain.strip()
                            if subdomain and subdomain not in subdomains:
                                subdomains.append(subdomain)
        except Exception as e:
            logger.error(f"Subdomain enumeration failed: {e}")
        
        return sorted(set(subdomains))[:50]  # Limit to 50
    
    def _resolve_ips(self, target: str) -> List[str]:
        """Resolve target to IP addresses"""
        ips = []
        try:
            # IPv4
            answers = dns.resolver.resolve(target, 'A')
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
        
        try:
            # IPv6
            answers = dns.resolver.resolve(target, 'AAAA')
            for rdata in answers:
                ips.append(str(rdata))
        except:
            pass
        
        return ips


class NmapScanner:
    """Nmap Scanner with real implementation"""
    
    def __init__(self):
        self.results = {
            "target": "",
            "scan_type": "",
            "timestamp": "",
            "hosts": [],
            "ports": [],
            "services": [],
            "os_detection": {},
            "vulnerabilities": []
        }
    
    async def scan(self, target: str, scan_type: str = "quick") -> Dict[str, Any]:
        """Perform Nmap scan"""
        self.results["target"] = target
        self.results["scan_type"] = scan_type
        self.results["timestamp"] = datetime.now().isoformat()
        
        logger.info(f"Starting Nmap scan for {target}")
        
        # Build nmap command
        if scan_type == "quick":
            cmd = ["nmap", "-sV", "-T4", "--top-ports", "100", target]
        elif scan_type == "full":
            cmd = ["nmap", "-sV", "-sC", "-O", "-A", "-T4", target]
        elif scan_type == "vuln":
            cmd = ["nmap", "-sV", "--script", "vulners,vulscan", target]
        else:
            cmd = ["nmap", "-sV", target]
        
        try:
            # Run nmap
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300  # 5 minutes timeout
            )
            
            # Parse output
            self._parse_nmap_output(result.stdout)
            
        except subprocess.TimeoutExpired:
            logger.error(f"Nmap scan timeout for {target}")
            self.results["error"] = "Scan timeout"
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            self.results["error"] = str(e)
        
        return self.results
    
    def _parse_nmap_output(self, output: str):
        """Parse nmap output"""
        lines = output.split('\n')
        current_host = None
        
        for line in lines:
            line = line.strip()
            
            # Host detection
            if 'Nmap scan report for' in line:
                host = line.split('for ')[-1]
                current_host = {"host": host, "ports": [], "os": ""}
                self.results["hosts"].append(current_host)
            
            # Port detection
            elif '/tcp' in line or '/udp' in line:
                parts = line.split()
                if len(parts) >= 3:
                    port_info = {
                        "port": parts[0].split('/')[0],
                        "protocol": parts[0].split('/')[1] if '/' in parts[0] else "tcp",
                        "state": parts[1],
                        "service": parts[2] if len(parts) > 2 else "",
                        "version": ' '.join(parts[3:]) if len(parts) > 3 else ""
                    }
                    
                    self.results["ports"].append(port_info)
                    if current_host:
                        current_host["ports"].append(port_info)
                    
                    # Check for potential vulnerabilities
                    service_lower = port_info["service"].lower()
                    if any(vuln in service_lower for vuln in ['ftp', 'telnet', 'smb', 'mysql', 'postgresql']):
                        self.results["vulnerabilities"].append({
                            "port": port_info["port"],
                            "service": port_info["service"],
                            "risk": "potentially vulnerable service"
                        })
            
            # OS detection
            elif 'OS:' in line or 'Running:' in line:
                if current_host:
                    current_host["os"] = line.split(':', 1)[-1].strip()
                    self.results["os_detection"] = {"os": current_host["os"]}


class VulnerabilityScan:
    """Vulnerability scanning and CVE identification"""
    
    def __init__(self):
        self.results = {
            "target": "",
            "timestamp": "",
            "vulnerabilities": [],
            "cves": [],
            "risk_score": 0
        }
    
    async def identify_vulnerabilities(self, nmap_results: Dict[str, Any]) -> Dict[str, Any]:
        """Identify vulnerabilities from Nmap results"""
        self.results["target"] = nmap_results.get("target", "")
        self.results["timestamp"] = datetime.now().isoformat()
        
        # Analyze each service
        for port_info in nmap_results.get("ports", []):
            service = port_info.get("service", "").lower()
            version = port_info.get("version", "").lower()
            port = port_info.get("port", "")
            
            # Search for known vulnerabilities
            vulns = self._search_cve_database(service, version)
            
            for vuln in vulns:
                vuln["port"] = port
                vuln["service"] = service
                self.results["vulnerabilities"].append(vuln)
                
                if vuln.get("cve"):
                    self.results["cves"].append(vuln["cve"])
        
        # Calculate risk score
        self.results["risk_score"] = self._calculate_risk_score()
        
        return self.results
    
    def _search_cve_database(self, service: str, version: str) -> List[Dict[str, Any]]:
        """Search CVE database for vulnerabilities"""
        vulnerabilities = []
        
        # Use NVD API (free, no key required)
        try:
            # Search by keyword (service name)
            url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={service}"
            response = requests.get(url, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                
                # Get first 5 CVEs
                for item in data.get('vulnerabilities', [])[:5]:
                    cve = item.get('cve', {})
                    cve_id = cve.get('id', '')
                    description = ''
                    
                    # Get description
                    descriptions = cve.get('descriptions', [])
                    if descriptions:
                        description = descriptions[0].get('value', '')
                    
                    # Get CVSS score
                    cvss_score = 0
                    metrics = cve.get('metrics', {})
                    if 'cvssMetricV31' in metrics and metrics['cvssMetricV31']:
                        cvss_score = metrics['cvssMetricV31'][0].get('cvssData', {}).get('baseScore', 0)
                    elif 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
                        cvss_score = metrics['cvssMetricV2'][0].get('cvssData', {}).get('baseScore', 0)
                    
                    vulnerabilities.append({
                        "cve": cve_id,
                        "description": description[:200],  # Truncate
                        "cvss_score": cvss_score,
                        "severity": self._get_severity(cvss_score)
                    })
        except Exception as e:
            logger.error(f"CVE search failed: {e}")
        
        return vulnerabilities
    
    def _get_severity(self, cvss_score: float) -> str:
        """Get severity level from CVSS score"""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0:
            return "LOW"
        else:
            return "NONE"
    
    def _calculate_risk_score(self) -> float:
        """Calculate overall risk score"""
        if not self.results["vulnerabilities"]:
            return 0.0
        
        total_score = sum(v.get("cvss_score", 0) for v in self.results["vulnerabilities"])
        return round(total_score / len(self.results["vulnerabilities"]), 2)


# Helper functions for the main app
async def run_osint(target: str) -> Dict[str, Any]:
    """Run OSINT gathering"""
    osint = OSINTTool()
    return await osint.gather_intelligence(target)


async def run_nmap_scan(target: str, scan_type: str = "quick") -> Dict[str, Any]:
    """Run Nmap scan"""
    scanner = NmapScanner()
    return await scanner.scan(target, scan_type)


async def identify_vulnerabilities(nmap_results: Dict[str, Any]) -> Dict[str, Any]:
    """Identify vulnerabilities from scan results"""
    vuln_scanner = VulnerabilityScan()
    return await vuln_scanner.identify_vulnerabilities(nmap_results)
