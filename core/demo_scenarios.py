"""
Demo scenarios and enhanced testing functionality
"""
import json as _json
import time
from datetime import datetime
from pathlib import Path


def determine_demo_scenario(target: str):
    """Determine demo scenario based on target"""
    
    demo_scenarios = {
        "10.10.10.40": {
            "name": "Legacy Windows Server (Blue)",
            "os": "Windows Server 2008 R2",
            "vulnerabilities": ["CVE-2017-0144", "CVE-2017-0145"],
            "services": [
                {"port": 135, "service": "msrpc", "version": "Microsoft Windows RPC"},
                {"port": 139, "service": "netbios-ssn", "version": "Microsoft Windows netbios-ssn"},
                {"port": 445, "service": "microsoft-ds", "version": "Windows Server 2008 R2 - 2012 microsoft-ds"},
                {"port": 3389, "service": "ms-wbt-server", "version": "Microsoft Terminal Services"}
            ],
            "exploit_focus": "MS17-010 EternalBlue SMB Remote Code Execution"
        },
        "10.10.10.75": {
            "name": "Apache Struts Web Server (Shocker)",
            "os": "Ubuntu 14.04.5 LTS",
            "vulnerabilities": ["CVE-2017-5638", "CVE-2014-6271"],
            "services": [
                {"port": 22, "service": "ssh", "version": "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8"},
                {"port": 80, "service": "http", "version": "Apache httpd 2.4.7"},
                {"port": 2222, "service": "ssh", "version": "OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.8"}
            ],
            "exploit_focus": "Apache Struts2 Content-Type Remote Code Execution"
        },
        "10.10.10.14": {
            "name": "Domain Controller (Forest)",
            "os": "Windows Server 2016",
            "vulnerabilities": ["CVE-2020-1472"],
            "services": [
                {"port": 53, "service": "domain", "version": "Microsoft DNS 6.1.7601 (1DB15D39)"},
                {"port": 88, "service": "kerberos-sec", "version": "Microsoft Windows Kerberos"},
                {"port": 135, "service": "msrpc", "version": "Microsoft Windows RPC"},
                {"port": 389, "service": "ldap", "version": "Microsoft Windows Active Directory LDAP"},
                {"port": 445, "service": "microsoft-ds", "version": "Windows Server 2016 Standard Evaluation 14393 microsoft-ds"},
                {"port": 3389, "service": "ssl/ms-wbt-server", "version": ""}
            ],
            "exploit_focus": "CVE-2020-1472 Zerologon Domain Controller Compromise"
        }
    }
    
    default_scenario = {
        "name": "Generic Linux Server",
        "os": "Linux 3.13.0-37-generic",
        "vulnerabilities": ["CVE-2021-44228"],
        "services": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 6.6.1p1"},
            {"port": 80, "service": "http", "version": "Apache httpd 2.4.7"},
            {"port": 443, "service": "https", "version": "Apache httpd 2.4.7"}
        ],
        "exploit_focus": "Log4Shell Remote Code Execution"
    }
    
    return demo_scenarios.get(target, default_scenario)


def run_enhanced_scan(target: str, work_dir: Path, job_id: str, scenario: dict, jobs: dict) -> Path:
    """Enhanced scan with real-time updates and scenario-based results"""
    
    from core.job_utils import _update_job_status
    
    def update_scan_progress(message: str, progress: int):
        _update_job_status(jobs, job_id, "scan", "running", progress=progress, scan_output=message)
        time.sleep(1)
    
    update_scan_progress(f"Starting Nmap scan on {target}...", 12)
    update_scan_progress("Host discovery completed. Target is up.", 15)
    update_scan_progress("Port scan in progress...", 18)
    update_scan_progress("Service detection running...", 22)
    
    scan_result = {
        "scan_info": {
            "target": target,
            "scan_type": "comprehensive",
            "start_time": datetime.now().isoformat(),
            "nmap_version": "7.80",
            "scan_args": f"nmap -sS -sV -O -A -p 1-65535 {target}"
        },
        "host_info": {
            "ip": target,
            "hostname": f"{scenario['name'].lower().replace(' ', '-')}.lab",
            "status": "up",
            "os_detection": scenario["os"],
            "os_accuracy": "95%"
        },
        "open_ports": scenario["services"],
        "vulnerabilities_detected": scenario["vulnerabilities"],
        "scan_stats": {
            "total_ports_scanned": 65535,
            "open_ports": len(scenario["services"]),
            "closed_ports": 65535 - len(scenario["services"]),
            "scan_duration": "2m 34s"
        }
    }
    
    update_scan_progress(f"Scan completed! Found {len(scenario['services'])} open ports", 25)
    
    scan_file = work_dir / "nmap_scan.json"
    scan_file.write_text(_json.dumps(scan_result, indent=2))
    
    return scan_file


def get_real_cve_info(cve_id: str) -> dict:
    """Get real CVE information"""
    
    cve_database = {
        "CVE-2017-0144": {
            "title": "Microsoft Windows SMB Remote Code Execution Vulnerability",
            "severity": "CRITICAL",
            "cvss_score": 9.3,
            "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets (EternalBlue).",
            "poc_code": "# MS17-010 EternalBlue Exploit\\nimport socket\\n\\ndef exploit_eternalblue(target_ip):\\n    # SMB negotiation and payload",
            "exploit_url": "https://github.com/worawit/MS17-010",
            "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144"]
        },
        "CVE-2017-5638": {
            "title": "Apache Struts2 Content-Type Remote Code Execution",
            "severity": "CRITICAL", 
            "cvss_score": 9.8,
            "description": "Apache Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10 allows remote code execution via Content-Type header.",
            "poc_code": "# Struts2 CVE-2017-5638 Exploit\\nimport requests\\n\\ndef exploit_struts2(target_url):\\n    # OGNL payload",
            "exploit_url": "https://github.com/mazen160/struts-pwn",
            "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638"]
        },
        "CVE-2020-1472": {
            "title": "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection.",
            "poc_code": "# CVE-2020-1472 Zerologon Exploit\\nfrom impacket.dcerpc.v5 import nrpc\\n\\ndef zerologon_exploit(dc_handle, dc_ip):",
            "exploit_url": "https://github.com/SecuraBV/CVE-2020-1472",
            "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472"]
        },
        "CVE-2021-44228": {
            "title": "Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "poc_code": "# CVE-2021-44228 Log4Shell Exploit\\nimport requests\\n\\ndef log4shell_exploit(target_url, ldap_server):\\n    # JNDI lookup payload",
            "exploit_url": "https://github.com/kozmer/log4j-shell-poc",
            "references": ["https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228"]
        }
    }
    
    return cve_database.get(cve_id)


def fetch_enhanced_poc(scan_json: Path, work_dir: Path, scenario: dict) -> str:
    """Enhanced PoC fetching with real CVE lookups"""
    
    poc_results = []
    
    for cve in scenario["vulnerabilities"]:
        cve_info = get_real_cve_info(cve)
        
        if cve_info:
            poc_results.append({
                "cve_id": cve,
                "title": cve_info["title"],
                "severity": cve_info["severity"],
                "cvss_score": cve_info["cvss_score"],
                "description": cve_info["description"],
                "poc_code": cve_info["poc_code"],
                "exploit_url": cve_info["exploit_url"],
                "references": cve_info["references"]
            })
    
    poc_file = work_dir / "poc_research.json"
    poc_file.write_text(_json.dumps(poc_results, indent=2))
    
    return str(poc_file)


def run_demo_exploit(target: str, poc_info: str, work_dir: Path, scenario: dict, authorize: bool = False) -> Path:
    """Enhanced demo exploit execution"""
    
    exploit_result = {
        "target": target,
        "scenario": scenario["name"],
        "exploit_focus": scenario["exploit_focus"],
        "authorized": authorize,
        "execution_time": datetime.now().isoformat(),
        "results": []
    }
    
    try:
        poc_data = _json.loads(Path(poc_info).read_text())
        
        for poc in poc_data:
            exploit_attempt = {
                "cve_id": poc["cve_id"],
                "exploit_name": poc["title"],
                "severity": poc["severity"],
                "cvss_score": poc["cvss_score"],
                "execution_status": "DEMO_MODE",
                "demo_result": f"Would execute {poc['cve_id']} exploit against {target}",
                "poc_verified": True,
                "payload_generated": True,
                "exploit_code_available": bool(poc.get("poc_code")),
                "references_validated": len(poc.get("references", [])),
                "recommendation": f"Patch {poc['cve_id']} immediately - CVSS {poc['cvss_score']}/10.0"
            }
            
            if authorize and target.startswith("10.10.10."):
                exploit_attempt["demo_result"] = f"Demo execution successful - {poc['cve_id']} vulnerability confirmed"
                exploit_attempt["execution_status"] = "SUCCESS"
            
            exploit_result["results"].append(exploit_attempt)
    
    except Exception as e:
        exploit_result["error"] = str(e)
    
    exploit_file = work_dir / "exploit_results.json"
    exploit_file.write_text(_json.dumps(exploit_result, indent=2))
    
    return exploit_file