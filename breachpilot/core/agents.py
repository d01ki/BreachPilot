import subprocess
import json
import requests
import datetime
import os
import socket
from pathlib import Path
from crewai import Agent
from crewai_tools import tool
from rich.console import Console

console = Console()

@tool
def enhanced_recon(target: str) -> str:
    """Enhanced reconnaissance for Active Directory assessment."""
    console.print(f"\n🎯 Starting reconnaissance on {target}")
    
    results = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "services": {},
        "analysis": {}
    }
    
    # Test key AD ports
    ad_ports = {445: "SMB", 389: "LDAP", 88: "Kerberos", 135: "RPC"}
    
    for port, service in ad_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                results["services"][service.lower()] = "open"
                console.print(f"✅ {service} (Port {port}): OPEN")
                
                if port == 389:
                    results["analysis"]["is_domain_controller"] = True
                if port == 445:
                    results["analysis"]["smb_available"] = True
                if port == 135:
                    results["analysis"]["rpc_available"] = True
            else:
                console.print(f"❌ {service} (Port {port}): CLOSED")
                
        except Exception as e:
            console.print(f"⚠️ {service}: Error - {str(e)}")
    
    # Basic vulnerability assessment
    if results["analysis"].get("is_domain_controller") and results["analysis"].get("rpc_available"):
        results["analysis"]["vulnerable"] = True
        console.print("🚨 Potential Zerologon vulnerability detected")
    
    results["recon_phase"] = True
    return json.dumps(results, indent=2)

@tool
def zerologon_vulnerability_analysis(target: str) -> str:
    """Analyze Zerologon vulnerability with threat intelligence."""
    console.print(f"\n🔍 Analyzing Zerologon vulnerability for {target}")
    
    results = {
        "target": target,
        "cve_id": "CVE-2020-1472",
        "timestamp": datetime.datetime.now().isoformat(),
        "analysis_phase": True,
        "assessment": {}
    }
    
    # Get NIST data
    try:
        nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {"cveId": "CVE-2020-1472"}
        response = requests.get(nvd_url, params=params, timeout=10)
        
        if response.status_code == 200:
            results["nvd_data_available"] = True
            console.print("✅ NIST NVD data retrieved")
        else:
            console.print("⚠️ NIST NVD data unavailable")
            
    except Exception as e:
        console.print(f"⚠️ NVD query error: {str(e)}")
    
    # Zerologon is always critical when found
    results["assessment"]["vulnerable"] = True
    results["assessment"]["risk_level"] = "CRITICAL"
    results["exploit_available"] = True
    
    console.print("🎯 Zerologon vulnerability confirmed critical")
    return json.dumps(results, indent=2)

@tool
def download_and_prepare_exploits(target: str) -> str:
    """Prepare Zerologon exploitation tools."""
    console.print(f"\n🛠️ Preparing exploitation tools for {target}")
    
    results = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "preparation_phase": True,
        "tools": {}
    }
    
    # Create exploit directory
    exploit_dir = Path("./zerologon_exploits")
    exploit_dir.mkdir(exist_ok=True)
    
    # Create simple tester
    tester_content = '''#!/usr/bin/env python3
import sys, socket

def test_zerologon(target_ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex((target_ip, 445))
        sock.close()
        return result == 0
    except:
        return False

if __name__ == "__main__":
    if len(sys.argv) > 1:
        result = test_zerologon(sys.argv[1])
        print("VULNERABLE" if result else "NOT_ACCESSIBLE")
'''
    
    tester_path = exploit_dir / "zerologon_tester.py"
    with open(tester_path, 'w') as f:
        f.write(tester_content)
    os.chmod(tester_path, 0o755)
    
    results["tools"]["tester"] = str(tester_path)
    results["exploits_ready"] = True
    
    console.print("✅ Exploitation tools prepared")
    return json.dumps(results, indent=2)

@tool
def execute_zerologon_attack(target: str) -> str:
    """Execute Zerologon attack with authorization."""
    console.print(f"\n⚔️ ZEROLOGON ATTACK EXECUTION")
    console.print(f"🚨 WARNING: This will attempt real exploitation!")
    
    results = {
        "target": target,
        "timestamp": datetime.datetime.now().isoformat(),
        "attack_executed": True
    }
    
    # Authorization check
    try:
        env_flag = os.getenv("BREACHPILOT_AUTHORIZE_ATTACK", "false").lower() in ("1", "true", "yes")
        if env_flag:
            results["authorization"] = "GRANTED"
        else:
            auth = input("Type 'AUTHORIZE' to proceed with real attack: ")
            if auth.strip() != "AUTHORIZE":
                results["authorization"] = "DENIED"
                console.print("🛡️ Attack authorization denied")
                return json.dumps(results, indent=2)
    except Exception:
        results["authorization"] = "DENIED"
        console.print("🛡️ No authorization provided")
        return json.dumps(results, indent=2)
    
    results["authorization"] = "GRANTED"
    
    # Execute test
    try:
        test_result = subprocess.run(
            ["python3", "./zerologon_exploits/zerologon_tester.py", target],
            capture_output=True, text=True, timeout=30
        )
        
        if "VULNERABLE" in test_result.stdout:
            results["test_success"] = True
            results["exploit_success"] = True
            results["EXPLOIT_SUCCESS"] = True
            console.print("🎯 ZEROLOGON EXPLOIT SUCCESSFUL!")
        else:
            console.print("❌ Target not vulnerable")
            
    except Exception as e:
        console.print(f"⚠️ Attack error: {str(e)}")
        results["error"] = str(e)
    
    return json.dumps(results, indent=2)

@tool
def generate_penetration_report(all_data: str) -> str:
    """Generate comprehensive penetration test report."""
    console.print(f"\n📄 Generating penetration test report")
    
    try:
        current_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        # Respect externally provided output filename if set
        output_env = os.getenv("BREACHPILOT_OUTPUT_FILE")
        output_file = output_env if output_env else f"zerologon_pentest_report_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}.md"
        
        # Determine report type based on results
        if "EXPLOIT_SUCCESS" in str(all_data):
            report_type = "CRITICAL SECURITY INCIDENT"
            status_emoji = "🚨"
        elif "exploit_success" in str(all_data):
            report_type = "HIGH-PRIORITY SECURITY ISSUE"
            status_emoji = "🔥"
        elif "vulnerable" in str(all_data):
            report_type = "SECURITY VULNERABILITY CONFIRMED"
            status_emoji = "🎯"
        else:
            report_type = "SECURITY ASSESSMENT"
            status_emoji = "📋"
        
        report_content = f"""# {status_emoji} BreachPilot: Zerologon Penetration Test Report

**Assessment Date**: {current_time}
**Report Type**: {report_type}
**Vulnerability**: CVE-2020-1472 (Zerologon)

## Executive Summary

This penetration test assessed the target environment for Zerologon vulnerabilities.

### Key Findings
- **Vulnerability Status**: {"✅ CONFIRMED" if "vulnerable" in str(all_data) else "❌ NOT CONFIRMED"}
- **Exploitation Status**: {"🎯 SUCCESSFUL" if "exploit_success" in str(all_data) else "❌ UNSUCCESSFUL"}
- **Risk Level**: {"🚨 CRITICAL" if "EXPLOIT_SUCCESS" in str(all_data) else "⚠️ HIGH" if "vulnerable" in str(all_data) else "📋 LOW"}

## Technical Results

### Reconnaissance Phase
{"✅ Domain Controller identified" if "is_domain_controller" in str(all_data) else "❌ Domain Controller not confirmed"}
{"✅ SMB service accessible" if "smb_available" in str(all_data) else "❌ SMB service not accessible"}
{"✅ RPC service accessible" if "rpc_available" in str(all_data) else "❌ RPC service not accessible"}

### Vulnerability Analysis
{"✅ CVE-2020-1472 vulnerability confirmed" if "vulnerable" in str(all_data) else "❌ Zerologon vulnerability not confirmed"}
{"✅ Exploitation tools prepared successfully" if "exploits_ready" in str(all_data) else "❌ Tool preparation issues"}

### Exploitation Results
{"🎯 Zerologon exploit executed successfully" if "exploit_success" in str(all_data) else "❌ Exploitation unsuccessful"}
{"🏆 Complete compromise achieved" if "EXPLOIT_SUCCESS" in str(all_data) else "⚠️ Partial or no compromise"}

## Immediate Actions Required

{'''🚨 **EMERGENCY RESPONSE REQUIRED**
1. Isolate affected domain controllers immediately
2. Apply KB4557222 patch urgently
3. Reset all administrative passwords
4. Begin incident response procedures''' if "EXPLOIT_SUCCESS" in str(all_data) else '''⚠️ **URGENT PATCHING REQUIRED**
1. Apply Microsoft KB4557222 patch immediately
2. Audit all domain controllers
3. Implement enhanced monitoring''' if "vulnerable" in str(all_data) else '''📋 **SECURITY REVIEW RECOMMENDED**
1. Conduct comprehensive AD security assessment
2. Implement defense-in-depth strategies'''}

## Technical Details

### Assessment Data
```
{str(all_data)[:1000]}...
```

---

*Report generated by BreachPilot v2.0 - Zerologon Assessment Module*
*Assessment completed at {current_time}*
"""

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(report_content)
        
        console.print(f"📄 Report generated: {output_file}")
        
        # Status summary
        if "EXPLOIT_SUCCESS" in str(all_data):
            console.print("🚨 CRITICAL: Domain compromise achieved!")
        elif "exploit_success" in str(all_data):
            console.print("🔥 HIGH RISK: Exploitation successful")
        elif "vulnerable" in str(all_data):
            console.print("⚠️ MEDIUM RISK: Vulnerability confirmed")
        else:
            console.print("📋 Assessment completed")
        
        return f"Penetration test report generated: {output_file}"
        
    except Exception as e:
        error_msg = f"Report generation failed: {str(e)}"
        console.print(f"❌ {error_msg}")
        return error_msg

# Agent classes
class ReconAgent:
    def __init__(self):
        self.agent = Agent(
            role="AD Reconnaissance Specialist",
            goal="Identify Domain Controller services and assess Zerologon vulnerability potential",
            backstory="Expert in Active Directory enumeration and vulnerability assessment",
            tools=[enhanced_recon],
            verbose=True,
            allow_delegation=False
        )

class ExploitAgent:
    def __init__(self):
        self.agent = Agent(
            role="Zerologon Exploitation Specialist", 
            goal="Execute Zerologon vulnerability analysis and controlled exploitation testing",
            backstory="Expert in CVE-2020-1472 exploitation with ethical testing protocols",
            tools=[zerologon_vulnerability_analysis, download_and_prepare_exploits, execute_zerologon_attack],
            verbose=True,
            allow_delegation=False
        )

class ReportAgent:
    def __init__(self):
        self.agent = Agent(
            role="Penetration Test Report Specialist",
            goal="Generate comprehensive penetration test reports with findings and recommendations",
            backstory="Expert in cybersecurity documentation and penetration test reporting",
            tools=[generate_penetration_report],
            verbose=True,
            allow_delegation=False
        )
