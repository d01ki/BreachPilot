"""BreachPilot AI Agents implementation."""

import json
import subprocess
import os
from typing import Dict, Any, List
from pathlib import Path

from crewai import Agent
from crewai.tools import tool
from rich.console import Console
from rich.prompt import Confirm, Prompt
from rich.table import Table

from ..utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


@tool
def nmap_scan(target: str) -> str:
    """Perform nmap port scan on target."""
    try:
        cmd = [
            "nmap", "-sV", "-sC", "-O", 
            "--version-intensity", "5",
            "-oJ", f"/tmp/nmap_{target.replace('.', '_')}.json",
            target
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        
        if result.returncode == 0:
            # Try to read JSON output
            json_file = f"/tmp/nmap_{target.replace('.', '_')}.json"
            if os.path.exists(json_file):
                with open(json_file, 'r') as f:
                    return f.read()
            else:
                # Fallback to text output
                return result.stdout
        else:
            logger.error(f"Nmap scan failed: {result.stderr}")
            return f"Scan failed: {result.stderr}"
            
    except subprocess.TimeoutExpired:
        return "Scan timed out after 5 minutes"
    except Exception as e:
        logger.error(f"Nmap scan error: {str(e)}")
        return f"Scan error: {str(e)}"


@tool
def get_cve_info(service: str, version: str) -> str:
    """Get CVE information for a service and version."""
    # This is a simplified CVE lookup - in production, you'd use proper CVE databases
    cve_database = {
        "microsoft-ds": {
            "Windows 7": ["CVE-2017-0144", "CVE-2017-0143"],
            "Windows 10": ["CVE-2017-0144"],
            "default": ["CVE-2017-0144"]
        },
        "ssh": {
            "OpenSSH 7.4": ["CVE-2018-15473"],
            "default": ["CVE-2018-15473"]
        },
        "http": {
            "Apache 2.4": ["CVE-2021-41773"],
            "default": ["CVE-2021-41773"]
        }
    }
    
    service_cves = cve_database.get(service, {})
    cves = service_cves.get(version, service_cves.get("default", []))
    
    return json.dumps({
        "service": service,
        "version": version,
        "cves": cves
    })


@tool
def user_approval_cve(cve_list: str) -> str:
    """Get user approval for CVE candidates."""
    try:
        cves = json.loads(cve_list)
        approved_cves = []
        
        console.print("\n[bold yellow]🔍 CVE Candidates Found[/bold yellow]")
        
        table = Table()
        table.add_column("CVE", style="cyan")
        table.add_column("Service", style="green")
        table.add_column("Severity", style="red")
        
        if isinstance(cves, list):
            for cve in cves:
                table.add_row(cve, "Unknown", "Medium")
                if Confirm.ask(f"Approve {cve} for further analysis?"):
                    approved_cves.append(cve)
        elif isinstance(cves, dict):
            for cve in cves.get('cves', []):
                table.add_row(cve, cves.get('service', 'Unknown'), "Medium")
                if Confirm.ask(f"Approve {cve} for further analysis?"):
                    approved_cves.append(cve)
        
        console.print(table)
        
        return json.dumps({
            "approved_cves": approved_cves,
            "user_approved": True
        })
        
    except Exception as e:
        logger.error(f"User approval error: {str(e)}")
        return json.dumps({
            "approved_cves": [],
            "user_approved": False,
            "error": str(e)
        })


@tool
def generate_markdown_report(data: str, output_file: str) -> str:
    """Generate markdown report from analysis data."""
    try:
        import datetime
        report_data = json.loads(data) if isinstance(data, str) else data
        
        report_content = f"""# BreachPilot Penetration Test Report

**Generated**: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
**Target**: {report_data.get('target', 'Unknown')}

## Executive Summary

This report contains the findings from an automated penetration test conducted using BreachPilot.

## Target Information

- **Target**: {report_data.get('target', 'Unknown')}
- **Scan Date**: {datetime.datetime.now().strftime('%Y-%m-%d')}
- **Tool**: BreachPilot v0.1.0

## Findings

### Open Ports and Services

{report_data.get('scan_summary', 'No scan data available')}

### Identified Vulnerabilities

{report_data.get('vulnerability_summary', 'No vulnerabilities identified')}

### CVE Analysis

{report_data.get('cve_analysis', 'No CVE analysis performed')}

## Recommendations

1. **Patch Management**: Ensure all systems are updated with the latest security patches
2. **Service Hardening**: Review and harden exposed services
3. **Network Segmentation**: Implement proper network segmentation
4. **Monitoring**: Implement proper logging and monitoring

## Methodology

This assessment was conducted using:
- Nmap for port scanning and service detection
- AI-powered CVE analysis
- Human-in-the-loop validation for safety

## Disclaimer

This report is generated for educational and research purposes. All testing should be conducted only on systems you own or have explicit permission to test.
"""
        
        # Write report to file
        with open(output_file, 'w') as f:
            f.write(report_content)
        
        return f"Report successfully generated: {output_file}"
        
    except Exception as e:
        logger.error(f"Report generation error: {str(e)}")
        return f"Report generation failed: {str(e)}"


class ReconAgent:
    """Reconnaissance agent for information gathering."""
    
    def __init__(self):
        self.agent = Agent(
            role="Reconnaissance Specialist",
            goal="Perform thorough reconnaissance on target systems to identify open ports, services, and potential attack vectors",
            backstory="You are an expert in network reconnaissance with deep knowledge of nmap and service enumeration techniques.",
            tools=[nmap_scan],
            verbose=True,
            allow_delegation=False
        )


class PoCAgent:
    """Proof of Concept agent for vulnerability analysis."""
    
    def __init__(self):
        self.agent = Agent(
            role="Vulnerability Analyst",
            goal="Analyze discovered services for known vulnerabilities and get user approval for CVE investigation",
            backstory="You are a cybersecurity expert specializing in vulnerability assessment and CVE analysis. You always require human approval before proceeding with any potentially risky analysis.",
            tools=[get_cve_info, user_approval_cve],
            verbose=True,
            allow_delegation=False
        )


class ReportAgent:
    """Report generation agent."""
    
    def __init__(self):
        self.agent = Agent(
            role="Security Report Writer",
            goal="Generate comprehensive and professional security assessment reports in markdown format",
            backstory="You are a technical writer specializing in cybersecurity reports. You excel at creating clear, actionable reports that help organizations understand their security posture.",
            tools=[generate_markdown_report],
            verbose=True,
            allow_delegation=False
        )