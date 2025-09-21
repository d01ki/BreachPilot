"""
Simple vulnerability analyzer without OpenAI dependency
"""
import asyncio
from typing import Dict, Any, List
from datetime import datetime


class SimpleVulnAnalyzer:
    """Simple pattern-based vulnerability analyzer"""
    
    async def analyze(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze scan results and return vulnerabilities"""
        print("🔍 Analyzing with pattern matching...")
        
        vulnerabilities = []
        ports = scan_results.get("ports", [])
        
        # Pattern-based CVE detection
        for port in ports:
            service = port.get("service", "").lower()
            version = port.get("version", "").lower()
            
            # Check for Zerologon (Netlogon on DC)
            if "ldap" in service and "active directory" in version:
                vulnerabilities.append({
                    "cve": "CVE-2020-1472",
                    "description": "Zerologon - Netlogon Elevation of Privilege",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "port": port["port"],
                    "service": port["service"],
                    "why_identified": "Windows Domain Controller detected with Netlogon service",
                    "evidence": f"{port['service']} on port {port['port']}",
                    "poc_available": True,
                    "github_repos": ["https://github.com/dirkjanm/CVE-2020-1472", "https://github.com/SecuraBV/CVE-2020-1472"],
                    "exploitdb_entries": ["EDB-49071"]
                })
            
            # Check for SMBGhost
            if "microsoft-ds" in service:
                vulnerabilities.append({
                    "cve": "CVE-2020-0796",
                    "description": "SMBGhost - SMBv3 Remote Code Execution",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "port": port["port"],
                    "service": port["service"],
                    "why_identified": "SMB service on Windows Server detected",
                    "evidence": f"{port['service']} {port.get('version', '')}",
                    "poc_available": True,
                    "github_repos": ["https://github.com/chompie1337/SMBGhost_RCE_PoC"],
                    "exploitdb_entries": ["EDB-48267"]
                })
            
            # Check for BlueKeep
            if "ms-wbt-server" in service or "terminal services" in version:
                vulnerabilities.append({
                    "cve": "CVE-2019-0708",
                    "description": "BlueKeep - RDP Remote Code Execution",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "port": port["port"],
                    "service": port["service"],
                    "why_identified": "RDP service detected on port 3389",
                    "evidence": f"{port['service']} on port {port['port']}",
                    "poc_available": True,
                    "github_repos": ["https://github.com/robertdavidgraham/rdpscan"],
                    "exploitdb_entries": ["EDB-47683"]
                })
            
            # Check for Kerberos vulnerabilities
            if "kerberos" in service:
                vulnerabilities.append({
                    "cve": "CVE-2022-37966",
                    "description": "Kerberos Bronze Bit Attack",
                    "cvss_score": 8.1,
                    "severity": "HIGH",
                    "port": port["port"],
                    "service": port["service"],
                    "why_identified": "Kerberos authentication service detected",
                    "evidence": f"{port['service']} on port {port['port']}",
                    "poc_available": True,
                    "github_repos": ["https://github.com/ly4k/Certipy"],
                    "exploitdb_entries": []
                })
        
        # Remove duplicates and sort by CVSS
        seen = set()
        unique_vulns = []
        for v in vulnerabilities:
            if v["cve"] not in seen:
                seen.add(v["cve"])
                unique_vulns.append(v)
        
        unique_vulns.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        # Build XAI explanations
        xai = {}
        for v in unique_vulns:
            poc_info = []
            if v.get("github_repos"):
                poc_info.append(f"GitHub: {len(v['github_repos'])} repos")
            if v.get("exploitdb_entries"):
                poc_info.append(f"ExploitDB: {', '.join(v['exploitdb_entries'])}")
            
            xai[v["cve"]] = {
                "why_identified": v.get("why_identified"),
                "evidence": v.get("evidence"),
                "attack_vector": "Network-based",
                "impact": self._assess_impact(v.get("cvss_score", 0)),
                "poc_available": ", ".join(poc_info) if poc_info else "Not available"
            }
        
        print(f"✅ Found {len(unique_vulns)} vulnerabilities")
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_method": "Pattern-based Analysis",
            "vulnerabilities": unique_vulns,
            "xai_explanations": xai
        }
    
    def _assess_impact(self, cvss_score: float) -> str:
        """Assess impact based on CVSS"""
        if cvss_score >= 9.0:
            return "Critical - Complete system compromise likely"
        elif cvss_score >= 7.0:
            return "High - Significant security impact"
        elif cvss_score >= 4.0:
            return "Medium - Moderate security risk"
        else:
            return "Low - Limited security impact"


# Global instance
_analyzer = None

def get_simple_analyzer():
    """Get analyzer instance"""
    global _analyzer
    if _analyzer is None:
        _analyzer = SimpleVulnAnalyzer()
    return _analyzer
