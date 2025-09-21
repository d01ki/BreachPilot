"""
Real AI agents for CVE analysis and PoC retrieval with JSON-based communication
"""
import os
import json
import asyncio
from typing import Dict, Any, List
from datetime import datetime
from pathlib import Path

try:
    from crewai import Agent, Task, Crew, Process
    from langchain_openai import ChatOpenAI
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class RealAISecurityAgents:
    """Real AI agents using OpenAI with JSON file communication"""
    
    def __init__(self):
        self.llm = None
        if CREWAI_AVAILABLE:
            openai_key = os.getenv("OPENAI_API_KEY")
            if openai_key:
                self.llm = ChatOpenAI(
                    model="gpt-4o-mini",  # or gpt-4o for better results
                    api_key=openai_key,
                    temperature=0.1
                )
                print(f"✅ OpenAI API configured")
            else:
                print("⚠️ OPENAI_API_KEY not set")
    
    async def analyze_vulnerabilities(
        self, 
        scan_results: Dict[str, Any],
        chain_id: str
    ) -> Dict[str, Any]:
        """Run real AI vulnerability analysis"""
        if not CREWAI_AVAILABLE or not self.llm:
            print("⚠️ AI not available, using fallback")
            return await self._fallback_analysis(scan_results)
        
        print("🤖 Starting Real AI Security Analysis...")
        
        # Save scan results to JSON for agents
        work_dir = Path("reports") / chain_id / "agent_work"
        work_dir.mkdir(parents=True, exist_ok=True)
        
        scan_file = work_dir / "scan_results.json"
        with open(scan_file, 'w') as f:
            json.dump(scan_results, f, indent=2)
        
        # Create agents
        cve_analyst = self._create_cve_analyst()
        poc_hunter = self._create_poc_hunter()
        
        # Create tasks with JSON file I/O
        cve_task = Task(
            description=f"""Analyze the scan results and identify CVEs.

Input file: {scan_file}
Output file: {work_dir}/cve_analysis.json

Read the scan results from the input file and identify:
1. Specific CVEs for each service/version
2. CVSS scores and severity
3. Technical explanation of WHY each CVE applies
4. Evidence from the scan

Output JSON format:
{{
  "vulnerabilities": [
    {{
      "cve": "CVE-YYYY-XXXXX",
      "service": "service name",
      "port": "port number",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "detailed description",
      "why_identified": "technical reasoning",
      "evidence": "version/service evidence"
    }}
  ]
}}

Save results to output file.""",
            agent=cve_analyst,
            expected_output="JSON file with CVE analysis"
        )
        
        poc_task = Task(
            description=f"""Find PoC exploits for identified CVEs.

Input file: {work_dir}/cve_analysis.json
Output file: {work_dir}/poc_results.json

For each CVE in the input:
1. Search for GitHub repositories with exploits
2. Check ExploitDB entries
3. Look for Metasploit modules
4. Find public advisories with PoCs

Output JSON format:
{{
  "poc_findings": [
    {{
      "cve": "CVE-YYYY-XXXXX",
      "poc_available": true/false,
      "github_repos": ["url1", "url2"],
      "exploitdb_entries": ["edb-id1"],
      "metasploit_modules": ["exploit/linux/..."],
      "attack_complexity": "LOW/MEDIUM/HIGH",
      "poc_description": "brief description"
    }}
  ]
}}

Save results to output file.""",
            agent=poc_hunter,
            expected_output="JSON file with PoC information",
            context=[cve_task]
        )
        
        # Execute crew
        crew = Crew(
            agents=[cve_analyst, poc_hunter],
            tasks=[cve_task, poc_task],
            process=Process.sequential,
            verbose=True
        )
        
        try:
            print("⏳ AI agents working...")
            result = crew.kickoff()
            print(f"✅ AI analysis complete")
            
            # Read results from JSON files
            cve_data = self._read_json_file(work_dir / "cve_analysis.json")
            poc_data = self._read_json_file(work_dir / "poc_results.json")
            
            # Merge results
            merged = self._merge_results(cve_data, poc_data)
            
            # Sort by risk (CVSS score)
            if merged.get("vulnerabilities"):
                merged["vulnerabilities"].sort(
                    key=lambda x: x.get("cvss_score", 0),
                    reverse=True
                )
            
            return {
                "timestamp": datetime.now().isoformat(),
                "analysis_method": "Real AI (OpenAI GPT-4o)",
                "vulnerabilities": merged.get("vulnerabilities", []),
                "xai_explanations": self._build_xai(merged.get("vulnerabilities", [])),
                "raw_ai_output": str(result)
            }
            
        except Exception as e:
            print(f"❌ AI analysis error: {e}")
            return await self._fallback_analysis(scan_results)
    
    def _create_cve_analyst(self) -> Agent:
        """Create CVE analyst agent"""
        return Agent(
            role='CVE Security Analyst',
            goal='Identify accurate CVEs for detected services with detailed technical analysis',
            backstory="""You are an expert cybersecurity analyst with deep knowledge of CVE databases.
            You carefully analyze service versions and match them to known vulnerabilities.
            You provide precise CVE IDs, CVSS scores, and clear technical explanations.
            You work with JSON files for data exchange.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False
        )
    
    def _create_poc_hunter(self) -> Agent:
        """Create PoC hunter agent"""
        return Agent(
            role='Exploit & PoC Hunter',
            goal='Find publicly available proof-of-concept exploits and working code',
            backstory="""You are a specialist in finding exploit code and PoCs.
            You search GitHub, ExploitDB, Metasploit, and security advisories.
            You verify PoC availability and provide direct links.
            You assess exploit complexity and reliability.
            You work with JSON files for data exchange.""",
            llm=self.llm,
            verbose=True,
            allow_delegation=False
        )
    
    def _read_json_file(self, filepath: Path) -> Dict[str, Any]:
        """Read JSON file"""
        try:
            if filepath.exists():
                with open(filepath, 'r') as f:
                    return json.load(f)
        except Exception as e:
            print(f"Error reading {filepath}: {e}")
        return {}
    
    def _merge_results(
        self, 
        cve_data: Dict[str, Any], 
        poc_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Merge CVE and PoC results"""
        vulnerabilities = cve_data.get("vulnerabilities", [])
        poc_findings = poc_data.get("poc_findings", [])
        
        # Create PoC lookup
        poc_map = {p.get("cve"): p for p in poc_findings}
        
        # Merge into vulnerabilities
        for vuln in vulnerabilities:
            cve = vuln.get("cve")
            if cve in poc_map:
                poc_info = poc_map[cve]
                vuln["poc_available"] = poc_info.get("poc_available", False)
                vuln["github_repos"] = poc_info.get("github_repos", [])
                vuln["exploitdb_entries"] = poc_info.get("exploitdb_entries", [])
                vuln["metasploit_modules"] = poc_info.get("metasploit_modules", [])
                vuln["attack_complexity"] = poc_info.get("attack_complexity", "UNKNOWN")
                vuln["poc_description"] = poc_info.get("poc_description", "")
        
        return {"vulnerabilities": vulnerabilities}
    
    def _build_xai(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Build XAI explanations"""
        xai = {}
        for vuln in vulnerabilities:
            cve = vuln.get("cve")
            if cve:
                poc_status = "Available" if vuln.get("poc_available") else "Not found"
                if vuln.get("github_repos"):
                    poc_status = f"GitHub: {len(vuln.get('github_repos', []))} repos"
                elif vuln.get("exploitdb_entries"):
                    poc_status = f"ExploitDB: {', '.join(vuln.get('exploitdb_entries', []))}"
                
                xai[cve] = {
                    "why_identified": vuln.get("why_identified", "AI analysis"),
                    "evidence": vuln.get("evidence", "Service version match"),
                    "attack_vector": "Network-based",
                    "impact": self._assess_impact(vuln.get("cvss_score", 0)),
                    "poc_available": poc_status
                }
        return xai
    
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
    
    async def _fallback_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback when AI unavailable"""
        print("📊 Using fallback pattern matching...")
        
        vulnerabilities = []
        
        # Enhanced CVE database with PoC info
        cve_db = {
            "apache": {
                "2.4": {
                    "cve": "CVE-2021-44228",
                    "description": "Apache Log4Shell - Remote Code Execution",
                    "cvss_score": 10.0,
                    "severity": "CRITICAL",
                    "why_identified": "Apache 2.4.x commonly uses vulnerable Log4j library",
                    "poc_available": True,
                    "github_repos": ["https://github.com/christophetd/log4shell-vulnerable-app"],
                    "exploitdb_entries": ["EDB-50592"]
                }
            },
            "openssh": {
                "7.": {
                    "cve": "CVE-2018-15473",
                    "description": "OpenSSH Username Enumeration",
                    "cvss_score": 5.3,
                    "severity": "MEDIUM",
                    "why_identified": "OpenSSH 7.x vulnerable to timing-based user enumeration",
                    "poc_available": True,
                    "github_repos": ["https://github.com/epi052/cve-2018-15473"],
                    "exploitdb_entries": []
                }
            },
            "mysql": {
                "5.": {
                    "cve": "CVE-2020-14559",
                    "description": "MySQL Server Information Disclosure",
                    "cvss_score": 6.5,
                    "severity": "MEDIUM",
                    "why_identified": "MySQL 5.x versions affected",
                    "poc_available": False,
                    "github_repos": [],
                    "exploitdb_entries": []
                }
            },
            "tomcat": {
                "9.": {
                    "cve": "CVE-2020-1938",
                    "description": "Apache Tomcat AJP Request Injection (Ghostcat)",
                    "cvss_score": 9.8,
                    "severity": "CRITICAL",
                    "why_identified": "Tomcat 9.x vulnerable to AJP connector exploit",
                    "poc_available": True,
                    "github_repos": ["https://github.com/YDHCUI/CNVD-2020-10487-Tomcat-Ajp-lfi"],
                    "exploitdb_entries": ["EDB-48143"]
                }
            }
        }
        
        ports = scan_results.get("ports", [])
        
        for port in ports:
            service = port.get("service", "").lower()
            version = port.get("version", "").lower()
            
            for svc_name, versions in cve_db.items():
                if svc_name in service or svc_name in version:
                    for ver_pattern, cve_data in versions.items():
                        if ver_pattern in version:
                            vuln = {
                                **cve_data,
                                "port": port["port"],
                                "service": port["service"],
                                "evidence": f"Service: {port.get('service')} {port.get('version', '')}"
                            }
                            vulnerabilities.append(vuln)
        
        # Sort by CVSS score
        vulnerabilities.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        
        # Build XAI
        xai = {}
        for v in vulnerabilities:
            poc_status = "Available on GitHub" if v.get("github_repos") else "Not found"
            xai[v["cve"]] = {
                "why_identified": v.get("why_identified"),
                "evidence": v.get("evidence"),
                "attack_vector": "Network-based",
                "impact": self._assess_impact(v.get("cvss_score", 0)),
                "poc_available": poc_status
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_method": "Pattern-based Fallback",
            "vulnerabilities": vulnerabilities,
            "xai_explanations": xai
        }


# Global instance
_ai_agents = None

def get_ai_security_agents() -> RealAISecurityAgents:
    """Get AI agents instance"""
    global _ai_agents
    if _ai_agents is None:
        _ai_agents = RealAISecurityAgents()
    return _ai_agents
