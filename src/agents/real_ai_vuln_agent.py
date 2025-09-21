"""
Real AI-powered CVE Analysis and PoC Retrieval Agent
Uses actual AI agents to identify vulnerabilities and find exploits
"""
import os
import json
import asyncio
from typing import Dict, Any, List
from datetime import datetime

try:
    from crewai import Agent, Task, Crew, Process
    from crewai_tools import tool
    from langchain_anthropic import ChatAnthropic
    from langchain_openai import ChatOpenAI
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False


class RealAIVulnAgent:
    """Real AI agent for CVE analysis and PoC retrieval"""
    
    def __init__(self):
        self.llm = None
        if CREWAI_AVAILABLE:
            api_key = os.getenv("ANTHROPIC_API_KEY") or os.getenv("OPENAI_API_KEY")
            if os.getenv("ANTHROPIC_API_KEY"):
                self.llm = ChatAnthropic(
                    model="claude-3-5-sonnet-20241022",
                    api_key=os.getenv("ANTHROPIC_API_KEY"),
                    temperature=0.1
                )
            elif os.getenv("OPENAI_API_KEY"):
                self.llm = ChatOpenAI(
                    model="gpt-4o",
                    api_key=os.getenv("OPENAI_API_KEY"),
                    temperature=0.1
                )
    
    async def analyze_with_ai(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Run real AI analysis"""
        if not CREWAI_AVAILABLE or not self.llm:
            print("⚠️ AI not available, using fallback")
            return await self._fallback_analysis(scan_results)
        
        print("🤖 Starting real AI vulnerability analysis...")
        
        # Extract services
        services_text = self._format_services(scan_results)
        
        # Create agents
        cve_analyst = Agent(
            role='CVE Security Analyst',
            goal='Identify CVEs for detected services with high accuracy',
            backstory="""Expert cybersecurity analyst specializing in CVE identification.
            You analyze service versions and match them to known vulnerabilities in CVE databases.
            You provide accurate CVE IDs, CVSS scores, and detailed explanations.""",
            llm=self.llm,
            verbose=True
        )
        
        poc_researcher = Agent(
            role='Exploit Researcher', 
            goal='Find publicly available PoCs and exploits for identified CVEs',
            backstory="""Specialist in finding proof-of-concept exploits and working exploits.
            You search GitHub, ExploitDB, and security advisories for available exploits.
            You verify PoC availability and provide direct links when possible.""",
            llm=self.llm,
            verbose=True
        )
        
        # Create tasks
        cve_task = Task(
            description=f"""Analyze these services and identify CVEs:

{services_text}

For each service:
1. Identify specific CVEs that affect this version
2. Provide accurate CVSS score
3. Explain WHY this version is vulnerable
4. Assess severity (CRITICAL/HIGH/MEDIUM/LOW)

Return JSON format:
{{
  "vulnerabilities": [
    {{
      "cve": "CVE-YYYY-XXXXX",
      "service": "service name",
      "port": "port number",
      "version": "version string",
      "cvss_score": 9.8,
      "severity": "CRITICAL",
      "description": "clear description",
      "why_identified": "technical reason",
      "evidence": "version evidence"
    }}
  ]
}}""",
            agent=cve_analyst,
            expected_output="JSON with identified CVEs and explanations"
        )
        
        poc_task = Task(
            description=f"""For each CVE identified, research PoC availability:

Search for:
1. GitHub repositories with working exploits
2. ExploitDB entries
3. Metasploit modules
4. Public security advisories with PoCs

For each CVE provide:
- PoC availability status
- Direct links if available
- Attack complexity assessment

Add to existing CVE data under "poc_info" field.""",
            agent=poc_researcher,
            expected_output="Enhanced CVE data with PoC information",
            context=[cve_task]
        )
        
        # Execute
        crew = Crew(
            agents=[cve_analyst, poc_researcher],
            tasks=[cve_task, poc_task],
            process=Process.sequential,
            verbose=True
        )
        
        try:
            result = crew.kickoff()
            print(f"✅ AI analysis complete: {result}")
            
            # Parse result
            parsed = self._parse_ai_result(str(result))
            
            return {
                "timestamp": datetime.now().isoformat(),
                "analysis_method": "AI-powered (Real CrewAI)",
                "vulnerabilities": parsed.get("vulnerabilities", []),
                "xai_explanations": self._build_xai(parsed.get("vulnerabilities", [])),
                "raw_ai_output": str(result)
            }
            
        except Exception as e:
            print(f"❌ AI analysis error: {e}")
            return await self._fallback_analysis(scan_results)
    
    def _format_services(self, scan_results: Dict[str, Any]) -> str:
        """Format services for AI"""
        lines = []
        ports = scan_results.get("ports", [])
        
        for port in ports:
            lines.append(
                f"Port {port['port']}/{port['protocol']}: "
                f"{port['service']} {port.get('version', 'unknown version')}"
            )
        
        return "\n".join(lines) if lines else "No services detected"
    
    def _parse_ai_result(self, result: str) -> Dict[str, Any]:
        """Parse AI output"""
        try:
            # Try to extract JSON
            import re
            json_match = re.search(r'\{.*\}', result, re.DOTALL)
            if json_match:
                return json.loads(json_match.group())
            
            # Fallback: extract structured data
            vulns = []
            if "CVE-" in result:
                # Simple extraction
                cve_matches = re.findall(r'CVE-\d{4}-\d+', result)
                for cve in cve_matches[:5]:  # Limit to 5
                    vulns.append({
                        "cve": cve,
                        "severity": "HIGH",
                        "cvss_score": 7.5,
                        "description": f"Vulnerability {cve} identified by AI",
                        "why_identified": "AI pattern matching",
                        "evidence": "Service version analysis"
                    })
            
            return {"vulnerabilities": vulns}
            
        except Exception as e:
            print(f"Parse error: {e}")
            return {"vulnerabilities": []}
    
    def _build_xai(self, vulnerabilities: List[Dict]) -> Dict[str, Any]:
        """Build XAI explanations"""
        xai = {}
        for vuln in vulnerabilities:
            cve = vuln.get("cve")
            if cve:
                xai[cve] = {
                    "why_identified": vuln.get("why_identified", "AI analysis"),
                    "evidence": vuln.get("evidence", "Version match"),
                    "attack_vector": vuln.get("attack_vector", "Network"),
                    "impact": vuln.get("impact", "Potential compromise"),
                    "poc_available": vuln.get("poc_info", {}).get("available", "Unknown")
                }
        return xai
    
    async def _fallback_analysis(self, scan_results: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback when AI unavailable"""
        print("📊 Using fallback CVE matching...")
        
        vulnerabilities = []
        
        # CVE database for common services
        cve_db = {
            "apache": {
                "2.4": [
                    {
                        "cve": "CVE-2021-44228",
                        "description": "Apache Log4Shell vulnerability",
                        "cvss_score": 10.0,
                        "severity": "CRITICAL",
                        "why_identified": "Apache 2.4 may use Log4j",
                        "poc_available": "Yes - Multiple PoCs on GitHub"
                    }
                ],
                "2.2": [
                    {
                        "cve": "CVE-2017-15715",
                        "description": "Apache expression parsing vulnerability",
                        "cvss_score": 8.1,
                        "severity": "HIGH",
                        "why_identified": "Version 2.2 is vulnerable",
                        "poc_available": "Yes - ExploitDB"
                    }
                ]
            },
            "openssh": {
                "7.": [
                    {
                        "cve": "CVE-2018-15473",
                        "description": "OpenSSH username enumeration",
                        "cvss_score": 5.3,
                        "severity": "MEDIUM",
                        "why_identified": "OpenSSH 7.x vulnerable to user enum",
                        "poc_available": "Yes - Python script available"
                    }
                ]
            },
            "mysql": {
                "5.7": [
                    {
                        "cve": "CVE-2020-14559",
                        "description": "MySQL Server vulnerability",
                        "cvss_score": 6.5,
                        "severity": "MEDIUM",
                        "why_identified": "MySQL 5.7 vulnerable",
                        "poc_available": "Limited"
                    }
                ]
            }
        }
        
        ports = scan_results.get("ports", [])
        
        for port in ports:
            service = port.get("service", "").lower()
            version = port.get("version", "").lower()
            
            for svc_name, versions in cve_db.items():
                if svc_name in service or svc_name in version:
                    for ver_pattern, cves in versions.items():
                        if ver_pattern in version:
                            for cve_data in cves:
                                vulnerabilities.append({
                                    **cve_data,
                                    "port": port["port"],
                                    "service": port["service"],
                                    "evidence": f"Service version: {port.get('version', 'unknown')}"
                                })
        
        # Build XAI
        xai = {}
        for v in vulnerabilities:
            xai[v["cve"]] = {
                "why_identified": v.get("why_identified"),
                "evidence": v.get("evidence"),
                "attack_vector": "Network-based",
                "impact": "Potential system compromise",
                "poc_available": v.get("poc_available")
            }
        
        return {
            "timestamp": datetime.now().isoformat(),
            "analysis_method": "Pattern-based (Fallback)",
            "vulnerabilities": vulnerabilities,
            "xai_explanations": xai
        }


# Global instance
_real_ai_agent = None

def get_real_ai_agent() -> RealAIVulnAgent:
    """Get real AI agent instance"""
    global _real_ai_agent
    if _real_ai_agent is None:
        _real_ai_agent = RealAIVulnAgent()
    return _real_ai_agent
