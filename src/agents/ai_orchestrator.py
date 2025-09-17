"""
BreachPilot AI Agent Core
CrewAI + Claude + OpenAI統合による自律的ペネトレーションテスト支援
"""
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

from crewai import Agent, Task, Crew, Process
from crewai.tools import BaseTool
from pydantic import BaseModel
import openai
from anthropic import Anthropic

from ..utils.config import load_config


class BreachPilotTool(BaseTool):
    """Base tool class for BreachPilot custom tools"""
    name: str = "BreachPilot Tool"
    description: str = "A tool for penetration testing automation"
    
    def _run(self, **kwargs) -> str:
        raise NotImplementedError


class ScanAnalysisTool(BreachPilotTool):
    """Scan result analysis tool"""
    name: str = "scan_analysis"
    description: str = "Analyze network scan results and identify potential vulnerabilities"
    
    def _run(self, scan_data: str) -> str:
        """Analyze scan results and provide vulnerability assessment"""
        try:
            data = json.loads(scan_data) if isinstance(scan_data, str) else scan_data
            
            analysis = {
                "target": data.get("target", "unknown"),
                "open_ports": [],
                "vulnerabilities": [],
                "recommendations": []
            }
            
            # Extract open ports
            for port_info in data.get("ports", []):
                if port_info.get("state") == "open":
                    analysis["open_ports"].append({
                        "port": port_info.get("port"),
                        "service": port_info.get("service"),
                        "product": port_info.get("product"),
                        "version": port_info.get("version")
                    })
            
            # Vulnerability analysis based on open ports
            open_port_nums = [p.get("port") for p in analysis["open_ports"]]
            
            # Check for AD/DC indicators
            if 389 in open_port_nums and 445 in open_port_nums:
                analysis["vulnerabilities"].append({
                    "type": "Domain Controller Detection",
                    "severity": "info",
                    "description": "Target appears to be a Windows Domain Controller",
                    "cve": None
                })
                
            if 88 in open_port_nums:
                analysis["vulnerabilities"].append({
                    "type": "Kerberos Service",
                    "severity": "medium",
                    "description": "Kerberos authentication service detected - potential for Zerologon attack",
                    "cve": "CVE-2020-1472"
                })
                analysis["recommendations"].append("Test for Zerologon vulnerability (CVE-2020-1472)")
                
            if 445 in open_port_nums:
                analysis["vulnerabilities"].append({
                    "type": "SMB Service",
                    "severity": "medium", 
                    "description": "SMB service detected - check for SMB vulnerabilities",
                    "cve": None
                })
                analysis["recommendations"].append("Enumerate SMB shares and test for known SMB vulnerabilities")
            
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            return f"Error analyzing scan data: {str(e)}"


class PoCSearchTool(BreachPilotTool):
    """PoC search and ranking tool"""
    name: str = "poc_search"
    description: str = "Search and rank Proof of Concept exploits from various sources"
    
    def _run(self, vulnerability: str, cve: str = "") -> str:
        """Search for relevant PoC exploits"""
        try:
            # This would integrate with the existing poc_agent functionality
            # For now, return structured data about CVE-2020-1472
            if "zerologon" in vulnerability.lower() or cve == "CVE-2020-1472":
                poc_info = {
                    "cve": "CVE-2020-1472",
                    "name": "Zerologon",
                    "severity": "critical",
                    "cvss": 10.0,
                    "description": "An elevation of privilege vulnerability in Microsoft Windows Netlogon Remote Protocol",
                    "poc_sources": [
                        {
                            "source": "GitHub",
                            "url": "https://github.com/SecuraBV/CVE-2020-1472",
                            "quality": "high",
                            "language": "python"
                        },
                        {
                            "source": "ExploitDB",
                            "url": "https://www.exploit-db.com/exploits/48731",
                            "quality": "high",
                            "language": "python"
                        }
                    ],
                    "prerequisites": ["Network access to target DC", "Python environment"],
                    "impact": "Complete domain compromise"
                }
                return json.dumps(poc_info, indent=2)
            else:
                return json.dumps({"error": "No PoC found for specified vulnerability"})
                
        except Exception as e:
            return f"Error searching for PoC: {str(e)}"


class ExploitAnalysisTool(BreachPilotTool):
    """Exploit result analysis tool"""
    name: str = "exploit_analysis"
    description: str = "Analyze exploit execution results and determine success/failure"
    
    def _run(self, exploit_log: str) -> str:
        """Analyze exploit execution logs"""
        try:
            log_data = json.loads(exploit_log) if isinstance(exploit_log, str) else exploit_log
            
            analysis = {
                "status": "unknown",
                "success_indicators": [],
                "failure_indicators": [],
                "recommendations": [],
                "timeline": []
            }
            
            # Analyze log entries
            if isinstance(log_data, list):
                for entry in log_data:
                    stage = entry.get("stage", "")
                    message = entry.get("msg", "")
                    
                    analysis["timeline"].append({
                        "timestamp": entry.get("t", 0),
                        "stage": stage,
                        "message": message
                    })
                    
                    # Success indicators
                    if "VULNERABLE" in message:
                        analysis["success_indicators"].append("Target confirmed vulnerable")
                        analysis["status"] = "success"
                    elif "authentication successful" in message.lower():
                        analysis["success_indicators"].append("Authentication bypass successful")
                        analysis["status"] = "success"
                    
                    # Failure indicators
                    elif "NOT_ACCESSIBLE" in message:
                        analysis["failure_indicators"].append("Target not accessible")
                        analysis["status"] = "failed"
                    elif "timeout" in message.lower():
                        analysis["failure_indicators"].append("Connection timeout")
                        analysis["status"] = "failed"
            
            # Generate recommendations
            if analysis["status"] == "success":
                analysis["recommendations"].extend([
                    "Immediate patching required",
                    "Monitor for suspicious authentication activities",
                    "Consider implementing additional network segmentation"
                ])
            elif analysis["status"] == "failed":
                analysis["recommendations"].extend([
                    "Verify target accessibility",
                    "Check firewall rules",
                    "Confirm target is running vulnerable service"
                ])
                
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            return f"Error analyzing exploit results: {str(e)}"


class AIAgentOrchestrator:
    """Main orchestrator for BreachPilot AI agents using CrewAI"""
    
    def __init__(self):
        self.config = load_config()
        self.anthropic_client = None
        self.openai_client = None
        
        # Initialize AI clients
        if self.config.get("ANTHROPIC_API_KEY"):
            self.anthropic_client = Anthropic(api_key=self.config["ANTHROPIC_API_KEY"])
            
        if self.config.get("OPENAI_API_KEY"):
            self.openai_client = openai.OpenAI(api_key=self.config["OPENAI_API_KEY"])
        
        # Initialize tools
        self.tools = [
            ScanAnalysisTool(),
            PoCSearchTool(),
            ExploitAnalysisTool()
        ]
    
    def create_scan_agent(self) -> Agent:
        """Create scan analysis agent"""
        return Agent(
            role="Vulnerability Scan Analyst",
            goal="Analyze network scan results to identify potential security vulnerabilities and attack vectors",
            backstory="""You are an expert penetration tester with deep knowledge of network services 
                        and common vulnerabilities. You excel at analyzing scan results to identify 
                        security weaknesses and prioritize threats.""",
            tools=[tool for tool in self.tools if tool.name == "scan_analysis"],
            verbose=True
        )
    
    def create_poc_agent(self) -> Agent:
        """Create PoC research agent"""
        return Agent(
            role="Exploit Research Specialist",
            goal="Research and evaluate Proof of Concept exploits for identified vulnerabilities",
            backstory="""You are a security researcher who specializes in finding and evaluating 
                        exploit code. You understand the nuances of different exploit techniques 
                        and can assess their reliability and potential impact.""",
            tools=[tool for tool in self.tools if tool.name == "poc_search"],
            verbose=True
        )
    
    def create_exploit_agent(self) -> Agent:
        """Create exploit analysis agent"""  
        return Agent(
            role="Exploit Execution Analyst",
            goal="Analyze exploit execution results to determine success and provide actionable insights",
            backstory="""You are an experienced penetration tester who specializes in exploit 
                        execution and result analysis. You can quickly determine if an attack 
                        was successful and provide recommendations for remediation.""",
            tools=[tool for tool in self.tools if tool.name == "exploit_analysis"],
            verbose=True
        )
    
    def create_report_agent(self) -> Agent:
        """Create report generation agent"""
        return Agent(
            role="Security Report Writer",
            goal="Generate comprehensive penetration testing reports that combine technical findings with business impact analysis",
            backstory="""You are a senior security consultant who excels at creating detailed, 
                        actionable security reports. You can translate technical vulnerabilities 
                        into business risks and provide clear remediation guidance.""",
            tools=[],
            verbose=True
        )
    
    def analyze_scan_results(self, scan_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Orchestrate scan analysis using AI agents"""
        try:
            # Create agents
            scan_agent = self.create_scan_agent()
            
            # Create task
            scan_task = Task(
                description=f"""Analyze the following network scan results and provide a comprehensive 
                               vulnerability assessment:
                               
                               {json.dumps(scan_data, indent=2)}
                               
                               Focus on:
                               1. Identifying open services and their versions
                               2. Highlighting potential vulnerabilities, especially Zerologon (CVE-2020-1472)
                               3. Assessing the security posture of the target
                               4. Providing prioritized recommendations""",
                agent=scan_agent,
                expected_output="A detailed JSON analysis of vulnerabilities and recommendations"
            )
            
            # Execute crew
            crew = Crew(
                agents=[scan_agent],
                tasks=[scan_task],
                process=Process.sequential,
                verbose=True
            )
            
            result = crew.kickoff()
            
            # Save result
            analysis_path = work_dir / "ai_scan_analysis.json"
            analysis_path.write_text(str(result))
            
            return {"status": "success", "result": str(result), "path": str(analysis_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def research_poc(self, vulnerability_info: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Orchestrate PoC research using AI agents"""
        try:
            # Create agents
            poc_agent = self.create_poc_agent()
            
            # Create task
            poc_task = Task(
                description=f"""Research and evaluate Proof of Concept exploits for the following vulnerability:
                               
                               {json.dumps(vulnerability_info, indent=2)}
                               
                               Focus on:
                               1. Finding reliable PoC exploits from trusted sources
                               2. Evaluating the quality and reliability of available exploits
                               3. Assessing the prerequisites and complexity of exploitation
                               4. Prioritizing the most suitable exploit for testing""",
                agent=poc_agent,
                expected_output="A detailed assessment of available PoC exploits with recommendations"
            )
            
            # Execute crew
            crew = Crew(
                agents=[poc_agent],
                tasks=[poc_task],
                process=Process.sequential,
                verbose=True
            )
            
            result = crew.kickoff()
            
            # Save result
            poc_path = work_dir / "ai_poc_research.json"
            poc_path.write_text(str(result))
            
            return {"status": "success", "result": str(result), "path": str(poc_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def analyze_exploit_results(self, exploit_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Orchestrate exploit result analysis using AI agents"""
        try:
            # Create agents
            exploit_agent = self.create_exploit_agent()
            
            # Create task
            exploit_task = Task(
                description=f"""Analyze the following exploit execution results:
                               
                               {json.dumps(exploit_data, indent=2)}
                               
                               Focus on:
                               1. Determining if the exploit was successful
                               2. Identifying key success or failure indicators
                               3. Assessing the potential impact of successful exploitation
                               4. Providing specific remediation recommendations""",
                agent=exploit_agent,
                expected_output="A comprehensive analysis of exploit results with actionable insights"
            )
            
            # Execute crew
            crew = Crew(
                agents=[exploit_agent],
                tasks=[exploit_task],
                process=Process.sequential,
                verbose=True
            )
            
            result = crew.kickoff()
            
            # Save result
            analysis_path = work_dir / "ai_exploit_analysis.json"
            analysis_path.write_text(str(result))
            
            return {"status": "success", "result": str(result), "path": str(analysis_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def generate_comprehensive_report(self, all_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Generate comprehensive report using Claude"""
        try:
            if not self.anthropic_client:
                return {"status": "error", "error": "Anthropic API key not configured"}
            
            # Prepare comprehensive data summary
            report_data = {
                "target": all_data.get("target", "unknown"),
                "timestamp": datetime.now().isoformat(),
                "scan_results": all_data.get("scan", {}),
                "poc_research": all_data.get("poc", {}),
                "exploit_results": all_data.get("exploit", {}),
                "ai_analysis": {
                    "scan": all_data.get("ai_scan_analysis", ""),
                    "poc": all_data.get("ai_poc_research", ""),
                    "exploit": all_data.get("ai_exploit_analysis", "")
                }
            }
            
            # Create comprehensive prompt for Claude
            prompt = f"""
            Generate a comprehensive penetration testing report based on the following data:

            {json.dumps(report_data, indent=2)}

            Please create a detailed report that includes:

            1. **Executive Summary**
               - Key findings and overall risk assessment
               - Business impact analysis
               - Critical recommendations

            2. **Technical Findings**
               - Detailed vulnerability analysis
               - Attack vectors and methodology
               - Proof of concept execution results

            3. **Risk Assessment**
               - CVSS scoring where applicable
               - Likelihood and impact assessment
               - Prioritized vulnerability ranking

            4. **Remediation Recommendations**
               - Immediate actions required
               - Long-term security improvements
               - Specific patch recommendations

            5. **Appendices**
               - Technical details and logs
               - References and additional resources

            Format the report in Markdown for easy conversion to PDF. Ensure the report is professional, 
            actionable, and suitable for both technical and executive audiences.
            """
            
            # Generate report using Claude
            response = self.anthropic_client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            report_content = response.content[0].text if response.content else "Error generating report"
            
            # Save report
            report_path = work_dir / "ai_comprehensive_report.md"
            report_path.write_text(report_content)
            
            return {"status": "success", "content": report_content, "path": str(report_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Global orchestrator instance
_orchestrator = None

def get_orchestrator() -> AIAgentOrchestrator:
    """Get global AI agent orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = AIAgentOrchestrator()
    return _orchestrator
