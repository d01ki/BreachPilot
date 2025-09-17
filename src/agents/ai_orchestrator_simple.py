"""
Simplified AI Orchestrator for dependency issues
Falls back to basic functionality when advanced AI packages are not available
"""
import os
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any

# Try to import AI dependencies, fall back to basic functionality if not available
try:
    from anthropic import Anthropic
    ANTHROPIC_AVAILABLE = True
except ImportError:
    ANTHROPIC_AVAILABLE = False

try:
    import openai
    OPENAI_AVAILABLE = True
except ImportError:
    OPENAI_AVAILABLE = False

try:
    from crewai import Agent, Task, Crew, Process
    from crewai.tools import BaseTool
    from pydantic import BaseModel
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

from ..utils.config import load_config


class BasicAnalysisTool:
    """Basic analysis tool when CrewAI is not available"""
    
    def __init__(self, name: str, description: str):
        self.name = name
        self.description = description
    
    def run(self, data: str) -> str:
        """Basic analysis without AI"""
        try:
            if "scan" in self.name.lower():
                return self.analyze_scan_basic(data)
            elif "poc" in self.name.lower():
                return self.analyze_poc_basic(data)
            elif "exploit" in self.name.lower():
                return self.analyze_exploit_basic(data)
            else:
                return f"Basic analysis completed for {self.name}"
        except Exception as e:
            return f"Analysis error: {str(e)}"
    
    def analyze_scan_basic(self, scan_data: str) -> str:
        """Basic scan analysis"""
        try:
            data = json.loads(scan_data) if isinstance(scan_data, str) else scan_data
            
            open_ports = []
            vulnerabilities = []
            
            for port_info in data.get("ports", []):
                if port_info.get("state") == "open":
                    open_ports.append(port_info.get("port"))
            
            # Basic vulnerability detection
            if 88 in open_ports and 445 in open_ports:
                vulnerabilities.append({
                    "type": "Potential Zerologon Vulnerability",
                    "severity": "Critical", 
                    "cve": "CVE-2020-1472",
                    "description": "Kerberos and SMB services detected - potential Zerologon vulnerability"
                })
            
            analysis = {
                "target": data.get("target", "unknown"),
                "open_ports": open_ports,
                "vulnerabilities": vulnerabilities,
                "recommendations": [
                    "Verify if target is a Domain Controller",
                    "Test for CVE-2020-1472 (Zerologon) if DC detected",
                    "Apply Microsoft security updates if vulnerable"
                ]
            }
            
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            return f"Scan analysis error: {str(e)}"
    
    def analyze_poc_basic(self, poc_data: str) -> str:
        """Basic PoC analysis"""
        try:
            data = json.loads(poc_data) if isinstance(poc_data, str) else poc_data
            
            analysis = {
                "cve": data.get("cve", "CVE-2020-1472"),
                "sources_found": len(data.get("sources", [])),
                "selected_poc": data.get("selected", {}).get("name", "None"),
                "assessment": "Basic PoC analysis completed - manual verification recommended"
            }
            
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            return f"PoC analysis error: {str(e)}"
    
    def analyze_exploit_basic(self, exploit_data: str) -> str:
        """Basic exploit analysis"""
        try:
            data = json.loads(exploit_data) if isinstance(exploit_data, str) else exploit_data
            
            success_indicators = 0
            failure_indicators = 0
            
            if isinstance(data, list):
                for entry in data:
                    message = entry.get("msg", "")
                    if "VULNERABLE" in message:
                        success_indicators += 1
                    elif "NOT_ACCESSIBLE" in message or "failed" in message.lower():
                        failure_indicators += 1
            
            analysis = {
                "status": "success" if success_indicators > 0 else "failed",
                "success_indicators": success_indicators,
                "failure_indicators": failure_indicators,
                "assessment": "Basic exploit analysis completed"
            }
            
            return json.dumps(analysis, indent=2)
            
        except Exception as e:
            return f"Exploit analysis error: {str(e)}"


class SimpleAIOrchestrator:
    """Simplified AI orchestrator with fallback capabilities"""
    
    def __init__(self):
        self.config = load_config()
        self.anthropic_client = None
        self.openai_client = None
        
        # Initialize AI clients if available
        if ANTHROPIC_AVAILABLE and self.config.get("ANTHROPIC_API_KEY"):
            try:
                self.anthropic_client = Anthropic(api_key=self.config["ANTHROPIC_API_KEY"])
            except Exception as e:
                print(f"Anthropic initialization failed: {e}")
                
        if OPENAI_AVAILABLE and self.config.get("OPENAI_API_KEY"):
            try:
                self.openai_client = openai.OpenAI(api_key=self.config["OPENAI_API_KEY"])
            except Exception as e:
                print(f"OpenAI initialization failed: {e}")
        
        # Initialize basic tools
        self.tools = {
            "scan_analysis": BasicAnalysisTool("scan_analysis", "Analyze scan results"),
            "poc_search": BasicAnalysisTool("poc_search", "Analyze PoC research"),
            "exploit_analysis": BasicAnalysisTool("exploit_analysis", "Analyze exploit results")
        }
    
    def analyze_scan_results(self, scan_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Analyze scan results with available capabilities"""
        try:
            if CREWAI_AVAILABLE and self.anthropic_client:
                return self._analyze_with_crewai("scan", scan_data, work_dir)
            else:
                return self._analyze_basic("scan", scan_data, work_dir)
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def research_poc(self, poc_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Research PoC with available capabilities"""
        try:
            if CREWAI_AVAILABLE and self.anthropic_client:
                return self._analyze_with_crewai("poc", poc_data, work_dir)
            else:
                return self._analyze_basic("poc", poc_data, work_dir)
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def analyze_exploit_results(self, exploit_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Analyze exploit results with available capabilities"""
        try:
            if CREWAI_AVAILABLE and self.anthropic_client:
                return self._analyze_with_crewai("exploit", exploit_data, work_dir)
            else:
                return self._analyze_basic("exploit", exploit_data, work_dir)
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def generate_comprehensive_report(self, all_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Generate report with available capabilities"""
        try:
            if self.anthropic_client:
                return self._generate_claude_report(all_data, work_dir)
            else:
                return self._generate_basic_report(all_data, work_dir)
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _analyze_basic(self, analysis_type: str, data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Basic analysis without AI"""
        tool_name = f"{analysis_type}_analysis"
        if tool_name in self.tools:
            result = self.tools[tool_name].run(json.dumps(data))
            
            # Save result
            result_path = work_dir / f"basic_{analysis_type}_analysis.json"
            result_path.write_text(result)
            
            return {"status": "success", "result": result, "path": str(result_path)}
        else:
            return {"status": "error", "error": f"No tool available for {analysis_type}"}
    
    def _analyze_with_crewai(self, analysis_type: str, data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Advanced analysis with CrewAI (when available)"""
        # This would contain the full CrewAI implementation
        # For now, fallback to basic analysis
        return self._analyze_basic(analysis_type, data, work_dir)
    
    def _generate_claude_report(self, all_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Generate report using Claude AI"""
        try:
            report_data = {
                "target": all_data.get("target", "unknown"),
                "timestamp": datetime.now().isoformat(),
                "scan_results": all_data.get("scan", {}),
                "poc_research": all_data.get("poc", {}),
                "exploit_results": all_data.get("exploit", {})
            }
            
            prompt = f"""
            Generate a comprehensive penetration testing report based on the following data:

            {json.dumps(report_data, indent=2)}

            Please create a detailed report that includes:
            1. Executive Summary with key findings
            2. Technical Findings with vulnerability details
            3. Risk Assessment with CVSS scoring
            4. Remediation Recommendations

            Format the report in Markdown for easy conversion to PDF.
            """
            
            response = self.anthropic_client.messages.create(
                model="claude-3-sonnet-20240229",
                max_tokens=4000,
                messages=[{"role": "user", "content": prompt}]
            )
            
            report_content = response.content[0].text if response.content else "Error generating report"
            
            # Save report
            report_path = work_dir / "claude_report.md"
            report_path.write_text(report_content)
            
            return {"status": "success", "content": report_content, "path": str(report_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _generate_basic_report(self, all_data: Dict[str, Any], work_dir: Path) -> Dict[str, Any]:
        """Generate basic report without AI"""
        try:
            report_content = f"""# Basic BreachPilot Report

**Target:** {all_data.get('target', 'unknown')}
**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

## Summary
This is a basic report generated without AI capabilities.
For full AI-powered analysis, please configure Anthropic API key.

## Raw Data
{json.dumps(all_data, indent=2)}

## Recommendations
- Review scan results manually
- Verify any potential vulnerabilities
- Apply security updates as needed
"""
            
            report_path = work_dir / "basic_report.md"
            report_path.write_text(report_content)
            
            return {"status": "success", "content": report_content, "path": str(report_path)}
            
        except Exception as e:
            return {"status": "error", "error": str(e)}


# Global orchestrator instance
_orchestrator = None

def get_orchestrator() -> SimpleAIOrchestrator:
    """Get global AI orchestrator instance"""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = SimpleAIOrchestrator()
    return _orchestrator
