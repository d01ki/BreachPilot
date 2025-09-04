"""BreachPilot CrewAI implementation."""

import json
import os
from typing import Dict, Any, Optional
from pathlib import Path

from crewai import Agent, Task, Crew, Process
from rich.console import Console
from rich.prompt import Confirm

from .agents import ReconAgent, PoCAgent, ReportAgent
from ..utils.logger import get_logger

console = Console()
logger = get_logger(__name__)


class BreachPilotCrew:
    """Main BreachPilot crew orchestrator."""
    
    def __init__(self, target: str, output_file: str = "report.md", verbose: bool = False):
        self.target = target
        self.output_file = output_file
        self.verbose = verbose
        self.scan_results = {}
        self.cve_selections = {}
        self.poc_results = {}
        
        # Initialize agents
        self.recon_agent = ReconAgent()
        self.poc_agent = PoCAgent()
        self.report_agent = ReportAgent()
        
        # Setup crew
        self._setup_crew()
    
    def _setup_crew(self):
        """Setup the CrewAI crew with agents and tasks."""
        
        # Define tasks
        self.recon_task = Task(
            description=f"Perform reconnaissance scan on target {self.target}. Use nmap to discover open ports, services, and versions. Structure the results in JSON format.",
            agent=self.recon_agent.agent,
            expected_output="JSON structured scan results with ports, services, and version information"
        )
        
        self.poc_task = Task(
            description="Analyze scan results and identify potential CVEs. Present findings to user for approval before proceeding.",
            agent=self.poc_agent.agent,
            expected_output="List of approved CVEs with PoC references and user consent status",
            context=[self.recon_task]
        )
        
        self.report_task = Task(
            description=f"Generate a comprehensive markdown report based on all findings and save to {self.output_file}",
            agent=self.report_agent.agent,
            expected_output="Complete markdown report with findings, CVEs, and recommendations",
            context=[self.recon_task, self.poc_task]
        )
        
        # Create crew
        self.crew = Crew(
            agents=[self.recon_agent.agent, self.poc_agent.agent, self.report_agent.agent],
            tasks=[self.recon_task, self.poc_task, self.report_task],
            process=Process.sequential,
            verbose=self.verbose
        )
    
    def run(self) -> Dict[str, Any]:
        """Execute the penetration testing workflow."""
        
        console.print("[bold]🔍 Starting Reconnaissance Phase...[/bold]")
        
        try:
            # Execute the crew workflow
            result = self.crew.kickoff()
            
            return {
                'success': True,
                'target': self.target,
                'output_file': self.output_file,
                'summary': str(result)
            }
            
        except Exception as e:
            logger.error(f"Crew execution failed: {str(e)}")
            raise e