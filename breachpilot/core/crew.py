"""BreachPilot CrewAI implementation - 実働重視版"""

import os
from crewai import Agent, Task, Crew, Process
from rich.console import Console

from .agents import ReconAgent, PoCAgent, ReportAgent
from ..utils.logger import get_logger

console = Console()
logger = get_logger(__name__)

class BreachPilotCrew:
    """Main BreachPilot crew orchestrator - Zerologon focused."""
    
    def __init__(self, target: str, output_file: str = "report.md", verbose: bool = False):
        self.target = target
        self.output_file = output_file
        self.verbose = verbose
        
        # OpenAI API key check
        if not os.getenv('OPENAI_API_KEY'):
            console.print("[bold red]❌ OPENAI_API_KEY environment variable is not set![/bold red]")
            raise ValueError("OpenAI API key is required")
        
        # Initialize agents
        self.recon_agent = ReconAgent()
        self.poc_agent = PoCAgent()
        self.report_agent = ReportAgent()
        
        self._setup_crew()
    
    def _setup_crew(self):
        """Setup the CrewAI crew with focused Zerologon tasks."""
        
        # 簡潔なタスク定義
        self.recon_task = Task(
            description=f"Scan {self.target} for Zerologon (CVE-2020-1472) vulnerability. Focus on SMB detection on ports 135,445,139.",
            agent=self.recon_agent.agent,
            expected_output="JSON with SMB detection results and Zerologon assessment potential"
        )
        
        self.poc_task = Task(
            description="Analyze for Zerologon vulnerability using NIST NVD and ExploitDB APIs. Download PoC if vulnerable. Get explicit user approval for any exploitation.",
            agent=self.poc_agent.agent,
            expected_output="Zerologon vulnerability assessment with PoC download status and user approval for execution",
            context=[self.recon_task]
        )
        
        self.report_task = Task(
            description=f"Generate focused Zerologon assessment report and save to {self.output_file}. Include NIST NVD data, ExploitDB findings, and user decisions.",
            agent=self.report_agent.agent,
            expected_output="Concise Zerologon-focused security assessment report with actionable recommendations",
            context=[self.recon_task, self.poc_task]
        )
        
        # 簡潔なクルー（ログ削減）
        self.crew = Crew(
            agents=[self.recon_agent.agent, self.poc_agent.agent, self.report_agent.agent],
            tasks=[self.recon_task, self.poc_task, self.report_task],
            process=Process.sequential,
            verbose=False  # ログ大幅削減
        )
    
    def run(self):
        """Execute the Zerologon-focused assessment workflow."""
        
        console.print("[bold]🎯 Starting Zerologon-focused assessment...[/bold]")
        console.print(f"[dim]Target: {self.target} | Focus: CVE-2020-1472[/dim]")
        
        try:
            # Execute the focused workflow
            result = self.crew.kickoff()
            
            return {
                'success': True,
                'target': self.target,
                'output_file': self.output_file,
                'focus': 'Zerologon CVE-2020-1472',
                'summary': str(result)
            }
            
        except Exception as e:
            logger.error(f"Zerologon assessment failed: {str(e)}")
            raise e
