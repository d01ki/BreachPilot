"""BreachPilot CrewAI implementation - Zerologon完全攻略版"""

import os
from crewai import Agent, Task, Crew, Process
from rich.console import Console

from .agents import ReconAgent, ExploitAgent, ReportAgent
from ..utils.logger import get_logger

console = Console()
logger = get_logger(__name__)

class BreachPilotCrew:
    """Main BreachPilot crew orchestrator - Full-chain Zerologon exploitation."""
    
    def __init__(self, target: str, output_file: str = "zerologon_pentest_report.md", verbose: bool = True):
        self.target = target
        self.output_file = output_file
        self.verbose = verbose
        
        # OpenAI API key check
        if not os.getenv('OPENAI_API_KEY'):
            console.print("[bold red]❌ OPENAI_API_KEY environment variable is not set![/bold red]")
            raise ValueError("OpenAI API key is required")
        
        # Initialize specialized agents
        self.recon_agent = ReconAgent()
        self.exploit_agent = ExploitAgent()  # Combined vulnerability analysis + exploitation
        self.report_agent = ReportAgent()
        
        self._setup_crew()
    
    def _setup_crew(self):
        """Setup the CrewAI crew with full-chain Zerologon exploitation tasks."""
        
        # Phase 1: Comprehensive Reconnaissance
        self.recon_task = Task(
            description=f"""Conduct comprehensive Active Directory reconnaissance on target {self.target}.
            
            Your mission:
            1. Perform AD-focused port scanning (53,88,135,139,389,445,etc.)
            2. Identify if target is a Domain Controller
            3. Enumerate SMB, LDAP, and Kerberos services
            4. Assess preliminary Zerologon vulnerability likelihood
            5. Use nmap with AD-specific scripts for detailed service detection
            
            Focus on identifying attack vectors for CVE-2020-1472 (Zerologon).""",
            agent=self.recon_agent.agent,
            expected_output="JSON with complete AD service enumeration, Domain Controller identification, and Zerologon vulnerability assessment potential"
        )
        
        # Phase 2-4: Full Exploitation Chain
        self.exploit_task = Task(
            description=f"""Execute complete Zerologon exploitation chain against {self.target}.
            
            Your mission:
            1. **Vulnerability Analysis**: Query NIST NVD and ExploitDB for CVE-2020-1472 intelligence
            2. **Exploit Preparation**: Download SecuraBV and dirkjanm Zerologon exploits
            3. **Authorization**: Obtain explicit user approval with 3-stage confirmation
            4. **Real Exploitation**: Execute actual Zerologon attack if authorized
            5. **Post-Exploitation**: Perform credential dumping with impacket if successful
            
            CRITICAL: This involves real penetration testing with potential domain compromise.
            Ensure proper authorization and safety measures.""",
            agent=self.exploit_agent.agent,
            expected_output="Complete exploitation results including vulnerability confirmation, exploit execution status, and domain compromise level (COMPLETE_COMPROMISE/PARTIAL/FAILED)",
            context=[self.recon_task]
        )
        
        # Phase 5: Comprehensive Report Generation
        self.report_task = Task(
            description=f"""Generate comprehensive penetration test report documenting complete Zerologon attack chain.
            
            Your mission:
            1. Document all phases: Reconnaissance → Vulnerability Analysis → Exploitation → Post-Exploitation
            2. Provide evidence of actual exploitation attempts and results
            3. Include emergency remediation guidance for confirmed vulnerabilities
            4. Generate executive summary with risk assessment and business impact
            5. Save complete report to {self.output_file}
            
            Focus on actionable intelligence and immediate response procedures.""",
            agent=self.report_agent.agent,
            expected_output="Professional penetration test report with complete attack chain documentation, evidence of exploitation, and emergency remediation guidance",
            context=[self.recon_task, self.exploit_task]
        )
        
        # Initialize full-chain penetration testing crew
        self.crew = Crew(
            agents=[self.recon_agent.agent, self.exploit_agent.agent, self.report_agent.agent],
            tasks=[self.recon_task, self.exploit_task, self.report_task],
            process=Process.sequential,
            verbose=self.verbose
        )
    
    def run(self):
        """Execute the complete Zerologon penetration test workflow."""
        
        console.print("[bold red]🎯 BreachPilot: Zerologon Full-Chain Exploitation[/bold red]")
        console.print(f"[bold]Target[/bold]: {self.target}")
        console.print(f"[bold]Objective[/bold]: Complete Active Directory compromise via CVE-2020-1472")
        console.print(f"[bold]Report[/bold]: {self.output_file}")
        
        console.print("\n[bold yellow]⚠️ WARNING: This is REAL PENETRATION TESTING[/bold yellow]")
        console.print("• Actual exploits will be downloaded and executed")
        console.print("• Domain controllers may be compromised")
        console.print("• Human authorization required for each phase")
        console.print("• Use only in authorized test environments")
        
        try:
            console.print("\n[bold blue]🚀 Initiating full-chain exploitation...[/bold blue]")
            
            # Execute the complete penetration test workflow
            result = self.crew.kickoff()
            
            console.print("\n[bold green]✅ Penetration test workflow completed![/bold green]")
            console.print(f"[green]📄 Full report available: {self.output_file}[/green]")
            
            # Provide final assessment summary
            if result and isinstance(result, str):
                if "COMPLETE_COMPROMISE" in result:
                    console.print("[bold red]🏆 CRITICAL RESULT: Domain fully compromised via Zerologon![/bold red]")
                    console.print("[bold red]⚠️ IMMEDIATE PATCHING AND INCIDENT RESPONSE REQUIRED[/bold red]")
                elif "exploit_success" in result:
                    console.print("[bold yellow]⚡ PARTIAL SUCCESS: Zerologon exploit executed[/bold yellow]")
                    console.print("[bold yellow]⚠️ URGENT VULNERABILITY REMEDIATION REQUIRED[/bold yellow]")
                elif "vulnerable" in result:
                    console.print("[bold blue]🎯 VULNERABILITY CONFIRMED: Target susceptible to Zerologon[/bold blue]")
                    console.print("[bold blue]📋 RECOMMEND IMMEDIATE PATCHING[/bold blue]")
            
            return {
                'success': True,
                'target': self.target,
                'output_file': self.output_file,
                'assessment_type': 'Full-Chain Zerologon Exploitation',
                'summary': str(result)
            }
            
        except KeyboardInterrupt:
            console.print("\n[yellow]⚠️ Penetration test interrupted by user[/yellow]")
            console.print("[yellow]Partial results may be available in report file[/yellow]")
            return {
                'success': False,
                'interrupted': True,
                'reason': 'User interruption'
            }
            
        except Exception as e:
            logger.error(f"Zerologon penetration test failed: {str(e)}")
            console.print(f"\n[red]❌ Critical error during penetration test: {str(e)}[/red]")
            
            # Provide troubleshooting guidance
            if "authorization" in str(e).lower():
                console.print("[yellow]💡 Check authorization and ensure you have explicit permission[/yellow]")
            elif "openai" in str(e).lower():
                console.print("[yellow]💡 Verify OPENAI_API_KEY is set correctly[/yellow]")
            elif "network" in str(e).lower() or "connection" in str(e).lower():
                console.print("[yellow]💡 Check network connectivity to target and external APIs[/yellow]")
            elif "impacket" in str(e).lower():
                console.print("[yellow]💡 Install impacket: pip install impacket[/yellow]")
            
            raise e
