#!/usr/bin/env python3
"""Demo script showing BreachPilot usage."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from breachpilot.core.crew import BreachPilotCrew
from rich.console import Console

console = Console()

def main():
    """Run a demo scan."""
    
    # Example target - use a safe test target
    target = "scanme.nmap.org"  # Safe target for testing
    
    console.print("[bold blue]🚀 BreachPilot Demo[/bold blue]")
    console.print(f"Target: {target}")
    console.print("This is a demonstration using a safe test target.\n")
    
    try:
        # Initialize crew
        crew = BreachPilotCrew(
            target=target,
            output_file="demo_report.md",
            verbose=True
        )
        
        # Run scan
        result = crew.run()
        
        console.print("\n[green]✅ Demo completed successfully![/green]")
        console.print(f"Report generated: demo_report.md")
        
    except Exception as e:
        console.print(f"\n[red]❌ Demo failed: {str(e)}[/red]")
        sys.exit(1)

if __name__ == "__main__":
    main()