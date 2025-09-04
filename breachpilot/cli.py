#!/usr/bin/env python3
"""BreachPilot CLI interface."""

import click
import json
import sys
from pathlib import Path
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from .core.crew import BreachPilotCrew
from .utils.logger import setup_logger

console = Console()
logger = setup_logger()


@click.command()
@click.option(
    "--target",
    "-t",
    required=True,
    help="Target IP address or hostname to scan"
)
@click.option(
    "--output",
    "-o",
    default="report.md",
    help="Output report filename (default: report.md)"
)
@click.option(
    "--verbose",
    "-v",
    is_flag=True,
    help="Enable verbose logging"
)
def main(target: str, output: str, verbose: bool):
    """BreachPilot - AI-powered penetration testing tool."""
    
    if verbose:
        logger.setLevel("DEBUG")
    
    console.print("[bold blue]🚀 BreachPilot - AI Penetration Testing Tool[/bold blue]")
    console.print(f"Target: {target}")
    console.print(f"Output: {output}")
    console.print()
    
    try:
        # Initialize the crew
        crew = BreachPilotCrew(target=target, output_file=output, verbose=verbose)
        
        # Run the penetration testing workflow
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            console=console
        ) as progress:
            task = progress.add_task("Initializing BreachPilot crew...", total=None)
            
            # Execute the crew workflow
            result = crew.run()
            
            progress.update(task, description="✅ Penetration testing completed!")
        
        console.print(f"\n[green]✅ Report generated: {output}[/green]")
        
        if result:
            console.print("\n[bold]Summary:[/bold]")
            console.print(result.get('summary', 'No summary available'))
        
    except KeyboardInterrupt:
        console.print("\n[yellow]⚠️  Process interrupted by user[/yellow]")
        sys.exit(1)
    except Exception as e:
        console.print(f"\n[red]❌ Error: {str(e)}[/red]")
        if verbose:
            import traceback
            console.print(traceback.format_exc())
        sys.exit(1)


if __name__ == "__main__":
    main()