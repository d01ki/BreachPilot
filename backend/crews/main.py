#!/usr/bin/env python3
"""
Main CrewAI Security Assessment Entry Point
Demonstrates how to use the new modular CrewAI implementation
"""

import logging
import asyncio
from typing import Optional

from backend.models import NmapResult, AnalystResult
from backend.config import config
from .security_crew import SecurityAssessmentCrew

# Configure logging
logger = logging.getLogger(__name__)

class SecurityAssessmentOrchestrator:
    """
    Main orchestrator for CrewAI security assessments
    Provides high-level interface for running security assessments
    """
    
    def __init__(self):
        """
        Initialize the security assessment orchestrator
        """
        try:
            self.crew = SecurityAssessmentCrew()
            self.available = True
            logger.info("SecurityAssessmentOrchestrator initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize orchestrator: {e}")
            self.available = False
    
    async def run_assessment(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Run comprehensive security assessment
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Comprehensive security analysis result
        """
        if not self.available:
            logger.error("SecurityAssessmentOrchestrator not available")
            raise RuntimeError("Security assessment orchestrator not properly initialized")
        
        logger.info(f"Starting comprehensive security assessment for {target_ip}")
        
        try:
            # Run CrewAI analysis
            result = self.crew.analyze_target(target_ip, nmap_result)
            
            logger.info(f"Security assessment completed for {target_ip} - {len(result.identified_cves)} CVEs identified")
            return result
            
        except Exception as e:
            logger.error(f"Security assessment failed: {e}")
            raise
    
    def get_crew_status(self) -> Dict[str, Any]:
        """
        Get status of CrewAI components
        
        Returns:
            Status dictionary
        """
        return {
            "orchestrator_available": self.available,
            "crew_available": self.crew.crew_available if hasattr(self.crew, 'crew_available') else False,
            "agents_count": len(self.crew.agents) if hasattr(self.crew, 'agents') else 0,
            "llm_model": config.LLM_MODEL,
            "serper_configured": bool(config.SERPER_API_KEY)
        }

# Convenience function for direct usage
async def run_security_assessment(target_ip: str, nmap_result: NmapResult) -> AnalystResult:
    """
    Convenience function to run security assessment
    
    Args:
        target_ip: Target IP address
        nmap_result: Nmap scan results
        
    Returns:
        Security analysis result
    """
    orchestrator = SecurityAssessmentOrchestrator()
    return await orchestrator.run_assessment(target_ip, nmap_result)

# Example usage
if __name__ == "__main__":
    import json
    
    # Example nmap result for testing
    example_nmap = NmapResult(
        target_ip="192.168.1.100",
        services=[
            {"port": 445, "name": "microsoft-ds", "product": "Microsoft Windows", "version": "Server 2019"},
            {"port": 3389, "name": "ms-wbt-server", "product": "Microsoft Terminal Services", "version": ""}
        ],
        os_detection="Microsoft Windows Server 2019",
        scan_time="2024-01-01 12:00:00"
    )
    
    async def main():
        try:
            orchestrator = SecurityAssessmentOrchestrator()
            
            # Check status
            status = orchestrator.get_crew_status()
            print("Crew Status:")
            print(json.dumps(status, indent=2))
            
            # Run assessment
            result = await orchestrator.run_assessment("192.168.1.100", example_nmap)
            
            print("\nAssessment Result:")
            print(f"Target: {result.target_ip}")
            print(f"CVEs Found: {len(result.identified_cves)}")
            print(f"Priority Vulnerabilities: {len(result.priority_vulnerabilities)}")
            print(f"Risk Assessment: {result.risk_assessment[:200]}...")
            
        except Exception as e:
            logger.error(f"Example run failed: {e}")
    
    # Run example
    asyncio.run(main())
