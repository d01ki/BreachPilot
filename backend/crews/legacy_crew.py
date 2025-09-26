#!/usr/bin/env python3
"""
Legacy CrewAI Wrapper for Backwards Compatibility
"""

import logging
from typing import Dict, Any, List, Optional

from backend.models import AnalystResult, NmapResult
from .security_crew import SecurityAssessmentCrew

logger = logging.getLogger(__name__)

class AnalystCrew(SecurityAssessmentCrew):
    """
    Legacy compatibility wrapper for existing code
    Maintains backwards compatibility with the original AnalystCrew interface
    """
    
    def __init__(self):
        """
        Initialize legacy crew with new implementation
        """
        try:
            super().__init__()
            logger.info("AnalystCrew (legacy wrapper) initialized successfully")
        except Exception as e:
            logger.error(f"Failed to initialize AnalystCrew: {e}")
            self.crew_available = False
    
    def analyze_vulnerabilities(self, target_ip: str, nmap_result: NmapResult) -> AnalystResult:
        """
        Legacy method for backwards compatibility
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Analyst result
        """
        logger.info(f"Legacy analyze_vulnerabilities called for {target_ip}")
        return self.analyze_target(target_ip, nmap_result)
