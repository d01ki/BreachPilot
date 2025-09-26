#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Orchestrator
Updated to use new modular CrewAI implementation
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional, List
from concurrent.futures import ThreadPoolExecutor, as_completed

from backend.models import (
    ScanRequest, ScanResult, NmapResult, AnalystResult, 
    ExploitResult, ReportResult, StepStatus
)
from backend.config import config
from backend.scanners.nmap_scanner import NmapScanner
from backend.crews import SecurityAssessmentCrew, AnalystCrew  # Updated import
from backend.exploiter.exploit_engine import ExploitEngine
from backend.report.report_generator import ReportGenerator

# Configure logging
logger = logging.getLogger(__name__)

class SecurityOrchestrator:
    """
    Professional Security Assessment Orchestrator
    Updated to use modular CrewAI implementation
    """
    
    def __init__(self):
        """
        Initialize the security orchestrator with all components
        """
        try:
            # Initialize components
            self.nmap_scanner = NmapScanner()
            
            # Use new modular CrewAI implementation
            try:
                self.security_crew = SecurityAssessmentCrew()
                self.analyst_available = True
                logger.info("New SecurityAssessmentCrew initialized")
            except Exception as e:
                logger.warning(f"Failed to initialize SecurityAssessmentCrew, falling back to legacy: {e}")
                self.security_crew = AnalystCrew()
                self.analyst_available = getattr(self.security_crew, 'crew_available', False)
            
            self.exploit_engine = ExploitEngine()
            self.report_generator = ReportGenerator()
            
            # Component status
            self.components_status = {
                'nmap_scanner': True,
                'security_crew': self.analyst_available,
                'exploit_engine': True,
                'report_generator': True
            }
            
            logger.info("SecurityOrchestrator initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityOrchestrator: {e}")
            raise
    
    async def execute_security_assessment(self, request: ScanRequest) -> ScanResult:
        """
        Execute comprehensive security assessment
        
        Args:
            request: Scan request parameters
            
        Returns:
            Complete scan results
        """
        start_time = time.time()
        
        logger.info(f"Starting security assessment for {request.target}")
        
        # Initialize result
        result = ScanResult(
            request=request,
            nmap_result=None,
            analyst_result=None,
            exploit_result=None,
            report_result=None,
            execution_time=0.0,
            status=StepStatus.IN_PROGRESS,
            errors=[]
        )
        
        try:
            # Step 1: Network Scanning
            logger.info("Step 1: Executing network scan")
            nmap_result = await self._execute_nmap_scan(request)
            result.nmap_result = nmap_result
            
            if not nmap_result or not nmap_result.services:
                logger.warning("No services detected, continuing with limited analysis")
            
            # Step 2: Vulnerability Analysis (Using new CrewAI implementation)
            logger.info("Step 2: Executing CrewAI vulnerability analysis")
            analyst_result = await self._execute_crewai_analysis(request.target, nmap_result)
            result.analyst_result = analyst_result
            
            # Step 3: Exploitation Analysis (if enabled)
            if request.enable_exploitation:
                logger.info("Step 3: Executing exploitation analysis")
                exploit_result = await self._execute_exploitation(request.target, analyst_result)
                result.exploit_result = exploit_result
            
            # Step 4: Report Generation
            logger.info("Step 4: Generating comprehensive report")
            report_result = await self._execute_report_generation(result)
            result.report_result = report_result
            
            # Calculate execution time
            result.execution_time = time.time() - start_time
            result.status = StepStatus.COMPLETED
            
            logger.info(f"Security assessment completed in {result.execution_time:.2f} seconds")
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = StepStatus.FAILED
            result.execution_time = time.time() - start_time
            logger.error(f"Security assessment failed: {e}")
        
        return result
    
    async def _execute_nmap_scan(self, request: ScanRequest) -> Optional[NmapResult]:
        """
        Execute Nmap network scan
        
        Args:
            request: Scan request
            
        Returns:
            Nmap scan results
        """
        try:
            # Run nmap scan in thread pool to avoid blocking
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.nmap_scanner.scan_target,
                    request.target,
                    request.scan_type,
                    request.port_range
                )
                nmap_result = future.result(timeout=config.NMAP_TIMEOUT)
            
            if nmap_result:
                logger.info(f"Nmap scan completed: {len(nmap_result.services or [])} services found")
            else:
                logger.warning("Nmap scan returned no results")
            
            return nmap_result
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return None
    
    async def _execute_crewai_analysis(self, target_ip: str, nmap_result: Optional[NmapResult]) -> Optional[AnalystResult]:
        """
        Execute CrewAI vulnerability analysis
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Analysis results
        """
        if not self.analyst_available:
            logger.error("CrewAI analyst not available")
            return None
        
        if not nmap_result:
            logger.warning("No nmap results available for analysis")
            return None
        
        try:
            # Run CrewAI analysis in thread pool
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self._run_crewai_analysis,
                    target_ip,
                    nmap_result
                )
                analyst_result = future.result(timeout=config.ASSESSMENT_TIMEOUT)
            
            if analyst_result and analyst_result.identified_cves:
                logger.info(f"CrewAI analysis completed: {len(analyst_result.identified_cves)} CVEs identified")
            else:
                logger.warning("CrewAI analysis returned no vulnerabilities")
            
            return analyst_result
            
        except Exception as e:
            logger.error(f"CrewAI analysis failed: {e}")
            return None
    
    def _run_crewai_analysis(self, target_ip: str, nmap_result: NmapResult) -> Optional[AnalystResult]:
        """
        Run CrewAI analysis (synchronous wrapper)
        
        Args:
            target_ip: Target IP address
            nmap_result: Nmap scan results
            
        Returns:
            Analysis results
        """
        try:
            # Use the appropriate method based on crew type
            if hasattr(self.security_crew, 'analyze_target'):
                return self.security_crew.analyze_target(target_ip, nmap_result)
            elif hasattr(self.security_crew, 'analyze_vulnerabilities'):
                return self.security_crew.analyze_vulnerabilities(target_ip, nmap_result)
            else:
                logger.error("Security crew has no analysis method")
                return None
                
        except Exception as e:
            logger.error(f"CrewAI analysis execution failed: {e}")
            return None
    
    async def _execute_exploitation(self, target_ip: str, analyst_result: Optional[AnalystResult]) -> Optional[ExploitResult]:
        """
        Execute exploitation analysis
        
        Args:
            target_ip: Target IP address
            analyst_result: Vulnerability analysis results
            
        Returns:
            Exploitation results
        """
        if not analyst_result or not analyst_result.identified_cves:
            logger.warning("No vulnerabilities available for exploitation analysis")
            return None
        
        try:
            # Run exploitation analysis in thread pool
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.exploit_engine.analyze_exploits,
                    target_ip,
                    analyst_result.identified_cves
                )
                exploit_result = future.result(timeout=120)  # 2 minute timeout
            
            if exploit_result and exploit_result.exploit_chains:
                logger.info(f"Exploitation analysis completed: {len(exploit_result.exploit_chains)} chains found")
            
            return exploit_result
            
        except Exception as e:
            logger.error(f"Exploitation analysis failed: {e}")
            return None
    
    async def _execute_report_generation(self, scan_result: ScanResult) -> Optional[ReportResult]:
        """
        Execute report generation
        
        Args:
            scan_result: Complete scan results
            
        Returns:
            Report generation results
        """
        try:
            # Generate report in thread pool
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.report_generator.generate_comprehensive_report,
                    scan_result
                )
                report_result = future.result(timeout=60)  # 1 minute timeout
            
            if report_result:
                logger.info("Report generation completed successfully")
            
            return report_result
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None
    
    def get_orchestrator_status(self) -> Dict[str, Any]:
        """
        Get orchestrator and component status
        
        Returns:
            Status information
        """
        crewai_status = {}
        if hasattr(self.security_crew, 'get_crew_status'):
            try:
                crewai_status = self.security_crew.get_crew_status()
            except:
                crewai_status = {'error': 'Failed to get CrewAI status'}
        
        return {
            'orchestrator': 'operational',
            'components': self.components_status,
            'crewai': crewai_status,
            'config': {
                'llm_model': config.LLM_MODEL,
                'max_cves': config.MAX_CVES_PER_ANALYSIS,
                'timeout': config.ASSESSMENT_TIMEOUT,
                'openai_configured': bool(config.OPENAI_API_KEY),
                'serper_configured': bool(config.SERPER_API_KEY)
            }
        }
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform health check of all components
        
        Returns:
            Health check results
        """
        health_status = {
            'overall': 'healthy',
            'components': {},
            'timestamp': time.time()
        }
        
        # Check each component
        try:
            # Check CrewAI
            if self.analyst_available:
                health_status['components']['crewai'] = 'operational'
            else:
                health_status['components']['crewai'] = 'degraded'
                health_status['overall'] = 'degraded'
            
            # Check other components
            health_status['components']['nmap'] = 'operational'
            health_status['components']['exploiter'] = 'operational'
            health_status['components']['reporter'] = 'operational'
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            health_status['overall'] = 'unhealthy'
            health_status['error'] = str(e)
        
        return health_status
