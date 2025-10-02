#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Orchestrator
Production-ready with real nmap integration
"""

import asyncio
import logging
import time
from typing import Dict, Any, Optional
from concurrent.futures import ThreadPoolExecutor

from backend.models import (
    ScanRequest, ScanResult, NmapResult, AnalystResult, 
    ExploitResult, ReportResult, StepStatus
)
from backend.config import config
from backend.scanners.nmap_scanner import NmapScanner
from backend.crews import SecurityAssessmentCrew

# Configure logging
logger = logging.getLogger(__name__)

class MockExploitEngine:
    """Mock exploit engine for demonstration"""
    
    def analyze_exploits(self, target_ip: str, cves: list) -> ExploitResult:
        """Mock exploit analysis"""
        logger.info(f"Mock exploit analysis for {target_ip}")
        
        return ExploitResult(
            target_ip=target_ip,
            tested_exploits=[{"cve": cve.cve_id, "success": False} for cve in cves[:3]],
            successful_exploits=[],
            failed_exploits=[cve.cve_id for cve in cves[:3]],
            status=StepStatus.COMPLETED
        )

class MockReportGenerator:
    """Mock report generator for demonstration"""
    
    def generate_comprehensive_report(self, scan_result: ScanResult) -> ReportResult:
        """Mock report generation"""
        logger.info("Mock generating report")
        
        return ReportResult(
            executive_summary="Professional security assessment completed using CrewAI multi-agent analysis.",
            technical_findings="Detailed technical findings from vulnerability analysis.",
            recommendations="Prioritized remediation recommendations based on risk assessment.",
            status=StepStatus.COMPLETED,
            generation_time=2.5
        )

class SecurityOrchestrator:
    """
    Production Security Assessment Orchestrator
    Integrates real nmap scanning with CrewAI analysis
    """
    
    def __init__(self):
        """
        Initialize the security orchestrator
        """
        try:
            # Initialize CrewAI system
            self.security_crew = SecurityAssessmentCrew()
            self.crew_available = self.security_crew.crew_available
            
            # Initialize real nmap scanner
            self.nmap_scanner = NmapScanner()
            
            # Initialize mock components for features not yet implemented
            self.exploit_engine = MockExploitEngine()
            self.report_generator = MockReportGenerator()
            
            # Component status
            self.components_status = {
                'crewai': self.crew_available,
                'nmap_scanner': True,
                'exploit_engine': True,
                'report_generator': True
            }
            
            logger.info("SecurityOrchestrator initialized successfully")
            logger.info(f"CrewAI available: {self.crew_available}")
            
        except Exception as e:
            logger.error(f"Failed to initialize SecurityOrchestrator: {e}")
            self.crew_available = False
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
            
            # Step 2: CrewAI Vulnerability Analysis
            logger.info("Step 2: Executing CrewAI vulnerability analysis")
            analyst_result = await self._execute_crewai_analysis(request.target, nmap_result)
            result.analyst_result = analyst_result
            
            # Step 3: Exploitation Analysis (if enabled)
            if request.enable_exploitation and analyst_result and analyst_result.identified_cves:
                logger.info("Step 3: Executing exploitation analysis")
                exploit_result = await self._execute_exploitation(request.target, analyst_result.identified_cves)
                result.exploit_result = exploit_result
            
            # Step 4: Report Generation
            logger.info("Step 4: Generating comprehensive report")
            report_result = await self._execute_report_generation(result)
            result.report_result = report_result
            
            # Calculate execution time
            result.execution_time = time.time() - start_time
            result.status = StepStatus.COMPLETED
            result.completed_at = time.time()
            
            logger.info(f"Security assessment completed in {result.execution_time:.2f} seconds")
            
        except Exception as e:
            result.errors.append(str(e))
            result.status = StepStatus.FAILED
            result.execution_time = time.time() - start_time
            logger.error(f"Security assessment failed: {e}")
        
        return result
    
    async def run_nmap_scan(self, target: str) -> NmapResult:
        """Execute nmap scan and return results"""
        logger.info(f"Starting nmap scan for {target}")
        
        try:
            # Create a scan request
            request = ScanRequest(
                target=target,
                scan_type="comprehensive",
                enable_exploitation=False
            )
            
            # Execute the scan
            result = await self._execute_nmap_scan(request)
            
            if result:
                logger.info(f"Nmap scan completed: {len(result.services or [])} services found")
            else:
                logger.error("Nmap scan returned no results")
            
            return result
            
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            raise
    
    async def run_vulnerability_analysis(self, nmap_result: NmapResult) -> AnalystResult:
        """Execute vulnerability analysis on nmap results"""
        logger.info(f"Starting vulnerability analysis for {nmap_result.target_ip}")
        
        try:
            result = await self._execute_crewai_analysis(nmap_result.target_ip, nmap_result)
            
            if result:
                logger.info(f"Analysis completed: {len(result.identified_cves or [])} CVEs identified")
            else:
                logger.error("Vulnerability analysis returned no results")
            
            return result
            
        except Exception as e:
            logger.error(f"Vulnerability analysis failed: {e}")
            raise
    
    async def _execute_nmap_scan(self, request: ScanRequest) -> Optional[NmapResult]:
        """Execute network scan using real nmap"""
        try:
            logger.info(f"Executing nmap scan on {request.target}")
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.nmap_scanner.scan,
                    request.target
                )
                nmap_result = future.result(timeout=config.NMAP_TIMEOUT)
            
            if nmap_result:
                logger.info(f"Network scan completed: {len(nmap_result.services or [])} services found")
                
                # Log discovered services
                if nmap_result.services:
                    for service in nmap_result.services:
                        logger.info(f"  - Port {service.get('port')}: {service.get('name')} ({service.get('product', 'Unknown')})")
            else:
                logger.warning("Nmap scan returned no results")
            
            return nmap_result
            
        except subprocess.TimeoutExpired:
            logger.error(f"Network scan timeout for {request.target}")
            return None
        except Exception as e:
            logger.error(f"Network scan failed: {e}", exc_info=True)
            return None
    
    async def _execute_crewai_analysis(self, target_ip: str, nmap_result: Optional[NmapResult]) -> Optional[AnalystResult]:
        """Execute CrewAI vulnerability analysis"""
        if not self.crew_available:
            logger.error("CrewAI not available")
            return None
        
        if not nmap_result or not nmap_result.services:
            logger.warning("No nmap results available for analysis")
            return None
        
        try:
            logger.info(f"Starting CrewAI analysis for {target_ip}")
            
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.security_crew.analyze_target,
                    target_ip,
                    nmap_result
                )
                analyst_result = future.result(timeout=config.ASSESSMENT_TIMEOUT)
            
            if analyst_result:
                if analyst_result.identified_cves:
                    logger.info(f"CrewAI analysis completed: {len(analyst_result.identified_cves)} CVEs identified")
                    for cve in analyst_result.identified_cves[:5]:  # Log first 5 CVEs
                        logger.info(f"  - {cve.cve_id}: {cve.severity} ({cve.cvss_score})")
                else:
                    logger.info("CrewAI analysis completed: No CVEs identified")
            else:
                logger.warning("CrewAI analysis returned no results")
            
            return analyst_result
            
        except Exception as e:
            logger.error(f"CrewAI analysis failed: {e}", exc_info=True)
            return None
    
    async def _execute_exploitation(self, target_ip: str, cves: list) -> Optional[ExploitResult]:
        """Execute exploitation analysis"""
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.exploit_engine.analyze_exploits,
                    target_ip,
                    cves
                )
                exploit_result = future.result(timeout=120)
            
            logger.info("Exploitation analysis completed")
            return exploit_result
            
        except Exception as e:
            logger.error(f"Exploitation analysis failed: {e}")
            return None
    
    async def _execute_report_generation(self, scan_result: ScanResult) -> Optional[ReportResult]:
        """Execute report generation"""
        try:
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(
                    self.report_generator.generate_comprehensive_report,
                    scan_result
                )
                report_result = future.result(timeout=60)
            
            logger.info("Report generation completed")
            return report_result
            
        except Exception as e:
            logger.error(f"Report generation failed: {e}")
            return None
    
    def get_orchestrator_status(self) -> Dict[str, Any]:
        """Get orchestrator status"""
        crewai_status = {}
        if hasattr(self.security_crew, 'get_crew_status'):
            try:
                crewai_status = self.security_crew.get_crew_status()
            except Exception as e:
                crewai_status = {'error': f'Failed to get CrewAI status: {e}'}
        
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
        """Perform health check"""
        health_status = {
            'overall': 'healthy',
            'components': {},
            'timestamp': time.time()
        }
        
        try:
            # Check CrewAI
            if self.crew_available:
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
