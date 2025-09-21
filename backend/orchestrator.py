import json
import uuid
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path

from backend.models import (
    ScanSession, ScanRequest, StepStatus,
    OSINTResult, NmapResult, AnalystResult,
    PoCResult, ExploitResult, ReportData
)
from backend.scanners.osint_scanner import OSINTScanner
from backend.scanners.nmap_scanner import NmapScanner
from backend.agents.analyst_crew import AnalystCrew
from backend.agents.poc_crew import PoCCrew
from backend.exploiter.exploit_executor import ExploitExecutor
from backend.report.report_generator import ReportGenerator
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    """Main orchestrator for the penetration testing workflow"""
    
    def __init__(self):
        self.sessions: Dict[str, ScanSession] = {}
        self.osint_scanner = OSINTScanner()
        self.nmap_scanner = NmapScanner()
        self.analyst_crew = AnalystCrew()
        self.poc_crew = PoCCrew()
        self.exploit_executor = ExploitExecutor()
        self.report_generator = ReportGenerator()
    
    def start_scan(self, request: ScanRequest) -> ScanSession:
        """Start a new penetration test scan"""
        session_id = str(uuid.uuid4())
        
        session = ScanSession(
            session_id=session_id,
            target_ip=request.target_ip,
            current_step="osint"
        )
        
        self.sessions[session_id] = session
        self._save_session(session)
        
        logger.info(f"Started scan session {session_id} for {request.target_ip}")
        return session
    
    def run_osint(self, session_id: str) -> OSINTResult:
        """Step 1: Run OSINT scan"""
        session = self._get_session(session_id)
        logger.info(f"Running OSINT for session {session_id}")
        
        session.current_step = "osint"
        
        # Run OSINT scan (no agent needed)
        osint_result = self.osint_scanner.scan(session.target_ip)
        session.osint_result = osint_result
        
        self._save_session(session)
        return osint_result
    
    def run_nmap(self, session_id: str) -> NmapResult:
        """Step 2: Run Nmap vulnerability scan"""
        session = self._get_session(session_id)
        logger.info(f"Running Nmap for session {session_id}")
        
        session.current_step = "nmap"
        
        # Run Nmap scan (no agent needed)
        nmap_result = self.nmap_scanner.scan(session.target_ip)
        session.nmap_result = nmap_result
        
        self._save_session(session)
        return nmap_result
    
    def run_analysis(self, session_id: str) -> AnalystResult:
        """Step 3: Analyze vulnerabilities with CVE + XAI"""
        session = self._get_session(session_id)
        logger.info(f"Running vulnerability analysis for session {session_id}")
        
        if not session.nmap_result:
            raise ValueError("Nmap scan must be completed before analysis")
        
        session.current_step = "analysis"
        
        # Use CrewAI agents for analysis
        analyst_result = self.analyst_crew.analyze_vulnerabilities(
            session.target_ip,
            session.nmap_result
        )
        session.analyst_result = analyst_result
        
        self._save_session(session)
        return analyst_result
    
    def search_pocs(self, session_id: str) -> list[PoCResult]:
        """Step 4: Search for PoC exploits"""
        session = self._get_session(session_id)
        logger.info(f"Searching PoCs for session {session_id}")
        
        if not session.analyst_result:
            raise ValueError("Analysis must be completed before PoC search")
        
        session.current_step = "poc_search"
        poc_results = []
        
        # Search PoC for each identified CVE
        for cve_analysis in session.analyst_result.identified_cves:
            poc_result = self.poc_crew.search_poc(cve_analysis)
            poc_results.append(poc_result)
        
        session.poc_results = poc_results
        self._save_session(session)
        
        return poc_results
    
    def await_user_approval(self, session_id: str, approved_cves: list[str]) -> None:
        """Step 5: Wait for user approval"""
        session = self._get_session(session_id)
        logger.info(f"User approval received for session {session_id}")
        
        session.current_step = "awaiting_approval"
        
        # Mark approved PoCs
        for poc in session.poc_results:
            if poc.cve_id in approved_cves:
                poc.status = StepStatus.APPROVED
            else:
                poc.status = StepStatus.REJECTED
        
        self._save_session(session)
    
    def run_exploits(self, session_id: str) -> list[ExploitResult]:
        """Step 6: Execute approved exploits"""
        session = self._get_session(session_id)
        logger.info(f"Running exploits for session {session_id}")
        
        session.current_step = "exploitation"
        exploit_results = []
        
        # Execute only approved PoCs
        approved_pocs = [p for p in session.poc_results if p.status == StepStatus.APPROVED]
        
        for poc in approved_pocs:
            exploit_result = self.exploit_executor.execute_exploit(
                session.target_ip,
                poc
            )
            exploit_results.append(exploit_result)
        
        session.exploit_results = exploit_results
        self._save_session(session)
        
        return exploit_results
    
    def verify_success(self, session_id: str) -> Dict[str, bool]:
        """Step 7: Verify exploitation success"""
        session = self._get_session(session_id)
        logger.info(f"Verifying success for session {session_id}")
        
        session.current_step = "verification"
        
        results = {}
        for exploit in session.exploit_results:
            results[exploit.cve_id] = exploit.success
        
        self._save_session(session)
        return results
    
    def generate_report(self, session_id: str) -> ReportData:
        """Step 8: Generate final report"""
        session = self._get_session(session_id)
        logger.info(f"Generating report for session {session_id}")
        
        session.current_step = "reporting"
        
        # Generate comprehensive report
        report_data = self.report_generator.generate_report(session)
        session.report_data = report_data
        
        session.current_step = "completed"
        self._save_session(session)
        
        return report_data
    
    def run_full_scan(self, request: ScanRequest, auto_approve: bool = False) -> ScanSession:
        """Run complete scan workflow"""
        logger.info(f"Starting full scan for {request.target_ip}")
        
        # Step 1: Start session
        session = self.start_scan(request)
        
        # Step 2: OSINT
        self.run_osint(session.session_id)
        
        # Step 3: Nmap
        self.run_nmap(session.session_id)
        
        # Step 4: Analysis
        self.run_analysis(session.session_id)
        
        # Step 5: PoC Search
        poc_results = self.search_pocs(session.session_id)
        
        # Step 6: User Approval (or auto-approve)
        if auto_approve:
            # Auto-approve all PoCs with exploits available
            approved = [p.cve_id for p in poc_results if p.selected_poc]
            self.await_user_approval(session.session_id, approved)
            
            # Step 7: Exploitation
            self.run_exploits(session.session_id)
            
            # Step 8: Verify
            self.verify_success(session.session_id)
        
        # Step 9: Generate Report
        self.generate_report(session.session_id)
        
        return self._get_session(session.session_id)
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get current session status"""
        session = self._get_session(session_id)
        
        return {
            "session_id": session.session_id,
            "target_ip": session.target_ip,
            "current_step": session.current_step,
            "created_at": session.created_at.isoformat(),
            "osint_complete": session.osint_result is not None,
            "nmap_complete": session.nmap_result is not None,
            "analysis_complete": session.analyst_result is not None,
            "pocs_found": len(session.poc_results),
            "exploits_run": len(session.exploit_results),
            "report_ready": session.report_data is not None
        }
    
    def _get_session(self, session_id: str) -> ScanSession:
        """Get session by ID"""
        if session_id not in self.sessions:
            # Try to load from file
            session_file = config.DATA_DIR / f"session_{session_id}.json"
            if session_file.exists():
                with open(session_file, 'r') as f:
                    data = json.load(f)
                    self.sessions[session_id] = ScanSession(**data)
            else:
                raise ValueError(f"Session {session_id} not found")
        
        return self.sessions[session_id]
    
    def _save_session(self, session: ScanSession):
        """Save session to disk"""
        session_file = config.DATA_DIR / f"session_{session.session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session.model_dump(), f, indent=2, default=str)
        logger.debug(f"Session {session.session_id} saved")
