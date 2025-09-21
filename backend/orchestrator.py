import json
import uuid
from typing import Dict, Any, List
from backend.models import ScanSession, ScanRequest, PoCResult, PoCInfo, ExploitResult
from backend.scanners.osint_scanner import OSINTScanner
from backend.scanners.nmap_scanner import NmapScanner
from backend.agents.analyst_crew import AnalystCrew
from backend.agents.poc_crew import PoCCrew
from backend.agents.exploit_crew import ExploitCrew
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self):
        self.sessions: Dict[str, ScanSession] = {}
        self.osint_scanner = OSINTScanner()
        self.nmap_scanner = NmapScanner()
        self.analyst_crew = AnalystCrew()
        self.poc_crew = PoCCrew()
        self.exploit_crew = ExploitCrew()
    
    def start_scan(self, request: ScanRequest) -> ScanSession:
        session_id = str(uuid.uuid4())
        session = ScanSession(session_id=session_id, target_ip=request.target_ip)
        self.sessions[session_id] = session
        self._save_session(session)
        return session
    
    def run_osint(self, session_id: str):
        session = self._get_session(session_id)
        session.osint_result = self.osint_scanner.scan(session.target_ip)
        self._save_session(session)
        return session.osint_result
    
    def run_nmap(self, session_id: str):
        session = self._get_session(session_id)
        session.nmap_result = self.nmap_scanner.scan(session.target_ip)
        self._save_session(session)
        return session.nmap_result
    
    def run_analysis(self, session_id: str):
        session = self._get_session(session_id)
        if not session.nmap_result:
            raise ValueError("Nmap must be completed")
        session.analyst_result = self.analyst_crew.analyze_vulnerabilities(session.target_ip, session.nmap_result)
        self._save_session(session)
        return session.analyst_result
    
    def search_pocs_for_cves(self, session_id: str, selected_cves: List[str]) -> List[PoCResult]:
        session = self._get_session(session_id)
        results = self.poc_crew.search_pocs(selected_cves, limit=3)
        session.poc_results = results
        self._save_session(session)
        return results
    
    def execute_single_poc(self, session_id: str, cve_id: str, poc: PoCInfo, target_ip: str) -> ExploitResult:
        """Execute a single PoC exploit"""
        logger.info(f"Executing PoC for {cve_id}")
        
        # Create a temporary PoCResult for the exploit crew
        poc_result = PoCResult(cve_id=cve_id, available_pocs=[poc], selected_poc=poc)
        
        # Execute the exploit using the exploit crew
        results = self.exploit_crew.execute_exploits(target_ip, [poc_result])
        
        if results:
            # Save to session
            session = self._get_session(session_id)
            session.exploit_results.append(results[0])
            self._save_session(session)
            return results[0]
        
        raise ValueError("Exploit execution failed")
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        session = self._get_session(session_id)
        return {
            "session_id": session.session_id,
            "target_ip": session.target_ip,
            "current_step": session.current_step,
            "osint_complete": session.osint_result is not None,
            "nmap_complete": session.nmap_result is not None,
            "analysis_complete": session.analyst_result is not None,
            "pocs_found": len(session.poc_results),
            "exploits_run": len(session.exploit_results)
        }
    
    def _get_session(self, session_id: str) -> ScanSession:
        if session_id not in self.sessions:
            session_file = config.DATA_DIR / f"session_{session_id}.json"
            if session_file.exists():
                with open(session_file, 'r') as f:
                    self.sessions[session_id] = ScanSession(**json.load(f))
            else:
                raise ValueError(f"Session {session_id} not found")
        return self.sessions[session_id]
    
    def _save_session(self, session: ScanSession):
        session_file = config.DATA_DIR / f"session_{session.session_id}.json"
        with open(session_file, 'w') as f:
            json.dump(session.model_dump(), f, indent=2, default=str)
