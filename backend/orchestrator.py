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
    
    def search_pocs_for_cves(self, session_id: str, selected_cves: List[str], limit: int = 4) -> List[PoCResult]:
        """Enhanced PoC search with improved limit handling"""
        session = self._get_session(session_id)
        logger.info(f"Searching PoCs for {len(selected_cves)} CVEs with limit {limit}")
        
        results = self.poc_crew.search_pocs(selected_cves, limit=limit)
        
        # Update session with results
        session.poc_results = results
        self._save_session(session)
        
        # Log summary
        total_pocs = sum(len(r.available_pocs) for r in results)
        total_with_code = sum(len([p for p in r.available_pocs if p.code]) for r in results)
        logger.info(f"PoC search complete: {total_pocs} total, {total_with_code} with code")
        
        return results
    
    def execute_single_poc(self, session_id: str, cve_id: str, poc: PoCInfo, target_ip: str) -> ExploitResult:
        """Execute a single PoC exploit (legacy compatibility method)"""
        logger.info(f"Executing single PoC for {cve_id}")
        
        # Find the PoCResult for this CVE
        session = self._get_session(session_id)
        poc_result = None
        
        for pr in session.poc_results:
            if pr.cve_id == cve_id:
                poc_result = pr
                break
        
        if not poc_result:
            # Create a temporary PoCResult
            poc_result = PoCResult(cve_id=cve_id, available_pocs=[poc], selected_poc=poc)
        
        # Use the new enhanced execution method
        results = self.exploit_crew.execute_single_poc_with_retry(target_ip, cve_id, poc_result)
        
        if results:
            # Update session with all results
            session.exploit_results.extend(results)
            self._save_session(session)
            
            # Return the first (and potentially successful) result for backward compatibility
            return results[0]
        
        raise ValueError("Exploit execution failed")
    
    def execute_multiple_pocs(self, session_id: str, cve_id: str, target_ip: str) -> List[ExploitResult]:
        """Execute all available PoCs for a CVE with retry logic"""
        logger.info(f"Executing multiple PoCs for {cve_id}")
        
        session = self._get_session(session_id)
        
        # Find the PoCResult for this CVE
        poc_result = None
        for pr in session.poc_results:
            if pr.cve_id == cve_id:
                poc_result = pr
                break
        
        if not poc_result or not poc_result.available_pocs:
            raise ValueError(f"No PoCs found for {cve_id}")
        
        # Execute with retry logic
        results = self.exploit_crew.execute_single_poc_with_retry(target_ip, cve_id, poc_result)
        
        # Update session
        session.exploit_results.extend(results)
        self._save_session(session)
        
        return results
    
    def execute_poc_by_index(self, session_id: str, cve_id: str, poc_index: int, target_ip: str) -> ExploitResult:
        """Execute a specific PoC by index using git clone method"""
        logger.info(f"Executing PoC #{poc_index} for {cve_id}")
        
        session = self._get_session(session_id)
        
        # Find the specific PoC
        poc_result = None
        target_poc = None
        
        for pr in session.poc_results:
            if pr.cve_id == cve_id:
                poc_result = pr
                if 0 <= poc_index < len(pr.available_pocs):
                    target_poc = pr.available_pocs[poc_index]
                break
        
        if not poc_result or not target_poc:
            raise ValueError(f"PoC #{poc_index} not found for {cve_id}")
        
        # Execute single PoC using the new git clone method
        result = self.exploit_crew._execute_single_poc_git(target_ip, cve_id, target_poc, poc_index + 1)
        
        # Update session
        session.exploit_results.append(result)
        self._save_session(session)
        
        return result
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        session = self._get_session(session_id)
        
        # Enhanced status with PoC and exploit details
        poc_summary = {}
        exploit_summary = {}
        
        if session.poc_results:
            poc_summary = {
                'total_cves': len(session.poc_results),
                'total_pocs': sum(len(pr.available_pocs) for pr in session.poc_results),
                'pocs_with_code': sum(len([p for p in pr.available_pocs if p.code]) for pr in session.poc_results)
            }
        
        if session.exploit_results:
            successful_exploits = [er for er in session.exploit_results if er.success]
            exploit_summary = {
                'total_attempts': len(session.exploit_results),
                'successful_exploits': len(successful_exploits),
                'unique_cves_attempted': len(set(er.cve_id for er in session.exploit_results)),
                'success_rate': round(len(successful_exploits) / len(session.exploit_results) * 100, 1) if session.exploit_results else 0
            }
        
        return {
            "session_id": session.session_id,
            "target_ip": session.target_ip,
            "current_step": session.current_step,
            "osint_complete": session.osint_result is not None,
            "nmap_complete": session.nmap_result is not None,
            "analysis_complete": session.analyst_result is not None,
            "pocs_found": len(session.poc_results),
            "exploits_run": len(session.exploit_results),
            "poc_summary": poc_summary,
            "exploit_summary": exploit_summary
        }
    
    def get_exploit_results_by_cve(self, session_id: str, cve_id: str) -> List[ExploitResult]:
        """Get all exploit results for a specific CVE"""
        session = self._get_session(session_id)
        return [er for er in session.exploit_results if er.cve_id == cve_id]
    
    def get_successful_exploits(self, session_id: str) -> List[ExploitResult]:
        """Get all successful exploit results"""
        session = self._get_session(session_id)
        return [er for er in session.exploit_results if er.success]
    
    def get_poc_files_info(self, session_id: str) -> Dict[str, List[str]]:
        """Get information about git repositories instead of files"""
        session = self._get_session(session_id)
        repos_info = {}
        
        for poc_result in session.poc_results:
            cve_repos = []
            for poc in poc_result.available_pocs:
                if 'github.com' in poc.url:
                    cve_repos.append({
                        'url': poc.url,
                        'source': poc.source,
                        'description': poc.description,
                        'author': poc.author,
                        'stars': poc.stars,
                        'repo_type': 'GitHub Repository'
                    })
            
            if cve_repos:
                repos_info[poc_result.cve_id] = cve_repos
        
        return repos_info
    
    def cleanup_exploit_files(self, session_id: str, keep_successful: bool = True):
        """Clean up temporary git repositories for a session"""
        try:
            # Git repositories are automatically cleaned up by GitPoCExecutor
            # This method is kept for API compatibility
            if hasattr(self.exploit_crew, 'git_executor'):
                self.exploit_crew.git_executor.cleanup()
                logger.info("Cleaned up temporary git repositories")
            
        except Exception as e:
            logger.error(f"Error cleaning up git repositories: {e}")
    
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
        config.DATA_DIR.mkdir(exist_ok=True)
        with open(session_file, 'w') as f:
            json.dump(session.model_dump(), f, indent=2, default=str)
