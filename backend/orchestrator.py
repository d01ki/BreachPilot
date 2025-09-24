import json
import uuid
import asyncio
from typing import Dict, Any, List
from backend.models import ScanSession, ScanRequest, PoCResult, PoCInfo, ExploitResult
from backend.scanners.nmap_scanner import NmapScanner
from backend.agents.analyst_crew import AnalystCrew
from backend.agents.poc_crew import PoCCrew
from backend.agents.exploit_crew import ExploitCrew
from backend.exploiter.zerologon_executor import ZerologonExecutor
from backend.config import config
import logging

logger = logging.getLogger(__name__)

class ScanOrchestrator:
    def __init__(self):
        self.sessions: Dict[str, ScanSession] = {}
        self.nmap_scanner = NmapScanner()
        self.analyst_crew = AnalystCrew()
        self.poc_crew = PoCCrew()
        self.exploit_crew = ExploitCrew()
        self.zerologon_executor = ZerologonExecutor()
    
    def start_scan(self, request: ScanRequest) -> ScanSession:
        """Start scan - only create session, don't auto-run anything"""
        session_id = str(uuid.uuid4())
        session = ScanSession(session_id=session_id, target_ip=request.target_ip)
        self.sessions[session_id] = session
        self._save_session(session)
        
        logger.info(f"🚀 Session created for {request.target_ip}")
        return session
    
    def run_nmap(self, session_id: str):
        """Run Nmap scan"""
        session = self._get_session(session_id)
        logger.info(f"🔍 Starting Nmap scan for {session.target_ip}")
        
        try:
            session.nmap_result = self.nmap_scanner.scan(session.target_ip)
            session.current_step = "analysis"
            self._save_session(session)
            logger.info(f"✅ Nmap scan completed for {session.target_ip}")
            return session.nmap_result
        except Exception as e:
            logger.error(f"❌ Nmap scan failed: {e}")
            raise e
    
    def run_analysis(self, session_id: str):
        """Run CVE analysis"""
        session = self._get_session(session_id)
        if not session.nmap_result:
            raise ValueError("Nmap scan must be completed first")
        
        logger.info(f"🔍 Starting CVE analysis for {session.target_ip}")
        
        try:
            session.analyst_result = self.analyst_crew.analyze_vulnerabilities(session.target_ip, session.nmap_result)
            session.current_step = "poc_search"
            self._save_session(session)
            logger.info(f"✅ CVE analysis completed for {session.target_ip}")
            return session.analyst_result
        except Exception as e:
            logger.error(f"❌ CVE analysis failed: {e}")
            raise e
    
    def search_pocs_for_cves(self, session_id: str, selected_cves: List[str], limit: int = 4) -> List[PoCResult]:
        """Enhanced PoC search with Zerologon auto-preparation"""
        session = self._get_session(session_id)
        logger.info(f"🔍 Searching PoCs for {len(selected_cves)} CVEs with limit {limit}")
        
        results = self.poc_crew.search_pocs(selected_cves, limit=limit)
        
        # Auto-prepare Zerologon PoC if CVE-2020-1472 is selected
        for result in results:
            if result.cve_id == "CVE-2020-1472":
                logger.info("🎯 CVE-2020-1472 detected - Auto-preparing Zerologon PoC")
                zerologon_poc = self._prepare_zerologon_poc(session.target_ip)
                if zerologon_poc:
                    # Insert Zerologon PoC at the beginning
                    result.available_pocs.insert(0, zerologon_poc)
                    result.total_found += 1
                    result.with_code += 1
                    logger.info("✅ Zerologon PoC auto-prepared and ready for execution")
        
        # Update session with results
        session.poc_results = results
        self._save_session(session)
        
        # Log summary
        total_pocs = sum(len(r.available_pocs) for r in results)
        total_with_code = sum(len([p for p in r.available_pocs if p.code]) for r in results)
        logger.info(f"🎯 PoC search complete: {total_pocs} total, {total_with_code} with code")
        
        return results
    
    def _prepare_zerologon_poc(self, target_ip: str) -> PoCInfo:
        """Prepare built-in Zerologon PoC"""
        try:
            # Extract DC name from target (fallback if not available)
            dc_name = "DC01"  # Default, can be enhanced to extract from scan results
            
            # Create Zerologon PoC info
            zerologon_poc = PoCInfo(
                source="BreachPilot Built-in",
                url="https://github.com/SecuraBV/CVE-2020-1472",  # Reference
                description="Zerologon (CVE-2020-1472) - Built-in PoC for Domain Controller privilege escalation",
                author="BreachPilot",
                stars=999,  # High priority
                code=self.zerologon_executor._get_zerologon_script(),
                filename="zerologon_exploit.py",
                execution_command=f"python3 zerologon_exploit.py {dc_name} {target_ip}",
                file_extension=".py",
                code_language="python",
                estimated_success_rate=0.95,
                requires_dependencies=True,
                dependencies=["impacket", "cryptography"]
            )
            
            return zerologon_poc
            
        except Exception as e:
            logger.error(f"Failed to prepare Zerologon PoC: {e}")
            return None
    
    def execute_single_poc(self, session_id: str, cve_id: str, poc: PoCInfo, target_ip: str) -> ExploitResult:
        """Execute a single PoC with special handling for Zerologon"""
        logger.info(f"🚀 Executing single PoC for {cve_id}")
        
        # Special handling for Zerologon
        if cve_id == "CVE-2020-1472" and poc.source == "BreachPilot Built-in":
            return self._execute_zerologon_poc(session_id, target_ip, poc)
        
        # Standard execution
        session = self._get_session(session_id)
        poc_result = None
        
        for pr in session.poc_results:
            if pr.cve_id == cve_id:
                poc_result = pr
                break
        
        if not poc_result:
            poc_result = PoCResult(cve_id=cve_id, available_pocs=[poc], selected_poc=poc)
        
        results = self.exploit_crew.execute_single_poc_with_retry(target_ip, cve_id, poc_result)
        
        if results:
            session.exploit_results.extend(results)
            self._save_session(session)
            return results[0]
        
        raise ValueError("Exploit execution failed")
    
    def _execute_zerologon_poc(self, session_id: str, target_ip: str, poc: PoCInfo) -> ExploitResult:
        """Execute built-in Zerologon PoC"""
        logger.info(f"🎯 Executing built-in Zerologon PoC against {target_ip}")
        
        session = self._get_session(session_id)
        
        try:
            # Extract DC name (enhanced logic could be added here)
            dc_name = self._extract_dc_name_from_scan(session) or "DC01"
            
            # Execute Zerologon
            zerologon_result = self.zerologon_executor.execute_zerologon(target_ip, dc_name)
            
            # Convert to ExploitResult
            exploit_result = ExploitResult(
                cve_id="CVE-2020-1472",
                target_ip=target_ip,
                exploit_used="Zerologon Built-in PoC",
                execution_output=zerologon_result["execution_output"],
                success=zerologon_result["success"],
                artifacts_captured=zerologon_result.get("artifacts", []),
                execution_command=zerologon_result["command"],
                execution_time=zerologon_result["execution_time"],
                vulnerability_confirmed=zerologon_result["vulnerability_confirmed"],
                exploit_successful=zerologon_result["exploit_successful"],
                poc_source="BreachPilot Built-in",
                poc_url="https://github.com/SecuraBV/CVE-2020-1472"
            )
            
            # Update session
            session.exploit_results.append(exploit_result)
            self._save_session(session)
            
            logger.info(f"✅ Zerologon execution completed. Success: {exploit_result.success}")
            return exploit_result
            
        except Exception as e:
            logger.error(f"❌ Zerologon execution failed: {e}")
            
            # Return failed result
            exploit_result = ExploitResult(
                cve_id="CVE-2020-1472",
                target_ip=target_ip,
                exploit_used="Zerologon Built-in PoC",
                execution_output=str(e),
                success=False,
                failure_reason=str(e)
            )
            
            session.exploit_results.append(exploit_result)
            self._save_session(session)
            
            return exploit_result
    
    def _extract_dc_name_from_scan(self, session: ScanSession) -> str:
        """Extract DC name from scan results"""
        try:
            if session.nmap_result and session.nmap_result.raw_output:
                # Look for Service Info with hostname
                import re
                match = re.search(r'Service Info: Host: ([^;]+)', session.nmap_result.raw_output)
                if match:
                    return match.group(1).strip()
            return None
        except:
            return None
    
    def execute_multiple_pocs(self, session_id: str, cve_id: str, target_ip: str) -> List[ExploitResult]:
        """Execute all available PoCs for a CVE with retry logic"""
        logger.info(f"🚀 Executing multiple PoCs for {cve_id}")
        
        session = self._get_session(session_id)
        
        poc_result = None
        for pr in session.poc_results:
            if pr.cve_id == cve_id:
                poc_result = pr
                break
        
        if not poc_result or not poc_result.available_pocs:
            raise ValueError(f"No PoCs found for {cve_id}")
        
        results = self.exploit_crew.execute_single_poc_with_retry(target_ip, cve_id, poc_result)
        
        session.exploit_results.extend(results)
        self._save_session(session)
        
        return results
    
    def execute_poc_by_index(self, session_id: str, cve_id: str, poc_index: int, target_ip: str) -> ExploitResult:
        """Execute a specific PoC by index using enhanced method"""
        logger.info(f"🚀 Executing PoC #{poc_index} for {cve_id}")
        
        session = self._get_session(session_id)
        
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
        
        # Special handling for Zerologon built-in
        if cve_id == "CVE-2020-1472" and target_poc.source == "BreachPilot Built-in":
            return self._execute_zerologon_poc(session_id, target_ip, target_poc)
        
        result = self.exploit_crew.execute_single_poc_enhanced(target_ip, cve_id, target_poc, poc_index + 1)
        
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
                'pocs_with_code': sum(len([p for p in pr.available_pocs if p.code]) for pr in session.poc_results),
                'zerologon_ready': any(pr.cve_id == "CVE-2020-1472" for pr in session.poc_results)
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
            "nmap_complete": session.nmap_result is not None,
            "analysis_complete": session.analyst_result is not None,
            "pocs_found": len(session.poc_results) if session.poc_results else 0,
            "exploits_run": len(session.exploit_results) if session.exploit_results else 0,
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
                if 'github.com' in poc.url or poc.source == "BreachPilot Built-in":
                    cve_repos.append({
                        'url': poc.url,
                        'source': poc.source,
                        'description': poc.description,
                        'author': poc.author,
                        'stars': poc.stars,
                        'repo_type': 'Built-in PoC' if poc.source == "BreachPilot Built-in" else 'GitHub Repository'
                    })
            
            if cve_repos:
                repos_info[poc_result.cve_id] = cve_repos
        
        return repos_info
    
    def cleanup_exploit_files(self, session_id: str, keep_successful: bool = True):
        """Clean up temporary git repositories for a session"""
        try:
            if hasattr(self.exploit_crew, 'git_executor'):
                self.exploit_crew.git_executor.cleanup()
                logger.info("🧹 Cleaned up temporary git repositories")
            
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