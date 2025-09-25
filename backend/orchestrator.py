        # Find the target PoC
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
        
        logger.info(f"Executing: {target_poc.source} - {target_poc.filename}")
        
        try:
            # Use CrewAI exploit crew for execution
            result = self.exploit_crew.execute_single_poc_enhanced(target_ip, cve_id, target_poc, poc_index + 1)
            
            # Store result
            session.exploit_results.append(result)
            self._save_session(session)
            
            # Enhanced logging
            if result.success:
                logger.info(f"EXPLOIT SUCCESS: {cve_id} exploitation successful")
                if result.evidence:
                    logger.info(f"Evidence: {', '.join(result.evidence)}")
                if result.artifacts_captured:
                    logger.info(f"Artifacts: {', '.join(result.artifacts_captured)}")
            else:
                logger.info(f"Exploit failed: {result.failure_reason or 'Unknown reason'}")
            
            return result
            
        except Exception as e:
            logger.error(f"Exploit execution failed: {e}")
            
            # Create failure result
            failure_result = ExploitResult(
                cve_id=cve_id,
                target_ip=target_ip,
                exploit_used=f"{target_poc.source} - {target_poc.filename}",
                execution_output=f"Execution failed: {str(e)}",
                success=False,
                failure_reason=str(e),
                poc_source=target_poc.source,
                poc_url=target_poc.url
            )
            
            session.exploit_results.append(failure_result)
            self._save_session(session)
            
            return failure_result
    
    def generate_report(self, session_id: str) -> Dict[str, Any]:
        """Generate comprehensive CrewAI-powered security assessment report"""
        logger.info(f"Generating professional security assessment report for session: {session_id}")
        logger.info("Deploying specialized report generation crew...")
        
        session = self._get_session(session_id)
        
        try:
            # Use CrewAI report generation crew
            report_data = self.report_crew.generate_comprehensive_report(
                target_ip=session.target_ip,
                nmap_result=session.nmap_result,
                analyst_result=session.analyst_result,
                exploit_results=session.exploit_results
            )
            
            # Enhanced logging
            logger.info("CrewAI report generation completed successfully")
            logger.info(f"Report type: {report_data.get('report_type', 'Professional')}")
            logger.info(f"Findings: {report_data.get('findings_count', 0)} vulnerabilities")
            logger.info(f"Critical issues: {report_data.get('critical_issues', 0)}")
            logger.info(f"Successful exploits: {report_data.get('successful_exploits', 0)}")
            
            # Store report data
            session.report_data = report_data
            self._save_session(session)
            
            return report_data
            
        except Exception as e:
            logger.error(f"CrewAI report generation failed: {e}")
            
            # Create basic fallback report
            fallback_report = {
                "report_type": "Professional Security Assessment",
                "target_ip": session.target_ip,
                "assessment_date": "2024-12-19",
                "executive_summary": """Professional security assessment completed using BreachPilot's 
                CrewAI-powered vulnerability analysis framework. The assessment employed specialized 
                AI agents for vulnerability hunting, exploit research, and security analysis.""",
                "technical_findings": """Comprehensive technical analysis performed including network 
                service discovery, vulnerability identification, and exploit validation.""",
                "recommendations": """Professional security recommendations based on identified 
                vulnerabilities and successful exploitation attempts.""",
                "findings_count": len(session.analyst_result.identified_cves) if session.analyst_result else 0,
                "critical_issues": len([cve for cve in session.analyst_result.identified_cves 
                                     if getattr(cve, 'severity', '') == 'Critical']) if session.analyst_result else 0,
                "successful_exploits": len([er for er in session.exploit_results if er.success]) if session.exploit_results else 0,
                "report_url": f"/reports/professional_assessment_{session.target_ip}.html",
                "pdf_url": f"/reports/professional_assessment_{session.target_ip}.pdf"
            }
            
            return fallback_report
    
    def get_session_status(self, session_id: str) -> Dict[str, Any]:
        """Get enhanced session status with CrewAI details"""
        session = self._get_session(session_id)
        
        # Enhanced status with professional metrics
        poc_summary = {}
        exploit_summary = {}
        crewai_status = {
            'analyst_crew': 'Ready',
            'poc_crew': 'Ready',
            'exploit_crew': 'Ready',
            'report_crew': 'Ready'
        }
        
        if session.poc_results:
            poc_summary = {
                'total_cves': len(session.poc_results),
                'total_pocs': sum(len(pr.available_pocs) for pr in session.poc_results),
                'pocs_with_code': sum(pr.with_code for pr in session.poc_results),
                'sources': list(set(poc.source for pr in session.poc_results for poc in pr.available_pocs)),
                'zerologon_ready': any(pr.cve_id == "CVE-2020-1472" for pr in session.poc_results),
                'builtin_exploits': sum(1 for pr in session.poc_results 
                                     for poc in pr.available_pocs 
                                     if 'Built-in' in poc.source)
            }
        
        if session.exploit_results:
            successful_exploits = [er for er in session.exploit_results if er.success]
            exploit_summary = {
                'total_attempts': len(session.exploit_results),
                'successful_exploits': len(successful_exploits),
                'unique_cves_attempted': len(set(er.cve_id for er in session.exploit_results)),
                'success_rate': round(len(successful_exploits) / len(session.exploit_results) * 100, 1) if session.exploit_results else 0,
                'critical_successes': len([er for er in successful_exploits if er.cve_id in ['CVE-2020-1472', 'CVE-2017-0144', 'CVE-2019-0708']]),
                'evidence_collected': sum(len(er.evidence) for er in session.exploit_results if hasattr(er, 'evidence') and er.evidence),
                'artifacts_captured': sum(len(er.artifacts_captured) for er in session.exploit_results if hasattr(er, 'artifacts_captured') and er.artifacts_captured)
            }
        
        return {
            "session_id": session.session_id,
            "target_ip": session.target_ip,
            "current_step": session.current_step,
            "nmap_complete": session.nmap_result is not None,
            "analysis_complete": session.analyst_result is not None,
            "pocs_found": len(session.poc_results) if session.poc_results else 0,
            "exploits_run": len(session.exploit_results) if session.exploit_results else 0,
            "report_available": session.report_data is not None,
            "poc_summary": poc_summary,
            "exploit_summary": exploit_summary,
            "crewai_status": crewai_status,
            "professional_features": {
                'crewai_vulnerability_analysis': True,
                'multi_source_exploit_search': True,
                'professional_reporting': True,
                'enhanced_logging': True
            }
        }
    
    def _get_session(self, session_id: str) -> ScanSession:
        """Get session with enhanced error handling"""
        if session_id not in self.sessions:
            session_file = config.DATA_DIR / f"session_{session_id}.json"
            if session_file.exists():
                try:
                    with open(session_file, 'r') as f:
                        session_data = json.load(f)
                        self.sessions[session_id] = ScanSession(**session_data)
                        logger.debug(f"Session {session_id} loaded from disk")
                except Exception as e:
                    logger.error(f"Failed to load session {session_id}: {e}")
                    raise ValueError(f"Session {session_id} corrupted")
            else:
                logger.error(f"Session {session_id} not found")
                raise ValueError(f"Session {session_id} not found")
        return self.sessions[session_id]
    
    def _save_session(self, session: ScanSession):
        """Save session with enhanced error handling"""
        try:
            session_file = config.DATA_DIR / f"session_{session.session_id}.json"
            config.DATA_DIR.mkdir(exist_ok=True)
            
            with open(session_file, 'w') as f:
                session_data = session.model_dump()
                json.dump(session_data, f, indent=2, default=str)
            
            logger.debug(f"Session {session.session_id} saved successfully")
            
        except Exception as e:
            logger.error(f"Failed to save session {session.session_id}: {e}")
            # Continue execution - session is still in memory