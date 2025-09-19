        ai_scan_result = orchestrator.analyze_scan_results(jobs[job_id]["scan"], work_dir)
        if ai_scan_result["status"] == "success":
            jobs[job_id]["ai_scan_analysis"] = ai_scan_result["result"]
            artifacts["ai_scan_analysis"] = ai_scan_result["path"]
        else:
            jobs[job_id]["ai_scan_analysis"] = f"AI analysis failed: {ai_scan_result.get('error', 'Unknown error')}"
        
        update_job_status_func(job_id, "poc", "running", progress=45)
        
        # Phase 3: Enhanced PoC Retrieval with real CVEs
        print(f"[{job_id}] Fetching real PoC information for scenario: {scenario['name']}")
        poc_info = fetch_enhanced_poc(scan_json, work_dir, scenario)
        artifacts["poc"] = poc_info
        jobs[job_id]["poc"] = poc_info
        
        update_job_status_func(job_id, "ai_poc_research", "running", progress=55)
        
        # Phase 4: AI-powered PoC Research
        print(f"[{job_id}] Running AI PoC research")
        ai_poc_result = orchestrator.research_poc(poc_info, work_dir)
        if ai_poc_result["status"] == "success":
            jobs[job_id]["ai_poc_research"] = ai_poc_result["result"]
            artifacts["ai_poc_research"] = ai_poc_result["path"]
        else:
            jobs[job_id]["ai_poc_research"] = f"AI PoC research failed: {ai_poc_result.get('error', 'Unknown error')}"
        
        update_job_status_func(job_id, "exploit", "running", progress=65)
        
        # Phase 5: Demo Exploit Execution
        print(f"[{job_id}] Running demo exploit execution")
        exploit_log = run_demo_exploit(target, poc_info, work_dir, scenario, authorize=use_authorize)
        artifacts["exploit_log"] = str(exploit_log)
        
        try:
            exploit_data = _json.loads(Path(exploit_log).read_text())
            jobs[job_id]["exploit"] = exploit_data
            jobs[job_id]["exploit_log_tail"] = str(exploit_data)[-800:]
        except Exception:
            jobs[job_id]["exploit_log_tail"] = "Failed to load exploit log"
        
        update_job_status_func(job_id, "ai_exploit_analysis", "running", progress=75)
        
        # Phase 6: AI-powered Exploit Analysis
        print(f"[{job_id}] Running AI exploit analysis")
        ai_exploit_result = orchestrator.analyze_exploit_results(jobs[job_id].get("exploit", {}), work_dir)
        if ai_exploit_result["status"] == "success":
            jobs[job_id]["ai_exploit_analysis"] = ai_exploit_result["result"]
            artifacts["ai_exploit_analysis"] = ai_exploit_result["path"]
        else:
            jobs[job_id]["ai_exploit_analysis"] = f"AI exploit analysis failed: {ai_exploit_result.get('error', 'Unknown error')}"
        
        update_job_status_func(job_id, "report", "running", progress=85)
        
        # Phase 7: Enhanced Report Generation
        print(f"[{job_id}] Generating comprehensive report")
        report_md, report_pdf = generate_report(target, artifacts, work_dir)
        
        # Final status update
        update_job_status_func(job_id, "completed", "completed", 
                              progress=100,
                              report_md=str(report_md),
                              report_pdf=str(report_pdf),
                              artifacts=artifacts,
                              completed_at=time.time())
        
        print(f"[{job_id}] Job completed successfully")
        
    except Exception as e:
        print(f"[{job_id}] Job failed: {str(e)}")
        update_job_status_func(job_id, "failed", "failed", 
                              error=str(e),
                              failed_at=time.time())
