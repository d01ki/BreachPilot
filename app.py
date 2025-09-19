        try:
            from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
            orchestrator = get_enhanced_multi_agent_orchestrator()
        except ImportError:
            orchestrator = get_multi_agent_orchestrator()
        
        result = orchestrator.stop_attack_chain(chain_id)
        return jsonify(result)
    except Exception as e:
        print(f"Error stopping attack chain {chain_id}: {e}")
        return jsonify({"error": str(e)})


@app.post("/start")
def start():
    """Start traditional penetration test job"""
    target = request.form.get("target", "").strip()
    authorize = request.form.get("authorize", "off") == "on"
    
    ip_pat = re.compile(r"^((\d{1,3}\.){3}\d{1,3}|localhost)$")
    host_pat = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
    
    if not (ip_pat.match(target) or host_pat.match(target)):
        flash("Invalid target format. Please enter a valid IP address or hostname.", "error")
        return redirect(url_for("index"))
    
    cfg = load_config()
    if not cfg.get("ANTHROPIC_API_KEY"):
        flash("Anthropic API key required for AI features. Please configure in Settings.", "warning")
    
    job_id = str(uuid.uuid4())
    _update_job_status(job_id, "initializing", "running", 
                      target=target, 
                      authorize=authorize,
                      started_at=time.time(),
                      progress=0)
    
    t = threading.Thread(target=run_job, args=(job_id, target, authorize), daemon=True)
    t.start()
    
    return redirect(url_for("status", job_id=job_id))


@app.get("/settings")
def settings():
    """Settings page"""
    cfg = load_config()
    return render_template("settings.html", cfg=cfg)


@app.post("/settings")
def save_settings():
    """Save API configuration"""
    cfg = load_config()
    
    cfg["OPENAI_API_KEY"] = request.form.get("openai_api_key", "").strip()
    cfg["ANTHROPIC_API_KEY"] = request.form.get("anthropic_api_key", "").strip()
    cfg["GITHUB_TOKEN"] = request.form.get("github_token", "").strip()
    
    save_config(cfg)
    flash("Settings saved successfully!", "success")
    return redirect(url_for("settings"))


@app.get("/status/<job_id>")
def status(job_id: str):
    """Job status page with real-time updates"""
    job = jobs.get(job_id)
    
    if not job:
        meta_path = Path("reports") / job_id / "meta.json"
        if meta_path.exists():
            try:
                job = _json.loads(meta_path.read_text())
                jobs[job_id] = job
            except Exception:
                job = None
    
    if not job:
        return render_template("status.html", job_id=job_id, status="not_found")
    
    phase = job.get("phase", "unknown")
    status_val = job.get("status", "unknown")
    progress = job.get("progress", 0)
    
    return render_template("status.html", 
                          job_id=job_id, 
                          status=status_val,
                          phase=phase,
                          progress=progress,
                          job=job)


@app.get("/api/job/<job_id>")
def api_job_status(job_id: str):
    """API endpoint for real-time job status updates"""
    job = jobs.get(job_id, {})
    
    if not job:
        meta_path = Path("reports") / job_id / "meta.json"
        if meta_path.exists():
            try:
                job = _json.loads(meta_path.read_text())
                jobs[job_id] = job
            except Exception:
                pass
    
    return jsonify({
        "status": job.get("status", "not_found"),
        "phase": job.get("phase", "unknown"),
        "progress": job.get("progress", 0),
        "last_update": job.get("last_update", 0),
        "error": job.get("error"),
        "target": job.get("target"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "has_reports": bool(job.get("report_md")),
        "scan_output": job.get("scan_output"),
        "scenario": job.get("scenario"),
        "scan": job.get("scan"),
        "exploit": job.get("exploit")
    })


@app.get("/download/<job_id>/<fmt>")
def download(job_id: str, fmt: str):
    """Download generated reports"""
    job = jobs.get(job_id)
    
    if not job or job.get("status") != "completed":
        return "Report not ready", 404
    
    if fmt == "pdf":
        file_path = job.get("report_pdf")
    elif fmt in ["md", "markdown"]:
        file_path = job.get("report_md")
    else:
        return "Invalid format", 400
    
    if not file_path or not Path(file_path).exists():
        return "File not found", 404
    
    return send_file(file_path, as_attachment=True)


@app.get("/results/<job_id>")
def results(job_id: str):
    """Detailed results view"""
    job = jobs.get(job_id)
    
    if not job:
        meta_path = Path("reports") / job_id / "meta.json"
        if meta_path.exists():
            try:
                job = _json.loads(meta_path.read_text())
                jobs[job_id] = job
            except Exception:
                job = None
    
    if not job:
        return "Job not found", 404
    
    if job.get("status") != "completed":
        return redirect(url_for("status", job_id=job_id))
    
    return render_template("results.html", job_id=job_id, job=job)


@app.get("/api/jobs")
def api_list_jobs():
    """API endpoint to list recent jobs with enhanced info"""
    recent_jobs = []
    
    reports_dir = Path("reports")
    if reports_dir.exists():
        for job_dir in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
            if job_dir.is_dir():
                meta_file = job_dir / "meta.json"
                if meta_file.exists():
                    try:
                        meta = _json.loads(meta_file.read_text())
                        
                        # Calculate file sizes
                        total_size = sum(f.stat().st_size for f in job_dir.rglob('*') if f.is_file())
                        
                        recent_jobs.append({
                            "job_id": job_dir.name,
                            "target": meta.get("target", "unknown"),
                            "status": meta.get("status", "unknown"),
                            "phase": meta.get("phase", "unknown"),
                            "started_at": meta.get("started_at"),
                            "completed_at": meta.get("completed_at"),
                            "progress": meta.get("progress", 0),
                            "size_mb": round(total_size / (1024 * 1024), 2),
                            "has_reports": bool(meta.get("report_md") or meta.get("report_pdf")),
                            "scenario": meta.get("scenario", {}).get("name", "Generic")
                        })
                    except Exception as e:
                        print(f"Error reading job meta {job_dir}: {e}")
    
    return jsonify({"jobs": recent_jobs})


@app.delete("/api/job/<job_id>")
def delete_job(job_id: str):
    """Delete a specific job and its artifacts"""
    try:
        # Remove from memory
        if job_id in jobs:
            del jobs[job_id]
        
        # Remove from disk
        job_dir = Path("reports") / job_id
        if job_dir.exists():
            shutil.rmtree(job_dir)
            print(f"Deleted job {job_id} and its artifacts")
        
        return jsonify({"success": True, "message": f"Job {job_id} deleted successfully"})
    except Exception as e:
        print(f"Error deleting job {job_id}: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.post("/api/jobs/cleanup")
def cleanup_old_jobs():
    """Clean up old jobs (keep only latest 5)"""
    try:
        reports_dir = Path("reports")
        if not reports_dir.exists():
            return jsonify({"success": True, "message": "No jobs to cleanup"})
        
        # Get all job directories sorted by modification time
        job_dirs = []
        for job_dir in reports_dir.iterdir():
            if job_dir.is_dir():
                job_dirs.append((job_dir, job_dir.stat().st_mtime))
        
        # Sort by modification time (newest first)
        job_dirs.sort(key=lambda x: x[1], reverse=True)
        
        # Keep only the latest 5, delete the rest
        deleted_count = 0
        for job_dir, _ in job_dirs[5:]:  # Skip first 5 (keep them)
            try:
                shutil.rmtree(job_dir)
                
                # Also remove from memory
                job_id = job_dir.name
                if job_id in jobs:
                    del jobs[job_id]
                
                deleted_count += 1
                print(f"Cleaned up old job: {job_id}")
            except Exception as e:
                print(f"Error deleting {job_dir}: {e}")
        
        return jsonify({
            "success": True, 
            "message": f"Cleaned up {deleted_count} old jobs",
            "deleted_count": deleted_count
        })
    except Exception as e:
        print(f"Error during cleanup: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.get("/health")
def health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": time.time(),
        "active_jobs": len([j for j in jobs.values() if j.get("status") == "running"]),
        "total_jobs": len(jobs)
    })


@app.errorhandler(404)
def not_found_error(error):
    """404 error handler"""
    return render_template("error.html", error="Page not found", code=404), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return render_template("error.html", error="Internal server error", code=500), 500


if __name__ == "__main__":
    # Ensure reports directory exists
    Path("reports").mkdir(exist_ok=True)
    
    # Run Flask app
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print(f"Starting Enhanced BreachPilot on port {port}")
    print("Enhanced Features:")
    print("  - Real-time Traditional Test: ✅") 
    print("  - Multi-Scenario Demo: ✅") 
    print("  - Enhanced Attack Chain: ✅")
    print("  - Job Management: ✅")
    print("  - Real CVE/PoC Integration: ✅")
    print("  - Beautiful UI: ✅")
    print("  - Production Ready: ✅")
    
    app.run(host="0.0.0.0", port=port, debug=debug)