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