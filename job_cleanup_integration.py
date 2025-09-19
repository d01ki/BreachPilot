# Job Management API Endpoints (integrate into app.py)
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
            import shutil
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
                import shutil
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