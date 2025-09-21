from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from pathlib import Path
import threading
import uuid
import os
import re
import json as _json
import time
import asyncio
import shutil
from datetime import datetime

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "bp-dev-secret")

jobs = {}


def _persist_meta(job_id: str, meta: dict):
    """Persist job metadata to disk"""
    job_dir = Path("reports") / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    (job_dir / "meta.json").write_text(_json.dumps(meta, indent=2))


def _update_job_status(job_id: str, phase: str, status: str = "running", **kwargs):
    """Update job status with additional metadata"""
    if job_id not in jobs:
        jobs[job_id] = {}
    
    jobs[job_id].update({
        "status": status,
        "phase": phase,
        "last_update": time.time(),
        **kwargs
    })
    _persist_meta(job_id, jobs[job_id])


@app.get("/")
def index():
    """Main landing page"""
    return render_template("index.html")


@app.get("/pentest")
def pentest():
    """Automated Pentest page"""
    return render_template("pentest.html")


@app.get("/settings")
def settings():
    """Settings page"""
    return render_template("settings.html")


@app.get("/api/jobs")
def api_list_jobs():
    """API endpoint to list recent jobs"""
    recent_jobs = []
    
    reports_dir = Path("reports")
    if reports_dir.exists():
        for job_dir in sorted(reports_dir.iterdir(), key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
            if job_dir.is_dir():
                meta_file = job_dir / "meta.json"
                if meta_file.exists():
                    try:
                        meta = _json.loads(meta_file.read_text())
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
                        })
                    except Exception as e:
                        print(f"Error reading job meta {job_dir}: {e}")
    
    return jsonify({"jobs": recent_jobs})


@app.delete("/api/job/<job_id>")
def delete_job(job_id: str):
    """Delete a specific job"""
    try:
        if job_id in jobs:
            del jobs[job_id]
        
        job_dir = Path("reports") / job_id
        if job_dir.exists():
            shutil.rmtree(job_dir)
            print(f"Deleted job {job_id}")
        
        return jsonify({"success": True, "message": f"Job {job_id} deleted"})
    except Exception as e:
        print(f"Error deleting job {job_id}: {e}")
        return jsonify({"success": False, "error": str(e)})


# Import real-time API endpoints
try:
    from api_realtime_endpoints import setup_realtime_api_routes
    setup_realtime_api_routes(app)
    print("✅ Real-time API routes loaded")
except ImportError as e:
    print(f"⚠️  Real-time API routes not available: {e}")


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
    return jsonify({"error": "Not found"}), 404


@app.errorhandler(500)
def internal_error(error):
    """500 error handler"""
    return jsonify({"error": "Internal server error"}), 500


if __name__ == "__main__":
    # Ensure reports directory exists
    Path("reports").mkdir(exist_ok=True)
    
    # Run Flask app
    port = int(os.getenv("PORT", 5000))
    debug = os.getenv("FLASK_DEBUG", "false").lower() == "true"
    
    print("=" * 50)
    print("🚀 BreachPilot - Automated Pentest")
    print("=" * 50)
    print(f"🌐 Server: http://localhost:{port}")
    print(f"⚡ Pentest: http://localhost:{port}/pentest")
    print("=" * 50)
    
    app.run(host="0.0.0.0", port=port, debug=debug)
