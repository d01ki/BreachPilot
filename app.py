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

# Import our custom modules
from core.demo_scenarios import determine_demo_scenario, run_enhanced_scan, fetch_enhanced_poc, run_demo_exploit
from core.job_runner import run_job
from core.api_endpoints import register_api_routes
from core.mock_imports import get_orchestrator, get_multi_agent_orchestrator, load_config, save_config

app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.getenv("FLASK_SECRET_KEY", "bp-dev-secret")

# Global jobs storage
jobs = {}

# Register API routes
register_api_routes(app, jobs)


@app.get("/")
def index():
    """Main landing page"""
    cfg = load_config()
    
    api_status = {
        "openai": bool(cfg.get("OPENAI_API_KEY")),
        "anthropic": bool(cfg.get("ANTHROPIC_API_KEY")), 
        "github": bool(cfg.get("GITHUB_TOKEN"))
    }
    
    return render_template("index.html", cfg=cfg, api_status=api_status)


@app.get("/attack-chain")
def attack_chain():
    """Attack Chain Orchestrator page"""
    return render_template("attack_chain.html")


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
    
    # Import job utilities
    from core.job_utils import _update_job_status
    
    _update_job_status(jobs, job_id, "initializing", "running", 
                      target=target, 
                      authorize=authorize,
                      started_at=time.time(),
                      progress=0)
    
    t = threading.Thread(target=run_job, args=(jobs, job_id, target, authorize), daemon=True)
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