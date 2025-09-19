from flask import Flask, render_template, request, redirect, url_for, send_file, jsonify, flash
from pathlib import Path
import threading
import uuid
import os
import re
import json as _json
import time
import asyncio

from src.agents.scan_agent import run_scan
from src.agents.poc_agent import fetch_poc
from src.agents.exploit_agent import run_exploit
from src.agents.report_agent import generate_report
from src.agents.ai_orchestrator import get_orchestrator
from src.agents.multi_agent_orchestrator import get_multi_agent_orchestrator
from src.utils.config import load_config, save_config


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


def run_job(job_id: str, target: str, use_authorize: bool):
    """Enhanced job runner with AI agent integration"""
    try:
        work_dir = Path("reports") / job_id
        work_dir.mkdir(parents=True, exist_ok=True)
        artifacts = {}
        
        # Get AI orchestrator
        orchestrator = get_orchestrator()
        
        # Phase 1: Network Scan
        _update_job_status(job_id, "scan", "running", progress=10)
        print(f"[{job_id}] Starting network scan for {target}")
        
        scan_json = run_scan(target, work_dir)
        artifacts["scan_json"] = str(scan_json)
        
        try:
            scan_data = _json.loads(Path(scan_json).read_text())
            jobs[job_id]["scan"] = scan_data
        except Exception:
            jobs[job_id]["scan"] = {"target": target, "error": "Failed to parse scan results"}
        
        _update_job_status(job_id, "scan", "running", progress=25)
        
        # Phase 2: AI-powered Scan Analysis
        _update_job_status(job_id, "ai_scan_analysis", "running", progress=35)
        print(f"[{job_id}] Running AI scan analysis")
        
        ai_scan_result = orchestrator.analyze_scan_results(jobs[job_id]["scan"], work_dir)
        if ai_scan_result["status"] == "success":
            jobs[job_id]["ai_scan_analysis"] = ai_scan_result["result"]
            artifacts["ai_scan_analysis"] = ai_scan_result["path"]
        else:
            jobs[job_id]["ai_scan_analysis"] = f"AI analysis failed: {ai_scan_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "poc", "running", progress=45)
        
        # Phase 3: PoC Retrieval  
        print(f"[{job_id}] Fetching PoC information")
        poc_info = fetch_poc(scan_json, work_dir)
        artifacts["poc"] = poc_info
        jobs[job_id]["poc"] = poc_info
        
        _update_job_status(job_id, "ai_poc_research", "running", progress=55)
        
        # Phase 4: AI-powered PoC Research
        print(f"[{job_id}] Running AI PoC research")
        ai_poc_result = orchestrator.research_poc(poc_info, work_dir)
        if ai_poc_result["status"] == "success":
            jobs[job_id]["ai_poc_research"] = ai_poc_result["result"]
            artifacts["ai_poc_research"] = ai_poc_result["path"]
        else:
            jobs[job_id]["ai_poc_research"] = f"AI PoC research failed: {ai_poc_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "exploit", "running", progress=65)
        
        # Phase 5: Exploit Execution
        print(f"[{job_id}] Running exploit execution")
        exploit_log = run_exploit(target, poc_info, work_dir, authorize=use_authorize)
        artifacts["exploit_log"] = str(exploit_log)
        
        try:
            exploit_data = _json.loads(Path(exploit_log).read_text())
            jobs[job_id]["exploit"] = exploit_data
            jobs[job_id]["exploit_log_tail"] = str(exploit_data)[-800:]
        except Exception:
            jobs[job_id]["exploit_log_tail"] = "Failed to load exploit log"
        
        _update_job_status(job_id, "ai_exploit_analysis", "running", progress=75)
        
        # Phase 6: AI-powered Exploit Analysis
        print(f"[{job_id}] Running AI exploit analysis")
        ai_exploit_result = orchestrator.analyze_exploit_results(jobs[job_id].get("exploit", {}), work_dir)
        if ai_exploit_result["status"] == "success":
            jobs[job_id]["ai_exploit_analysis"] = ai_exploit_result["result"]
            artifacts["ai_exploit_analysis"] = ai_exploit_result["path"]
        else:
            jobs[job_id]["ai_exploit_analysis"] = f"AI exploit analysis failed: {ai_exploit_result.get('error', 'Unknown error')}"
        
        _update_job_status(job_id, "report", "running", progress=85)
        
        # Phase 7: AI-powered Report Generation
        print(f"[{job_id}] Generating comprehensive report")
        report_md, report_pdf = generate_report(target, artifacts, work_dir)
        
        # Final status update
        _update_job_status(job_id, "completed", "completed", 
                          progress=100,
                          report_md=str(report_md),
                          report_pdf=str(report_pdf),
                          artifacts=artifacts,
                          completed_at=time.time())
        
        print(f"[{job_id}] Job completed successfully")
        
    except Exception as e:
        print(f"[{job_id}] Job failed: {str(e)}")
        _update_job_status(job_id, "failed", "failed", 
                          error=str(e),
                          failed_at=time.time())


@app.get("/")
def index():
    """Main landing page"""
    cfg = load_config()
    
    # Check API key configuration status
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


# Enhanced Attack Chain API Endpoints
@app.post("/api/attack-chain/create")
def create_attack_chain():
    """Create new enhanced attack chain"""
    try:
        data = request.get_json()
        target = data.get("target")
        objective = data.get("objective", "domain_compromise")
        use_enhanced = data.get("enhanced", True)  # デフォルトで強化版を使用
        
        if not target:
            return jsonify({"success": False, "error": "Target is required"})
        
        print(f"Creating {'enhanced' if use_enhanced else 'standard'} attack chain for target: {target}, objective: {objective}")
        
        if use_enhanced:
            try:
                from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
                orchestrator = get_enhanced_multi_agent_orchestrator()
                print("Using Enhanced Multi-Agent Orchestrator with real tools and AI analysis")
            except ImportError as e:
                print(f"Enhanced orchestrator not available, falling back to standard: {e}")
                orchestrator = get_multi_agent_orchestrator()
        else:
            orchestrator = get_multi_agent_orchestrator()
        
        chain = orchestrator.create_attack_chain(target, objective)
        
        print(f"Attack chain created with ID: {chain.id}")
        
        return jsonify({
            "success": True,
            "chain_id": chain.id,
            "enhanced": use_enhanced,
            "message": f"{'Enhanced' if use_enhanced else 'Standard'} attack chain created successfully"
        })
    except Exception as e:
        print(f"Error creating attack chain: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.post("/api/attack-chain/<chain_id>/execute")
def execute_attack_chain(chain_id: str):
    """Execute enhanced attack chain"""
    try:
        print(f"Starting execution for attack chain: {chain_id}")
        
        # Try enhanced orchestrator first
        try:
            from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
            orchestrator = get_enhanced_multi_agent_orchestrator()
            is_enhanced = True
        except ImportError:
            orchestrator = get_multi_agent_orchestrator()
            is_enhanced = False
        
        # Run execution in background thread since it's async
        def run_async_execution():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                print(f"[{chain_id}] {'Enhanced' if is_enhanced else 'Standard'} async execution started")
                
                if is_enhanced:
                    # Enhanced execution with real tools
                    result = loop.run_until_complete(orchestrator.execute_enhanced_attack_chain(chain_id))
                else:
                    # Standard simulation execution
                    result = loop.run_until_complete(orchestrator.execute_attack_chain(chain_id))
                
                print(f"[{chain_id}] Execution completed: {result.get('status', 'unknown')}")
            except Exception as e:
                print(f"[{chain_id}] Execution error: {e}")
            finally:
                loop.close()
        
        thread = threading.Thread(target=run_async_execution, daemon=True)
        thread.start()
        
        return jsonify({
            "success": True,
            "enhanced": is_enhanced,
            "message": f"{'Enhanced' if is_enhanced else 'Standard'} attack chain execution started"
        })
    except Exception as e:
        print(f"Error executing attack chain {chain_id}: {e}")
        return jsonify({"success": False, "error": str(e)})


@app.get("/api/attack-chain/<chain_id>/status")
def get_attack_chain_status(chain_id: str):
    """Get enhanced attack chain status"""
    try:
        # Try enhanced orchestrator first
        try:
            from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
            orchestrator = get_enhanced_multi_agent_orchestrator()
        except ImportError:
            orchestrator = get_multi_agent_orchestrator()
        
        status = orchestrator.get_chain_status(chain_id)
        
        # Add enhanced information if available
        if "error" not in status:
            logs = status.get("logs", [])
            if logs:
                print(f"[{chain_id}] Returning {len(logs)} log entries to client")
        
        return jsonify(status)
    except Exception as e:
        print(f"Error getting attack chain status {chain_id}: {e}")
        return jsonify({"error": str(e)})


@app.get("/api/attack-chain/<chain_id>/logs")
def get_attack_chain_logs(chain_id: str):
    """Get real-time logs for enhanced attack chain"""
    try:
        # Try enhanced orchestrator first
        try:
            from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
            orchestrator = get_enhanced_multi_agent_orchestrator()
        except ImportError:
            orchestrator = get_multi_agent_orchestrator()
        
        # Get logs from orchestrator
        if hasattr(orchestrator, 'execution_logs') and chain_id in orchestrator.execution_logs:
            logs = orchestrator.execution_logs[chain_id]
            return jsonify({"logs": logs})
        else:
            return jsonify({"logs": []})
    except Exception as e:
        print(f"Error getting logs for chain {chain_id}: {e}")
        return jsonify({"error": str(e), "logs": []})


@app.post("/api/attack-chain/<chain_id>/stop")
def stop_attack_chain(chain_id: str):
    """Stop enhanced attack chain execution"""
    try:
        print(f"Stopping attack chain: {chain_id}")
        
        # Try enhanced orchestrator first
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


@app.post("/api/attack-chain/<chain_id>/pause")
def pause_attack_chain(chain_id: str):
    """Pause enhanced attack chain execution (same as stop for now)"""
    return stop_attack_chain(chain_id)


@app.post("/start")
def start():
    """Start traditional penetration test job"""
    target = request.form.get("target", "").strip()
    authorize = request.form.get("authorize", "off") == "on"
    
    # Enhanced target validation
    ip_pat = re.compile(r"^((\d{1,3}\.){3}\d{1,3}|localhost)$")
    host_pat = re.compile(r"^[A-Za-z0-9.-]{1,253}$")
    
    if not (ip_pat.match(target) or host_pat.match(target)):
        flash("Invalid target format. Please enter a valid IP address or hostname.", "error")
        return redirect(url_for("index"))
    
    # Check if API keys are configured
    cfg = load_config()
    if not cfg.get("ANTHROPIC_API_KEY"):
        flash("Anthropic API key required for AI features. Please configure in Settings.", "warning")
    
    job_id = str(uuid.uuid4())
    _update_job_status(job_id, "initializing", "running", 
                      target=target, 
                      authorize=authorize,
                      started_at=time.time(),
                      progress=0)
    
    # Start job in background thread
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
    
    # Update API keys
    cfg["OPENAI_API_KEY"] = request.form.get("openai_api_key", "").strip()
    cfg["ANTHROPIC_API_KEY"] = request.form.get("anthropic_api_key", "").strip()
    cfg["GITHUB_TOKEN"] = request.form.get("github_token", "").strip()
    
    # Optional: Test API keys
    test_keys = request.form.get("test_keys", "off") == "on"
    if test_keys:
        test_results = {}
        
        # Test Anthropic
        if cfg["ANTHROPIC_API_KEY"]:
            try:
                from anthropic import Anthropic
                client = Anthropic(api_key=cfg["ANTHROPIC_API_KEY"])
                response = client.messages.create(
                    model="claude-3-haiku-20240307",
                    max_tokens=10,
                    messages=[{"role": "user", "content": "test"}]
                )
                test_results["anthropic"] = "✅ Valid"
            except Exception as e:
                test_results["anthropic"] = f"❌ Invalid: {str(e)[:50]}"
        
        # Test OpenAI
        if cfg["OPENAI_API_KEY"]:
            try:
                import openai
                client = openai.OpenAI(api_key=cfg["OPENAI_API_KEY"])
                response = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    max_tokens=5,
                    messages=[{"role": "user", "content": "test"}]
                )
                test_results["openai"] = "✅ Valid"
            except Exception as e:
                test_results["openai"] = f"❌ Invalid: {str(e)[:50]}"
        
        # Test GitHub
        if cfg["GITHUB_TOKEN"]:
            try:
                import requests
                response = requests.get("https://api.github.com/user", 
                                      headers={"Authorization": f"token {cfg['GITHUB_TOKEN']}"})
                if response.status_code == 200:
                    test_results["github"] = "✅ Valid"
                else:
                    test_results["github"] = f"❌ Invalid: {response.status_code}"
            except Exception as e:
                test_results["github"] = f"❌ Invalid: {str(e)[:50]}"
        
        for service, result in test_results.items():
            flash(f"{service.upper()} API: {result}", "info")
    
    save_config(cfg)
    flash("Settings saved successfully!", "success")
    return redirect(url_for("settings"))


@app.get("/status/<job_id>")
def status(job_id: str):
    """Job status page with real-time updates"""
    job = jobs.get(job_id)
    
    # Try to load from disk if not in memory
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
    
    # Determine current phase for UI display
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
    
    # Try loading from disk if not in memory
    if not job:
        meta_path = Path("reports") / job_id / "meta.json"
        if meta_path.exists():
            try:
                job = _json.loads(meta_path.read_text())
                jobs[job_id] = job
            except Exception:
                pass
    
    # Return sanitized job info
    return jsonify({
        "status": job.get("status", "not_found"),
        "phase": job.get("phase", "unknown"),
        "progress": job.get("progress", 0),
        "last_update": job.get("last_update", 0),
        "error": job.get("error"),
        "target": job.get("target"),
        "started_at": job.get("started_at"),
        "completed_at": job.get("completed_at"),
        "has_reports": bool(job.get("report_md"))
    })


@app.get("/download/<job_id>/<fmt>")
def download(job_id: str, fmt: str):
    """Download generated reports"""
    job = jobs.get(job_id)
    
    if not job or job.get("status") != "completed":
        return "Report not ready", 404
    
    # Determine file to download
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
    
    # Try to load from disk if not in memory
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
                        recent_jobs.append({
                            "job_id": job_dir.name,
                            "target": meta.get("target", "unknown"),
                            "status": meta.get("status", "unknown"),
                            "phase": meta.get("phase", "unknown"),
                            "started_at": meta.get("started_at"),
                            "completed_at": meta.get("completed_at")
                        })
                    except Exception:
                        pass
    
    return jsonify({"jobs": recent_jobs})


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
    print("AI Agent Features:")
    print("  - CrewAI Integration: ✅") 
    print("  - Claude Analysis: ✅") 
    print("  - OpenAI Support: ✅")
    print("  - Enhanced Multi-Agent Orchestrator: ✅")
    print("  - Real Tool Execution: ✅")
    print("  - AI-Powered Analysis: ✅")
    print("  - Attack Chain Visualization: ✅")
    print("  - Real-time Logging: ✅")
    print("  - Enhanced Reporting: ✅")
    
    app.run(host="0.0.0.0", port=port, debug=debug)
