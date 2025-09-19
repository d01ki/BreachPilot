"""
API endpoints for BreachPilot - Attack Chain and additional functionality
"""
from flask import jsonify, request, send_file
from pathlib import Path
import threading
import asyncio
import uuid
import time
import json as _json

# Mock imports for missing modules
try:
    from src.agents.multi_agent_orchestrator import get_multi_agent_orchestrator
except ImportError:
    print("Using mock multi_agent_orchestrator in api_endpoints.py")
    def get_multi_agent_orchestrator():
        class MockMultiAgentOrchestrator:
            def create_attack_chain(self, target, objective):
                class MockChain:
                    def __init__(self):
                        self.id = str(uuid.uuid4())
                return MockChain()
            def get_chain_status(self, chain_id):
                return {"status": "running", "logs": [{"timestamp": time.time(), "message": f"Mock status for {chain_id}"}]}
            def stop_attack_chain(self, chain_id):
                return {"status": "stopped"}
        return MockMultiAgentOrchestrator()


def setup_api_routes(app):
    """Setup API routes for Flask app"""
    
    @app.post("/api/attack-chain/create")
    def create_attack_chain():
        """Create new enhanced attack chain"""
        try:
            data = request.get_json()
            target = data.get("target")
            objective = data.get("objective", "domain_compromise")
            use_enhanced = data.get("enhanced", True)
            
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
            
            try:
                from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
                orchestrator = get_enhanced_multi_agent_orchestrator()
                is_enhanced = True
            except ImportError:
                orchestrator = get_multi_agent_orchestrator()
                is_enhanced = False
            
            def run_async_execution():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    print(f"[{chain_id}] {'Enhanced' if is_enhanced else 'Standard'} async execution started")
                    
                    if is_enhanced:
                        result = loop.run_until_complete(orchestrator.execute_enhanced_attack_chain(chain_id))
                    else:
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
            try:
                from src.agents.enhanced_multi_agent_orchestrator import get_enhanced_multi_agent_orchestrator
                orchestrator = get_enhanced_multi_agent_orchestrator()
            except ImportError:
                orchestrator = get_multi_agent_orchestrator()
            
            status = orchestrator.get_chain_status(chain_id)
            
            if "error" not in status:
                logs = status.get("logs", [])
                if logs:
                    print(f"[{chain_id}] Returning {len(logs)} log entries to client")
            
            return jsonify(status)
        except Exception as e:
            print(f"Error getting attack chain status {chain_id}: {e}")
            return jsonify({"error": str(e)})

    @app.post("/api/attack-chain/<chain_id>/stop")
    def stop_attack_chain(chain_id: str):
        """Stop enhanced attack chain execution"""
        try:
            print(f"Stopping attack chain: {chain_id}")
            
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

    @app.get("/download/<job_id>/<fmt>")
    def download(job_id: str, fmt: str):
        """Download generated reports"""
        from app import jobs  # Import jobs from main app
        
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
        from app import jobs  # Import jobs from main app
        from flask import render_template, redirect, url_for
        
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
