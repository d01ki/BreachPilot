"""
API endpoints for hybrid attack chain (Mock + Real AI)
"""
from flask import jsonify, request
import threading
import asyncio
import logging

logger = logging.getLogger(__name__)


def setup_realtime_api_routes(app):
    """Setup API routes for hybrid orchestrator"""
    
    @app.post("/api/attack-chain/create")
    def create_attack_chain():
        """Create new attack chain"""
        try:
            from src.agents.hybrid_orchestrator import get_hybrid_orchestrator
            
            data = request.get_json()
            target = data.get("target")
            objective = data.get("objective", "full_pentest")
            
            if not target:
                return jsonify({"success": False, "error": "Target is required"})
            
            orchestrator = get_hybrid_orchestrator()
            chain = orchestrator.create_attack_chain(target, objective)
            
            logger.info(f"Created chain {chain.id} for {target}")
            
            return jsonify({
                "success": True,
                "chain_id": chain.id,
                "message": "Hybrid attack chain created (Mock + Real AI)"
            })
        except Exception as e:
            logger.error(f"Error creating chain: {e}")
            return jsonify({"success": False, "error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/execute")
    def execute_attack_chain(chain_id: str):
        """Execute attack chain"""
        try:
            from src.agents.hybrid_orchestrator import get_hybrid_orchestrator
            
            orchestrator = get_hybrid_orchestrator()
            
            def run_async_execution():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        orchestrator.execute_attack_chain(chain_id)
                    )
                    logger.info(f"Chain {chain_id} completed: {result.get('status')}")
                except Exception as e:
                    logger.error(f"Chain {chain_id} error: {e}")
                finally:
                    loop.close()
            
            thread = threading.Thread(target=run_async_execution, daemon=True)
            thread.start()
            
            return jsonify({
                "success": True,
                "message": "Execution started"
            })
        except Exception as e:
            logger.error(f"Error executing {chain_id}: {e}")
            return jsonify({"success": False, "error": str(e)})
    
    @app.get("/api/attack-chain/<chain_id>/status")
    def get_attack_chain_status(chain_id: str):
        """Get real-time status"""
        try:
            from src.agents.hybrid_orchestrator import get_hybrid_orchestrator
            
            orchestrator = get_hybrid_orchestrator()
            status = orchestrator.get_chain_status(chain_id)
            
            return jsonify(status)
        except Exception as e:
            logger.error(f"Error getting status {chain_id}: {e}")
            return jsonify({"error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/stop")
    def stop_attack_chain(chain_id: str):
        """Stop execution"""
        try:
            from src.agents.hybrid_orchestrator import get_hybrid_orchestrator
            
            orchestrator = get_hybrid_orchestrator()
            result = orchestrator.stop_attack_chain(chain_id)
            
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error stopping {chain_id}: {e}")
            return jsonify({"error": str(e)})
