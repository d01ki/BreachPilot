"""
API endpoints for final orchestrator
"""
from flask import jsonify, request
import threading
import asyncio
import logging

logger = logging.getLogger(__name__)


def setup_realtime_api_routes(app):
    """Setup API routes"""
    
    @app.post("/api/attack-chain/create")
    def create_attack_chain():
        """Create chain"""
        try:
            from src.agents.final_orchestrator import get_final_orchestrator
            
            data = request.get_json()
            target = data.get("target")
            objective = data.get("objective", "full_pentest")
            
            if not target:
                return jsonify({"success": False, "error": "Target required"})
            
            orchestrator = get_final_orchestrator()
            chain = orchestrator.create_attack_chain(target, objective)
            
            logger.info(f"Created chain {chain.id} for {target}")
            
            return jsonify({
                "success": True,
                "chain_id": chain.id,
                "message": "OpenAI-powered chain created"
            })
        except Exception as e:
            logger.error(f"Error creating chain: {e}")
            return jsonify({"success": False, "error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/execute")
    def execute_attack_chain(chain_id: str):
        """Execute chain"""
        try:
            from src.agents.final_orchestrator import get_final_orchestrator
            
            orchestrator = get_final_orchestrator()
            
            def run_async():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        orchestrator.execute_attack_chain(chain_id)
                    )
                    logger.info(f"Chain {chain_id} done: {result.get('status')}")
                except Exception as e:
                    logger.error(f"Chain {chain_id} error: {e}")
                finally:
                    loop.close()
            
            thread = threading.Thread(target=run_async, daemon=True)
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
        """Get status"""
        try:
            from src.agents.final_orchestrator import get_final_orchestrator
            
            orchestrator = get_final_orchestrator()
            status = orchestrator.get_chain_status(chain_id)
            
            return jsonify(status)
        except Exception as e:
            logger.error(f"Error getting status {chain_id}: {e}")
            return jsonify({"error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/stop")
    def stop_attack_chain(chain_id: str):
        """Stop chain"""
        try:
            from src.agents.final_orchestrator import get_final_orchestrator
            
            orchestrator = get_final_orchestrator()
            result = orchestrator.stop_attack_chain(chain_id)
            
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error stopping {chain_id}: {e}")
            return jsonify({"error": str(e)})
