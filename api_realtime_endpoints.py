"""
Updated API endpoints for real-time attack chain
"""
from flask import jsonify, request
import threading
import asyncio
import logging

logger = logging.getLogger(__name__)


def setup_realtime_api_routes(app):
    """Setup real-time API routes"""
    
    @app.post("/api/attack-chain/create")
    def create_attack_chain():
        """Create new attack chain with real tools"""
        try:
            from src.agents.realtime_orchestrator import get_realtime_orchestrator
            
            data = request.get_json()
            target = data.get("target")
            objective = data.get("objective", "full_pentest")
            
            if not target:
                return jsonify({"success": False, "error": "Target is required"})
            
            orchestrator = get_realtime_orchestrator()
            chain = orchestrator.create_attack_chain(target, objective)
            
            logger.info(f"Created attack chain {chain.id} for target: {target}")
            
            return jsonify({
                "success": True,
                "chain_id": chain.id,
                "message": "Real-time attack chain created"
            })
        except Exception as e:
            logger.error(f"Error creating attack chain: {e}")
            return jsonify({"success": False, "error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/execute")
    def execute_attack_chain(chain_id: str):
        """Execute attack chain with real tools"""
        try:
            from src.agents.realtime_orchestrator import get_realtime_orchestrator
            
            orchestrator = get_realtime_orchestrator()
            
            def run_async_execution():
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(
                        orchestrator.execute_attack_chain(chain_id)
                    )
                    logger.info(f"Chain {chain_id} execution completed: {result.get('status')}")
                except Exception as e:
                    logger.error(f"Chain {chain_id} execution error: {e}")
                finally:
                    loop.close()
            
            thread = threading.Thread(target=run_async_execution, daemon=True)
            thread.start()
            
            return jsonify({
                "success": True,
                "message": "Attack chain execution started"
            })
        except Exception as e:
            logger.error(f"Error executing attack chain {chain_id}: {e}")
            return jsonify({"success": False, "error": str(e)})
    
    @app.get("/api/attack-chain/<chain_id>/status")
    def get_attack_chain_status(chain_id: str):
        """Get real-time status with scan results"""
        try:
            from src.agents.realtime_orchestrator import get_realtime_orchestrator
            
            orchestrator = get_realtime_orchestrator()
            status = orchestrator.get_chain_status(chain_id)
            
            return jsonify(status)
        except Exception as e:
            logger.error(f"Error getting status for {chain_id}: {e}")
            return jsonify({"error": str(e)})
    
    @app.post("/api/attack-chain/<chain_id>/stop")
    def stop_attack_chain(chain_id: str):
        """Stop attack chain execution"""
        try:
            from src.agents.realtime_orchestrator import get_realtime_orchestrator
            
            orchestrator = get_realtime_orchestrator()
            result = orchestrator.stop_attack_chain(chain_id)
            
            return jsonify(result)
        except Exception as e:
            logger.error(f"Error stopping {chain_id}: {e}")
            return jsonify({"error": str(e)})
