#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Framework
Main Application Entry Point - Updated for CrewAI Architecture
"""

import sys
import os
import logging
from pathlib import Path

# Add backend to Python path
sys.path.append(str(Path(__file__).parent / "backend"))

from backend.main import app
from backend.config import config

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

if __name__ == "__main__":
    logger.info("Starting BreachPilot Professional Security Assessment Framework")
    logger.info("CrewAI Architecture - Enterprise Edition")
    
    # Validate configuration
    if not config.validate():
        logger.error("Configuration validation failed - check your .env file")
        sys.exit(1)
    
    logger.info(f"Using LLM Model: {config.LLM_MODEL}")
    logger.info(f"OpenAI API Configured: {'✅' if config.OPENAI_API_KEY else '❌'}")
    logger.info(f"Serper API Configured: {'✅' if config.SERPER_API_KEY else '❌ (Optional)'}")
    
    # Import uvicorn here to avoid import issues
    try:
        import uvicorn
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=config.DEBUG,
            log_level=config.LOG_LEVEL.lower()
        )
    except ImportError:
        logger.error("uvicorn not installed. Install with: pip install uvicorn[standard]")
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Shutting down BreachPilot")
    except Exception as e:
        logger.error(f"Failed to start application: {e}")
        sys.exit(1)
