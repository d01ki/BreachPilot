#!/usr/bin/env python3
"""
BreachPilot - Automated Penetration Testing System
Main entry point for running the application
"""

import uvicorn
import sys
import os
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from backend.main import app
from backend.config import config
from fastapi.staticfiles import StaticFiles

if __name__ == "__main__":
    print("="*50)
    print("BreachPilot v2.0")
    print("Automated Penetration Testing System")
    print("="*50)
    print(f"\nData directory: {config.DATA_DIR}")
    print(f"Reports directory: {config.REPORTS_DIR}")
    print("\nStarting server...")
    print("Access the web interface at: http://localhost:8000")
    print("API documentation at: http://localhost:8000/docs")
    print("\nPress CTRL+C to stop\n")
    
    # Mount static files
    frontend_path = Path(__file__).parent / "frontend"
    if frontend_path.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_path / "static")), name="static")
        
        # Serve index.html at root
        from fastapi.responses import FileResponse
        
        @app.get("/ui")
        async def serve_ui():
            return FileResponse(str(frontend_path / "index.html"))
    
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
