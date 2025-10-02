#!/usr/bin/env python3
"""
BreachPilot - Automated Penetration Testing System
Main entry point for running the application
"""

import uvicorn
import sys
import os
import argparse
from pathlib import Path

# Add backend to path
sys.path.insert(0, str(Path(__file__).parent))

from backend.main import app
from backend.config import config
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description='BreachPilot - Automated Penetration Testing System'
    )
    parser.add_argument(
        '--port', '-p',
        type=int,
        default=int(os.getenv('PORT', 8000)),
        help='Port to run the server on (default: 8000, or PORT env var)'
    )
    parser.add_argument(
        '--host',
        type=str,
        default=os.getenv('HOST', '0.0.0.0'),
        help='Host to bind to (default: 0.0.0.0)'
    )
    parser.add_argument(
        '--reload',
        action='store_true',
        help='Enable auto-reload for development'
    )
    return parser.parse_args()

if __name__ == "__main__":
    args = parse_args()
    
    print("="*50)
    print("BreachPilot v2.0")
    print("Automated Penetration Testing System")
    print("="*50)
    print(f"\nData directory: {config.DATA_DIR}")
    print(f"Reports directory: {config.REPORTS_DIR}")
    print("\nStarting server...")
    print(f"Access the web interface at: http://localhost:{args.port}/ui")
    print(f"API documentation at: http://localhost:{args.port}/docs")
    print(f"\nListening on {args.host}:{args.port}")
    print("\nPress CTRL+C to stop\n")
    
    # Mount static files
    frontend_path = Path(__file__).parent / "frontend"
    if frontend_path.exists():
        app.mount("/static", StaticFiles(directory=str(frontend_path / "static")), name="static")
        
        # Serve index.html at /ui
        @app.get("/ui")
        async def serve_ui():
            return FileResponse(str(frontend_path / "index.html"))
    
    try:
        uvicorn.run(
            app, 
            host=args.host, 
            port=args.port, 
            log_level="info",
            reload=args.reload
        )
    except OSError as e:
        if e.errno == 98:  # Address already in use
            print(f"\n\u274c ERROR: Port {args.port} is already in use!\n")
            print("Solutions:")
            print(f"  1. Stop the process using port {args.port}:")
            print(f"     lsof -i :{args.port}")
            print(f"     kill -9 <PID>\n")
            print("  2. Use a different port:")
            print(f"     python app.py --port 8001\n")
            print("  3. Set PORT environment variable:")
            print(f"     PORT=8001 python app.py\n")
            sys.exit(1)
        else:
            raise
