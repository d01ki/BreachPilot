#!/usr/bin/env python3
"""
BreachPilot Professional Security Assessment Framework
Main Application Entry Point - CrewAI Architecture v2.0
"""

import sys
import os
import logging
from pathlib import Path

# Add backend to Python path
sys.path.append(str(Path(__file__).parent / "backend"))

try:
    from backend.main import app
    from backend.config import config
except ImportError as e:
    print(f"❌ Import Error: {e}")
    print("\n🔧 Setup Instructions:")
    print("1. Install dependencies: pip install -r requirements.txt")
    print("2. Configure .env file: cp .env.example .env")
    print("3. Add OpenAI API key to .env file")
    print("4. Run: python app.py")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL.upper(), logging.INFO),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

def print_startup_banner():
    """Print startup banner with system information"""
    print("\n" + "="*70)
    print("🛡️  BREACHPILOT PROFESSIONAL SECURITY ASSESSMENT FRAMEWORK")
    print("🤖  CrewAI Architecture - Enterprise Edition v2.0")
    print("="*70)
    print(f"🌐 Web Interface: http://localhost:8000")
    print(f"📚 API Documentation: http://localhost:8000/docs")
    print(f"📊 System Status: http://localhost:8000/status")
    print(f"🤖 CrewAI Status: http://localhost:8000/crewai/status")
    print("="*70)
    
    # Configuration status
    print("⚙️  Configuration Status:")
    print(f"   LLM Model: {config.LLM_MODEL}")
    print(f"   OpenAI API: {'✅ Configured' if config.OPENAI_API_KEY else '❌ Missing (Required)'}")
    print(f"   Serper API: {'✅ Configured' if config.SERPER_API_KEY else '⚠️  Optional'}")
    print(f"   Debug Mode: {'✅ Enabled' if config.DEBUG else '❌ Disabled'}")
    print(f"   Log Level: {config.LOG_LEVEL}")
    
    if not config.OPENAI_API_KEY:
        print("\n⚠️  WARNING: OpenAI API key not configured!")
        print("   CrewAI functionality will not work without API key.")
        print("   Please add OPENAI_API_KEY to your .env file.")
    
    print("\n🚀 Starting CrewAI Security Assessment Framework...")
    print("="*70 + "\n")

if __name__ == "__main__":
    print_startup_banner()
    
    # Validate configuration
    if not config.validate():
        print("❌ Configuration validation failed")
        print("\n🔧 Quick Fix:")
        print("1. Copy environment template: cp .env.example .env")
        print("2. Edit .env and add your OpenAI API key")
        print("3. Get API key from: https://platform.openai.com/")
        print("4. Restart application: python app.py")
        sys.exit(1)
    
    # Import uvicorn here to avoid import issues
    try:
        import uvicorn
        
        # Start the application
        uvicorn.run(
            "backend.main:app",
            host="0.0.0.0",
            port=8000,
            reload=config.DEBUG,
            log_level=config.LOG_LEVEL.lower(),
            access_log=config.DEBUG
        )
        
    except ImportError:
        print("❌ uvicorn not installed")
        print("   Install with: pip install uvicorn[standard]")
        sys.exit(1)
    except KeyboardInterrupt:
        print("\n👋 Shutting down BreachPilot Professional")
        print("   Thank you for using CrewAI Security Assessment Framework!")
    except Exception as e:
        print(f"❌ Failed to start application: {e}")
        print("\n🔍 Troubleshooting:")
        print("1. Check your .env configuration")
        print("2. Verify OpenAI API key is valid")
        print("3. Ensure all dependencies are installed")
        print("4. Check logs for detailed error information")
        sys.exit(1)
