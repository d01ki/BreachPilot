import os
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

class Config:
    # API Keys
    OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
    SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
    
    # Paths
    BASE_DIR = Path(__file__).parent.parent
    DATA_DIR = BASE_DIR / "data"
    REPORTS_DIR = BASE_DIR / "reports"
    TOOLS_DIR = BASE_DIR / "tools"
    
    # Create directories if they don't exist
    DATA_DIR.mkdir(exist_ok=True)
    REPORTS_DIR.mkdir(exist_ok=True)
    TOOLS_DIR.mkdir(exist_ok=True)
    
    # Tool paths
    NMAP_CMD = "nmap"
    METASPLOIT_PATH = "/usr/share/metasploit-framework"
    
    # LLM Settings
    LLM_MODEL = "gpt-4o-mini"
    LLM_TEMPERATURE = 0.1

config = Config()
