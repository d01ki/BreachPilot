#!/usr/bin/env python3
"""
BreachPilot Configuration Management
Updated for CrewAI Professional Implementation
"""

import os
from typing import Optional
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class Config:
    """
    Application configuration class
    """
    
    # OpenAI Configuration (Required for CrewAI)
    OPENAI_API_KEY: Optional[str] = os.getenv('OPENAI_API_KEY')
    
    # Serper API Key for Web Search (Optional)
    SERPER_API_KEY: Optional[str] = os.getenv('SERPER_API_KEY')
    
    # LLM Configuration
    LLM_MODEL: str = os.getenv('LLM_MODEL', 'gpt-4')
    LLM_TEMPERATURE: float = float(os.getenv('LLM_TEMPERATURE', '0.1'))
    
    # Application Configuration
    DEBUG: bool = os.getenv('DEBUG', 'false').lower() == 'true'
    LOG_LEVEL: str = os.getenv('LOG_LEVEL', 'INFO')
    
    # CrewAI Specific Configuration
    CREWAI_MEMORY_ENABLED: bool = os.getenv('CREWAI_MEMORY_ENABLED', 'true').lower() == 'true'
    CREWAI_VERBOSE: bool = os.getenv('CREWAI_VERBOSE', 'true').lower() == 'true'
    
    # Security Assessment Configuration
    MAX_CVES_PER_ANALYSIS: int = int(os.getenv('MAX_CVES_PER_ANALYSIS', '7'))
    ASSESSMENT_TIMEOUT: int = int(os.getenv('ASSESSMENT_TIMEOUT', '300'))  # 5 minutes
    
    # Network Configuration
    NMAP_TIMEOUT: int = int(os.getenv('NMAP_TIMEOUT', '300'))
    NMAP_MAX_THREADS: int = int(os.getenv('NMAP_MAX_THREADS', '10'))
    
    # Validation
    def validate(self) -> bool:
        """
        Validate configuration
        
        Returns:
            True if configuration is valid
        """
        if not self.OPENAI_API_KEY:
            print("WARNING: OPENAI_API_KEY not configured - CrewAI will not work")
            return False
        
        return True
    
    def get_crewai_config(self) -> dict:
        """
        Get CrewAI specific configuration
        
        Returns:
            CrewAI configuration dictionary
        """
        return {
            'openai_api_key': self.OPENAI_API_KEY,
            'serper_api_key': self.SERPER_API_KEY,
            'llm_model': self.LLM_MODEL,
            'llm_temperature': self.LLM_TEMPERATURE,
            'memory_enabled': self.CREWAI_MEMORY_ENABLED,
            'verbose': self.CREWAI_VERBOSE,
            'max_cves': self.MAX_CVES_PER_ANALYSIS,
            'timeout': self.ASSESSMENT_TIMEOUT
        }

# Global configuration instance
config = Config()

# Validate configuration on import
if not config.validate():
    print("Configuration validation failed - some features may not work properly")
